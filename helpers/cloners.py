from git import Repo
from abc import ABC, abstractmethod
from enum import Enum
import os
import logging
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, List
from urllib.parse import quote
from boto3 import client as boto3client
from .utils import (
    get_github_token_from_installation_id,
    create_ssl_context,
    extract_gitlab_project_id,
    detect_language_from_directory,
    get_directory_size_mb,
)
from dotenv import load_dotenv
import aiohttp
from datetime import datetime
import shutil
import base64

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Maximum number of commits difference allowed for incremental scan
# Beyond this, a full scan will be triggered
MAX_COMMITS_DIFFERENCE = 500


class ScanStrategy(str, Enum):
    """Enum representing the scanning strategy to use."""

    FULL_SCAN = "full"
    INCREMENTAL_SCAN = "incremental"
    SKIP_SCAN = "skip"


def create_temp_directory(repo_type):
    import tempfile
    from pathlib import Path
    import uuid

    temp_dir = Path(tempfile.mkdtemp(prefix=f"{repo_type}_scanner_"))
    unique_id = uuid.uuid4().hex[:8]
    repo_dir = temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{unique_id}"
    logger.info(f"Created temp directory: {repo_dir}")

    if repo_dir.exists():
        logger.warning(f"Directory {repo_dir} already exists, cleaning up...")
        shutil.rmtree(repo_dir)
    repo_dir.parent.mkdir(parents=True, exist_ok=True)

    return repo_dir


def clone_git_repository(url, destination, **kwargs):
    try:
        logger.info(f"Cloning repository to {destination}")
        Repo.clone_from(url, destination, **kwargs)
        logger.info(f"Successfully cloned repository")
    except Exception as e:
        if destination and destination.exists():
            try:
                shutil.rmtree(destination)
                logger.info(f"Cleaned up directory after failed clone: {destination}")
            except Exception as cleanup_error:
                logger.error(f"Failed to clean up directory: {cleanup_error}")
        raise RuntimeError(f"Repository clone failed: {str(e)}") from e


def get_current_commit_sha(repo_dir: Path) -> str:
    """
    Get the current HEAD commit SHA from a git repository.

    Args:
        repo_dir: Path to the git repository directory

    Returns:
        str: The current HEAD commit SHA, or empty string on failure
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            sha = result.stdout.strip()
            logger.info(f"Current commit SHA: {sha}")
            return sha
        logger.error(f"Failed to get current commit SHA: {result.stderr}")
        return ""
    except Exception as e:
        logger.error(f"Error getting current commit SHA: {e}")
        return ""


def get_commit_count_between(
    repo_dir: Path, old_sha: str, new_sha: str
) -> Optional[int]:
    """
    Count the number of commits between two commit SHAs.

    Args:
        repo_dir: Path to the git repository directory
        old_sha: The older commit SHA
        new_sha: The newer commit SHA (usually HEAD)

    Returns:
        Optional[int]: Number of commits between the two SHAs,
                       or None if unable to determine
    """
    try:
        # First verify both commits exist in the repo
        for sha in [old_sha, new_sha]:
            result = subprocess.run(
                ["git", "-C", str(repo_dir), "cat-file", "-e", sha],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.warning(f"Commit {sha} not found in repository")
                return None

        # Count commits between the two SHAs
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_dir),
                "rev-list",
                "--count",
                f"{old_sha}..{new_sha}",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            count = int(result.stdout.strip())
            logger.info(f"Commits between {old_sha[:8]} and {new_sha[:8]}: {count}")
            return count

        logger.warning(f"Failed to count commits: {result.stderr}")
        return None
    except Exception as e:
        logger.error(f"Error counting commits between SHAs: {e}")
        return None


def get_changed_files_between_commits(
    repo_dir: Path, old_sha: str, new_sha: str
) -> List[str]:
    """
    Get list of files changed between two commits.

    Args:
        repo_dir: Path to the git repository directory
        old_sha: The older commit SHA
        new_sha: The newer commit SHA (usually HEAD)

    Returns:
        List[str]: List of file paths that changed between commits,
                   empty list if unable to determine or on error
    """
    try:
        # First check if old_sha exists
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", "-e", old_sha],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                f"Previous commit {old_sha} not found - likely shallow clone or history rewritten"
            )
            # Check if this is a shallow clone
            depth_result = subprocess.run(
                ["git", "-C", str(repo_dir), "rev-list", "--count", "HEAD"],
                capture_output=True,
                text=True,
            )
            if depth_result.returncode == 0:
                commit_count = int(depth_result.stdout.strip())
                logger.info(f"Repository has {commit_count} commits available")

            logger.warning(
                f"Returning empty list to run a full scan since commit sha: {old_sha} was not found"
            )
            return []

        # Get changed files using git diff
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", "--name-only", old_sha, new_sha],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
            logger.info(f"Found {len(files)} changed files between commits")
            return files

        logger.error(f"Failed to get changed files: {result.stderr}")
        return []
    except Exception as e:
        logger.error(f"Error getting changed files between commits: {e}")
        return []


def get_scan_strategy(
    repo_dir: Path,
    previous_sha: Optional[str] = None,
    max_commits: int = MAX_COMMITS_DIFFERENCE,
) -> Dict[str, Any]:
    """
    Determine the scan strategy based on previous commit SHA.

    This function analyzes a cloned repository to determine whether to:
    - Skip the scan (no changes)
    - Do an incremental scan (some files changed)
    - Do a full scan (new repo, too many changes, or unable to determine)

    Args:
        repo_dir: Path to the cloned repository
        previous_sha: SHA from the previous scan (if any)
        max_commits: Maximum number of commits difference for incremental scan
                     (default: MAX_COMMITS_DIFFERENCE = 500)

    Returns:
        Dict with keys:
            - strategy: ScanStrategy enum value
            - reason: Human-readable explanation
            - current_sha: Current HEAD commit SHA
            - previous_sha: Previous commit SHA used for comparison
            - changed_files: List of changed file paths (for incremental scan)
            - commit_count: Number of commits between old and new SHA (if available)
    """
    current_sha = get_current_commit_sha(repo_dir)

    if not current_sha:
        return {
            "strategy": ScanStrategy.FULL_SCAN,
            "reason": "Unable to determine current commit SHA",
            "current_sha": "",
            "previous_sha": previous_sha or "",
            "changed_files": [],
            "commit_count": None,
        }

    # Scenario 1: No previous scan - full scan
    if not previous_sha:
        logger.info("No previous SHA provided - performing full scan")
        return {
            "strategy": ScanStrategy.FULL_SCAN,
            "reason": "No previous scan found - initial full scan required",
            "current_sha": current_sha,
            "previous_sha": "",
            "changed_files": [],
            "commit_count": None,
        }

    # Scenario 2: Same commit - skip scan
    if previous_sha == current_sha:
        logger.info(f"Same commit SHA ({current_sha[:8]}) - skipping scan")
        return {
            "strategy": ScanStrategy.SKIP_SCAN,
            "reason": "No new commits since last scan",
            "current_sha": current_sha,
            "previous_sha": previous_sha,
            "changed_files": [],
            "commit_count": 0,
        }

    # Scenario 3: Different commits - check commit count
    commit_count = get_commit_count_between(repo_dir, previous_sha, current_sha)

    if commit_count is None:
        # Unable to count commits (shallow clone or old SHA not available)
        # Try to get changed files anyway
        changed_files = get_changed_files_between_commits(
            repo_dir, previous_sha, current_sha
        )
        if changed_files:
            logger.info(
                f"Commit count unknown but found {len(changed_files)} changed files - incremental scan"
            )
            return {
                "strategy": ScanStrategy.INCREMENTAL_SCAN,
                "reason": f"Found {len(changed_files)} changed files (commit history unavailable)",
                "current_sha": current_sha,
                "previous_sha": previous_sha,
                "changed_files": changed_files,
                "commit_count": None,
            }
        else:
            logger.info("Unable to determine changes - falling back to full scan")
            return {
                "strategy": ScanStrategy.FULL_SCAN,
                "reason": "Unable to determine changed files (shallow clone or history not available)",
                "current_sha": current_sha,
                "previous_sha": previous_sha,
                "changed_files": [],
                "commit_count": None,
            }

    # Scenario 4: Too many commits - full scan
    if commit_count > max_commits:
        logger.info(
            f"Too many commits ({commit_count} > {max_commits}) - performing full scan"
        )
        return {
            "strategy": ScanStrategy.FULL_SCAN,
            "reason": f"Too many commits since last scan ({commit_count} > {max_commits} max)",
            "current_sha": current_sha,
            "previous_sha": previous_sha,
            "changed_files": [],
            "commit_count": commit_count,
        }

    # Scenario 5: Acceptable number of commits - incremental scan
    changed_files = get_changed_files_between_commits(
        repo_dir, previous_sha, current_sha
    )

    if not changed_files:
        # No changed files detected but commits are different
        # This could happen with merge commits that don't change files
        logger.info("No changed files detected despite different commits")
        return {
            "strategy": ScanStrategy.SKIP_SCAN,
            "reason": "No file changes detected between commits",
            "current_sha": current_sha,
            "previous_sha": previous_sha,
            "changed_files": [],
            "commit_count": commit_count,
        }

    logger.info(
        f"Incremental scan: {len(changed_files)} files changed across {commit_count} commits"
    )
    return {
        "strategy": ScanStrategy.INCREMENTAL_SCAN,
        "reason": f"{len(changed_files)} files changed across {commit_count} commits",
        "current_sha": current_sha,
        "previous_sha": previous_sha,
        "changed_files": changed_files,
        "commit_count": commit_count,
    }


class Cloner(ABC):
    def __init__(
        self,
        org_name,
        repo_name,
        project_name=None,
        hosted_git_url=None,
        **credentials,
    ):
        self.config = {
            "max_file_size_mb": 50,
            "max_total_size_mb": 600,
            "max_memory_mb": 3000,
            "chunk_size_mb": 60,
            "max_files_per_chunk": 100,
        }
        self._org_name = org_name
        self._repo_name = repo_name
        self._project_name = project_name
        self._hosted_git_url = hosted_git_url
        self._credentials = credentials
        self._detected_language = "unknown"
        self._branch = None

    async def _setup(self):
        try:
            ssl_context = create_ssl_context()
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)

            self._session = aiohttp.ClientSession(
                connector=conn, timeout=timeout, raise_for_status=True
            )
            self._temp_dir = create_temp_directory(
                self.__class__.__name__.replace("Cloner", "").lower()
            )
            self.scan_stats = {}
            self.scan_stats["start_time"] = datetime.now()
            logger.info("Scanner initialization completed")
        except Exception as e:
            logger.error(f"Scanner initialization failed: {str(e)}")
            raise

    async def _cleanup(self):
        try:
            if self._session and not self._session.closed:
                await self._session.close()
                logger.info(f"Closed aiohttp session for repo scan provider")
                self.scan_stats["end_time"] = datetime.now()

        except Exception as e:
            logger.error(
                f"Error occurred while cleaning up repo scan provider: {str(e)}"
            )

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()

    @abstractmethod
    def clone(self):
        """
        Clones the repository to a provided destination

        Returns: Temp path containing the cloned repository
        """
        pass

    @abstractmethod
    def get_scan_strategy(self, repo_dir: Path, **kwargs) -> Dict[str, Any]:
        """
        Determine the scan strategy for this repository.

        Args:
            repo_dir: Path to the cloned repository
            **kwargs: Additional keyword arguments (e.g., previous_sha, max_commits)

        Returns:
            Dict with strategy information including:
                - strategy: ScanStrategy enum value
                - reason: Human-readable explanation
                - current_sha: Current commit SHA
                - previous_sha: Previous commit SHA
                - changed_files: List of changed file paths
                - commit_count: Number of commits between SHAs
        """
        pass

    async def clone_and_analyze(
        self,
        previous_sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Clone the repository and analyze it to determine scan strategy.

        Returns:
            Dict with keys:
                - success: bool
                - destination: Path where repo was cloned
                - strategy: ScanStrategy enum value
                - reason: Human-readable explanation of the strategy
                - current_sha: Current commit SHA
                - previous_sha: Previous commit SHA used for comparison
                - changed_files: List of changed file paths (for incremental scan)
                - commit_count: Number of commits between old and new SHA
                - branch: Branch name that was cloned
                - detected_language: Detected programming language
                - error: Error message if any
        """
        try:
            # Clone the repository
            cloned_path = await self.clone()

            # Analyze the repository to determine scan strategy
            strategy_result = self.get_scan_strategy(
                repo_dir=cloned_path,
                previous_sha=previous_sha,
            )

            return {
                "success": True,
                "destination": cloned_path,
                "strategy": strategy_result["strategy"],
                "reason": strategy_result["reason"],
                "current_sha": strategy_result["current_sha"],
                "previous_sha": strategy_result["previous_sha"],
                "changed_files": strategy_result["changed_files"],
                "commit_count": strategy_result["commit_count"],
                "branch": self._branch,
                "detected_language": self._detected_language,
                "error": None,
            }

        except Exception as e:
            logger.error(f"Failed to clone and analyze repository: {e}")
            return {
                "success": False,
                "destination": None,
                "strategy": ScanStrategy.FULL_SCAN,
                "reason": f"Clone failed: {str(e)}",
                "current_sha": "",
                "previous_sha": previous_sha or "",
                "changed_files": [],
                "commit_count": None,
                "branch": self._branch,
                "detected_language": self._detected_language,
                "error": str(e),
            }


class GitHubCloner(Cloner):
    def get_scan_strategy(self, repo_dir: Path, **kwargs) -> Dict[str, Any]:
        return get_scan_strategy(repo_dir, **kwargs)

    async def clone(self):
        # fetch github token for authentication
        github_token_response = get_github_token_from_installation_id(
            int(self._credentials.get("installation_id")),
            os.getenv("GITHUB_APP_ID"),
            os.getenv("GITHUB_APP_PRIVATE_KEY"),
        )
        token = github_token_response.get("token")
        if not token:
            raise Exception("Failed to get token")
        self._credentials["token"] = token

        # validate github repo size, default branch and detected languages
        base_url = self._hosted_git_url or "https://github.com"
        api_url = (
            base_url.replace("https://", "https://api.")
            + f"/repos/{self._org_name}/{self._repo_name}"
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecurityScanner",
        }
        logger.info(f"Checking Github repository: {self._org_name}/{self._repo_name}")

        repo_data = {}

        async with self._session.get(api_url, headers=headers) as response:
            if response.status != 200:
                error_message = await response.text()
                raise ValueError(
                    f"GitHub API error ({response.status}): {error_message}"
                )

            data = await response.json()
            repo_data["size_mb"] = data.get("size", 0) / 1024
            repo_data["branch"] = data.get("default_branch", "main")
            self._branch = repo_data["branch"]
            self._detected_language = data.get("language")

            # for forked repos language might be null
            if not self._detected_language:
                self._detected_language = data.get("source", {}).get("language")

            logger.info(f"Repository size: {repo_data['size_mb']:.2f}MB")
            logger.info(f"Detected language: {self._detected_language}")
            logger.info(f"Default branch: {repo_data['branch']}")

            if repo_data["size_mb"] >= self.config.get("max_total_size_mb"):
                raise ValueError(
                    f"Repository size ({repo_data['size_mb']:.2f}MB) exceeds limit of {self.config.get('max_total_size_mb')}MB"
                )

        clone_url = (
            base_url.replace(
                "https://", f"https://x-access-token:{self._credentials.get('token')}@"
            )
            + f"/{self._org_name}/{self._repo_name}"
        )

        git_options = [
            f"--depth={MAX_COMMITS_DIFFERENCE}",
            "--single-branch",
            "--no-tags",
            f"--branch={repo_data['branch']}",
        ]

        clone_git_repository(clone_url, self._temp_dir, multi_options=git_options)
        return self._temp_dir


class GitLabCloner(Cloner):
    def get_scan_strategy(self, repo_dir: Path, **kwargs) -> Dict[str, Any]:
        return get_scan_strategy(repo_dir, **kwargs)

    async def clone(self):
        logger.info(f"Checking Gitlab repository: {self._org_name}/{self._repo_name}")
        access_token = self._credentials.get("access_token")
        project_id = extract_gitlab_project_id(
            f"{self._org_name}/{self._repo_name}", access_token
        )

        base_url = self._hosted_git_url or "https://gitlab.com"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        api_url = f"{base_url}/api/v4/projects/{project_id}"

        repo_data = {}
        async with self._session.get(api_url, headers=headers) as response:
            if response.status != 200:
                error_text = await response.text()
                raise ValueError(
                    f"Gitlab API error occurred while fetching repository metadata: {error_text}"
                )

            data = await response.json()
            size_kb = data.get("statistics", {}).get("repository_size", 0)
            repo_data["size_mb"] = size_kb / 1024
            repo_data["branch"] = data.get("default_branch", "main")
            self._branch = repo_data["branch"]
            self._detected_language = data.get("predominant_language")

        # for better language detection, also check languages in repository
        api_url = f"https://gitlab.com/api/v4/projects/{project_id}/languages"
        try:
            async with self._session.get(api_url, headers=headers) as lang_response:
                if lang_response.status != 200:
                    language_error_text = await lang_response.text()
                    raise ValueError(
                        f"Gitlab API error while checking languages: {language_error_text}"
                    )

                languages_data = await lang_response.json()
                if languages_data:
                    # Languages are returned with percentage values
                    # Get the one with highest percentage
                    primary_language = max(languages_data.items(), key=lambda x: x[1])[
                        0
                    ]
                    logger.info(
                        f"Primary language from languages API: {primary_language}"
                    )

                    # If languages API returned a value, prefer it over predominant_language
                    if primary_language and not self._detected_language:
                        self._detected_language = primary_language

        except Exception as lang_error:
            logger.warning(
                f"Error getting languages data. Using fallback. Error: {str(lang_error)}"
            )

        logger.info(f"Repository size: {repo_data['size_mb']:.2f}MB")
        logger.info(f"Detected language: {self._detected_language}")
        logger.info(f"Default branch: {repo_data['branch']}")

        if repo_data["size_mb"] >= self.config.get("max_total_size_mb"):
            raise ValueError(
                f"Repository size ({repo_data['size_mb']:.2f}MB) exceeds limit of {self.config.get('max_total_size_mb')}MB"
            )

        base_url = base_url.replace("https://", f"https://oauth2:{access_token}@")
        clone_url = f"{base_url}/{self._org_name}/{self._repo_name}"
        git_options = [
            f"--depth={MAX_COMMITS_DIFFERENCE}",
            "--single-branch",
            "--no-tags",
            f"--branch={repo_data['branch']}",
        ]
        clone_git_repository(clone_url, self._temp_dir, multi_options=git_options)
        return self._temp_dir


class AzureDevOpsCloner(Cloner):
    def get_scan_strategy(self, repo_dir: Path, **kwargs) -> Dict[str, Any]:
        return get_scan_strategy(repo_dir, **kwargs)

    async def clone(self):
        logger.info(
            f"Checking Azure devops repository: {self._org_name}/{self._project_name}/{self._repo_name}"
        )
        api_url = f"https://dev.azure.com/{quote(self._org_name)}/{quote(self._project_name)}/_apis/git/repositories/{quote(self._repo_name)}?api-version=7.1"
        token = base64.b64encode(f":{self._credentials.get('PAT')}".encode()).decode()
        auth_headers = {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }

        repo_data = {}
        async with self._session.get(api_url, headers=auth_headers) as response:
            if response.status != 200:
                error_text = await response.text()
                raise ValueError(
                    f"Azure Devops API error ({response.status}): {error_text}"
                )

            data = await response.json()
            repo_data["size_mb"] = data.get("size", 0) / 1000024
            api_response_branch = data.get("defaultBranch", "main")
            repo_data["branch"] = api_response_branch.replace("refs/heads/", "")
            self._branch = repo_data["branch"]

        # azure devops has different endpoint to get repo language data
        api_url = f"https://dev.azure.com/{quote(self._org_name)}/{quote(self._project_name)}/_apis/projectanalysis/languagemetrics?api-version=7.1"
        async with self._session.get(api_url, headers=auth_headers) as response:
            if response.status != 200:
                error_text = await response.text()
                raise ValueError(
                    f"Azure Devops API error ({response.status}): {error_text}"
                )

            data = await response.json()
            repos = list(
                filter(
                    lambda repo: repo["name"] == self._repo_name,
                    data["repositoryLanguageAnalytics"],
                )
            )
            if len(repos) == 0:
                repo_data.update({"language": "unknown"})

            highest_language = "unknown"
            highest_language_percentage = 0
            for lang in repos[0]["languageBreakdown"]:
                if lang.get("languagePercentage", 0) > highest_language_percentage:
                    highest_language = lang["name"]
                    highest_language_percentage = lang["languagePercentage"]
            self._detected_language = highest_language

        logger.info(f"Repository size: {repo_data['size_mb']:.2f}MB")
        logger.info(f"Detected language: {self._detected_language}")
        logger.info(f"Default branch: {repo_data['branch']}")

        if repo_data["size_mb"] >= self.config.get("max_total_size_mb"):
            raise ValueError(
                f"Repository size ({repo_data['size_mb']:.2f}MB) exceeds limit of {self.config.get('max_total_size_mb')}MB"
            )

        clone_url = f"https://{self._credentials.get('PAT')}@dev.azure.com/{quote(self._org_name)}/{quote(self._project_name)}/_git/{quote(self._repo_name)}"
        git_options = [
            f"--depth={MAX_COMMITS_DIFFERENCE}",
            "--single-branch",
            "--no-tags",
            f"--branch={repo_data['branch']}",
        ]
        clone_git_repository(clone_url, self._temp_dir, multi_options=git_options)
        return self._temp_dir


class CodeCommitCloner(Cloner):
    def get_scan_strategy(self, repo_dir: Path, **kwargs) -> Dict[str, Any]:
        return get_scan_strategy(repo_dir, **kwargs)

    async def clone(self):
        try:
            logger.info(
                f"Checking codecommit repository: {self._org_name}/{self._repo_name}"
            )
            codecommit_client = boto3client(
                "codecommit",
                region_name=self._org_name,
                aws_access_key_id=self._credentials.get("aws_access_key_id"),
                aws_secret_access_key=self._credentials.get("aws_secret_access_key"),
            )
        except Exception as e:
            logger.error(f"Failed to initialize CodeCommit client: {str(e)}")
            raise ValueError(f"Failed to initialize AWS CodeCommit client: {str(e)}")

        response = codecommit_client.get_repository(repositoryName=self._repo_name)
        repo_metadata = response.get("repositoryMetadata", {})
        branch = repo_metadata.get("defaultBranch", "main")
        self._branch = branch
        logger.info(f"Default branch: {branch}")
        logger.warning(
            "Codecommit API does not return size and language for repos. Those will be validated after cloning the repo"
        )

        clone_url = f"codecommit::{self._org_name}://{self._repo_name}"

        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = self._credentials.get("aws_access_key_id")
        env["AWS_SECRET_ACCESS_KEY"] = self._credentials.get("aws_secret_access_key")
        env["AWS_DEFAULT_REGION"] = self._org_name

        git_options = [
            f"--depth={MAX_COMMITS_DIFFERENCE}",
            "--single-branch",
            "--no-tags",
            f"--branch={branch}",
        ]

        clone_git_repository(
            clone_url,
            self._temp_dir,
            multi_options=git_options,
            env=env,
            allow_unsafe_protocols=True,
        )

        # get the language from the cloned repo
        self._detected_language = detect_language_from_directory(self._temp_dir)
        size_mb = get_directory_size_mb(self._temp_dir)
        logger.info(f"Repository size: {size_mb:.2f}MB")
        logger.info(f"Detected language: {self._detected_language}")

        if size_mb >= self.config.get("max_total_size_mb"):
            raise ValueError(
                f"Repository size ({size_mb:.2f}MB) exceeds limit of {self.config.get('max_total_size_mb')}MB"
            )

        logger.info("Successfully validated Codecommit repo")
        return self._temp_dir


class ClonerFactory:
    @staticmethod
    def create_cloner(
        repo_type,
        org_name,
        repo_name,
        project_name=None,
        hosted_git_url=None,
        **credentials,
    ):
        if repo_type == "github":
            return GitHubCloner(
                org_name, repo_name, project_name, hosted_git_url, **credentials
            )
        elif repo_type == "gitlab":
            return GitLabCloner(
                org_name, repo_name, project_name, hosted_git_url, **credentials
            )
        elif repo_type == "azure-devops":
            return AzureDevOpsCloner(
                org_name, repo_name, project_name, hosted_git_url, **credentials
            )
        elif repo_type == "codecommit":
            return CodeCommitCloner(
                org_name, repo_name, project_name, hosted_git_url, **credentials
            )
        else:
            raise ValueError(f"Unsupported repo_type: {repo_type}")


async def clone_and_get_scan_info(
    repo_type: str,
    org_name: str,
    repo_name: str,
    project_name: Optional[str] = None,
    previous_sha: Optional[str] = None,
    hosted_git_url: Optional[str] = None,
    **credentials,
) -> Dict[str, Any]:
    """
    Clone a repository and get scan strategy information.

    This is a convenience function that combines cloning and analysis
    to return all information needed for scanning.

    Args:
        repo_type (str): Type of repository ('github', 'gitlab', 'azure-devops', 'codecommit')
        org_name (str): Organization/user name or region for CodeCommit
        repo_name (str): Repository name
        previous_sha (str, optional): SHA from the previous scan for incremental scanning
        project_name (str, optional): Project name for Azure DevOps
        hosted_git_url (str, optional): Base URL for self-hosted instances
        **credentials: keyword arguments for credentials

    Returns:
        Dict with keys:
            - success: bool
            - destination: Path where repo was cloned
            - strategy: ScanStrategy enum value
            - reason: Human-readable explanation
            - current_sha: Current commit SHA
            - previous_sha: Previous commit SHA
            - changed_files: List of changed file paths
            - commit_count: Number of commits between SHAs
            - branch: Branch name that was cloned
            - detected_language: Detected programming language
            - error: Error message if any

    Example:
        result = await clone_and_get_scan_info(
            repo_type="github",
            org_name="myorg",
            repo_name="myrepo",
            previous_sha="abc123...",
            installation_id=12345,
        )

        if result["success"]:
            if result["strategy"] == ScanStrategy.SKIP_SCAN:
                print("No changes, skipping scan")
            elif result["strategy"] == ScanStrategy.INCREMENTAL_SCAN:
                print(f"Scanning {len(result['changed_files'])} changed files")
            else:
                print("Doing full scan")
    """
    async with ClonerFactory.create_cloner(
        repo_type,
        org_name,
        repo_name,
        project_name,
        hosted_git_url,
        **credentials,
    ) as cloner:
        return await cloner.clone_and_analyze(previous_sha)
