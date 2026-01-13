"""
AWS CodeCommit repository scanner implementation.

This module provides security scanning capabilities for AWS CodeCommit repositories
using the new CodeCommitClient and Semgrep for vulnerability detection.
"""

import os
import json
import aiohttp
import asyncio
import subprocess
import tempfile
import shutil
import time
import psutil
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import traceback
from sqlalchemy.orm import Session
from models import RepositoryScanResult
from progress_tracking import update_scan_progress, clear_scan_progress
from collections import defaultdict
from botocore.exceptions import ClientError, BotoCoreError
from git import Repo, GitCommandError
from .utils import logger, create_ssl_context, ScanConfig
import boto3
from botocore.exceptions import ClientError, BotoCoreError


async def get_codecommit_file_content(
    repo_name: str,
    region: str,
    file_path: str,
    aws_access_key_id: str,
    aws_secret_access_key: str,
    branch: str = "main",
) -> Dict[str, Any]:
    """
    Fetch file content from AWS CodeCommit repository.

    Args:
        repo_name: Name of the CodeCommit repository
        region: AWS region where the repository is hosted
        file_path: Path to the file in the repository
        aws_access_key_id: AWS access key ID for authentication
        aws_secret_access_key: AWS secret access key for authentication
        branch: Branch name (default: "main")

    Returns:
        Dict with 'success', 'content', and 'error' fields
    """
    try:
        # Initialize boto3 client
        codecommit_client = boto3.client(
            "codecommit",
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

        # Get the branch reference to find the commit ID
        try:
            branch_response = codecommit_client.get_branch(
                repositoryName=repo_name, branchName=branch
            )
            commit_id = branch_response["branch"]["commitId"]
            logger.info(f"✓ Found commit ID: {commit_id} for branch: {branch}")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"✗ Branch error: {error_code}")
            if error_code == "BranchDoesNotExistException":
                return {
                    "success": False,
                    "content": None,
                    "error": {
                        "message": f"Branch '{branch}' does not exist",
                        "code": "BRANCH_NOT_FOUND",
                        "details": f"The branch '{branch}' was not found in repository '{repo_name}'",
                    },
                }
            raise

        # Get the file content
        try:
            # Remove leading slash if present
            clean_file_path = file_path.lstrip("/")
            logger.info(
                f"Attempting to fetch file with cleaned path: '{clean_file_path}'"
            )

            file_response = codecommit_client.get_file(
                repositoryName=repo_name,
                commitSpecifier=commit_id,
                filePath=clean_file_path,
            )

            # boto3 automatically decodes the base64 content, so fileContent is already bytes
            # Just decode the bytes to UTF-8 string
            file_content = file_response["fileContent"].decode(
                "utf-8", errors="replace"
            )

            logger.info(
                f"✓ Successfully fetched content for {file_path} ({len(file_content)} bytes)"
            )
            return {
                "success": True,
                "content": file_content,
                "error": None,
                "metadata": {
                    "commit_id": commit_id,
                    "file_size": file_response.get("fileSize", 0),
                    "blob_id": file_response.get("blobId"),
                },
            }

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            error_message = e.response["Error"]["Message"]
            logger.error(f"✗ File fetch error: {error_code} - {error_message}")
            logger.error(f"  Tried path: '{clean_file_path}'")

            if error_code == "FileDoesNotExistException":
                logger.warning(f"File not found: {file_path}")
                return {
                    "success": False,
                    "content": None,
                    "error": {
                        "message": f"File not found: {file_path}",
                        "code": "FILE_NOT_FOUND",
                        "details": f"The file '{file_path}' does not exist in the repository",
                    },
                }
            elif error_code == "InvalidPathException":
                logger.warning(f"Invalid file path: {file_path}")
                return {
                    "success": False,
                    "content": None,
                    "error": {
                        "message": f"Invalid file path: {file_path}",
                        "code": "INVALID_PATH",
                        "details": "The file path provided is invalid",
                    },
                }
            raise

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        logger.error(f"AWS CodeCommit API error: {error_code} - {error_message}")

        if error_code == "RepositoryDoesNotExistException":
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": f"Repository '{repo_name}' not found",
                    "code": "REPOSITORY_NOT_FOUND",
                    "details": error_message,
                },
            }
        elif error_code == "AccessDeniedException":
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": "Access denied to repository",
                    "code": "ACCESS_DENIED",
                    "details": error_message,
                },
            }
        else:
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": f"AWS API error: {error_code}",
                    "code": "AWS_API_ERROR",
                    "details": error_message,
                },
            }

    except Exception as e:
        logger.error(f"Unexpected error fetching file content: {str(e)}")
        return {
            "success": False,
            "content": None,
            "error": {
                "message": "Internal server error",
                "code": "INTERNAL_ERROR",
                "details": str(e),
            },
        }


async def scan_codecommit_repo(
    repo_name: str,
    region: str,
    branch: str,
    user_id: str,
    db_session: Session,
    codecommit_analysis_record: RepositoryScanResult,
    aws_access_key_id: str = None,
    aws_secret_access_key: str = None,
    multi_scan: bool = True,
) -> Dict[str, Any]:
    """
    Trigger a Semgrep scan for an AWS CodeCommit repository.

    Args:
        repo_name: Name of the CodeCommit repository
        region: AWS region where the repository is hosted
        branch: Branch to scan
        user_id: ID of the user requesting the scan
        workspace_id: Workspace ID for organization
        db_session: Database session
        codecommit_analysis_record: Analysis record to update
        aws_access_key_id: AWS access key ID for IAM authentication
        aws_secret_access_key: AWS secret access key for IAM authentication
        multi_scan: Whether to use multiple scan configurations

    Returns:
        Dict containing scan results and status
    """
    logger.info(f"Starting scan for CodeCommit repository: {region}/{repo_name}")

    try:
        codecommit_analysis = codecommit_analysis_record

        # Clear previous scan progress
        clear_scan_progress(user_id, f"{region}/{repo_name}")
        update_scan_progress(user_id, f"{region}/{repo_name}", "initializing", 5)

        config = ScanConfig()
        async with AWSCodeCommitScanner(
            config,
            db_session,
            codecommit_analysis_record.id if codecommit_analysis_record else None,
            repo_name,
            region,
            aws_access_key_id,
            aws_secret_access_key,
        ) as scanner:
            try:
                # skipping size check since codecommit doesnt provide size in api
                # size will be checked after clone. if it exceeds max size it will raise an exception
                repo_dir = await scanner._clone_repository(branch)

                try:
                    results = await scanner.scan_repository(
                        repo_name=repo_name,
                        region=region,
                        user_id=user_id,
                        multi_scan=multi_scan,
                    )
                except Exception as e:
                    logger.error(f"An error occurred while scanning: {str(e)}")
                    raise
                finally:
                    if repo_dir and os.path.exists(repo_dir):
                        shutil.rmtree(repo_dir)

                if results.get("success"):
                    # Get repository metadata for additional info
                    repo_metadata = scanner.validate_credentials().get("details", {})

                    results["data"]["repository_info"] = {
                        "repository_name": repo_metadata.get(
                            "repository_name", repo_name
                        ),
                        "region": region,
                        "default_branch": repo_metadata.get("default_branch", branch),
                        "repository_id": repo_metadata.get("repository_id"),
                        "created_date": repo_metadata.get("created_date"),
                        "last_modified_date": repo_metadata.get("last_modified_date"),
                        "detected_language": scanner.detected_language,
                    }
                return results

            except Exception as e:
                error_msg = f"Scan error: {str(e)}"
                logger.error(error_msg)
                if codecommit_analysis_record:
                    codecommit_analysis_record.status = "error"
                    codecommit_analysis_record.error = error_msg
                    db_session.commit()
                return {
                    "success": False,
                    "error": {
                        "message": str(e),
                        "code": "SCAN_ERROR",
                        "type": type(e).__name__,
                        "timestamp": datetime.now().isoformat(),
                    },
                }

    except Exception as e:
        error_msg = f"Handler error: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())

        if codecommit_analysis_record:
            codecommit_analysis_record.status = "failed"
            codecommit_analysis_record.error = error_msg
            db_session.commit()

        return {
            "success": False,
            "error": {
                "message": "Unexpected error in scan handler",
                "code": "INTERNAL_ERROR",
                "details": str(e),
                "type": type(e).__name__,
                "timestamp": datetime.now().isoformat(),
            },
        }


class AWSCodeCommitScanner:
    def __init__(
        self,
        config: ScanConfig = ScanConfig(),
        db_session: Optional[Session] = None,
        analysis_id: Optional[int] = None,
        repo_name: str = None,
        region: str = None,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
    ):
        self.config = config
        self.db_session = db_session
        self.analysis_id = analysis_id
        self._clone_dir: Optional[str] = None
        self.repo_dir = None
        self._session = None
        self.detected_language = None

        self._validated = False
        self._repo_name = repo_name
        self._region = region
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self.branch = None

        self._user_id = None

        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "total_files": 0,
            "files_processed": 0,
            "files_skipped": 0,
            "files_too_large": 0,
            "total_size_mb": 0,
            "memory_usage_mb": 0,
            "findings_count": 0,
            "scan_durations": {},
        }

        # Validate that we have IAM credentials
        if not (aws_access_key_id and aws_secret_access_key):
            raise ValueError(
                "aws_access_key_id and aws_secret_access_key must be provided"
            )

        # Initialize boto3 client with IAM credentials
        self.codecommit_client = None
        try:
            self.codecommit_client = boto3.client(
                "codecommit",
                region_name=self._region,
                aws_access_key_id=self._aws_access_key_id,
                aws_secret_access_key=self._aws_secret_access_key,
            )
        except Exception as e:
            logger.error(f"Failed to initialize CodeCommit client: {str(e)}")
            raise ValueError(f"Failed to initialize AWS CodeCommit client: {str(e)}")

    def get_language_specific_configs(self, language: str) -> List[Dict]:
        """Get relevant scan configs based on repository language."""
        configs = []

        # Always include core security configs
        configs.extend(self.config.core_configs)
        logger.info("Added core security configs")

        # Always include web security configs
        configs.extend(self.config.web_configs)
        logger.info("Added web security configs")

        if not language:
            logger.warning(
                "No language detected, using core and web security configs only"
            )
            return configs

        # Normalize language name
        language = language.lower()

        # Handle C# variations
        if language in ["csharp", "cs", "dotnet", "net"]:
            language = "c#"

        # Add language-specific configs if available
        if language in self.config.language_configs:
            configs.extend(self.config.language_configs[language])
            logger.info(f"Added {language}-specific configs")
        else:
            logger.warning(f"No specific configs available for language: {language}")

        logger.info(
            f"Total configs to run: {len(configs)} ({[c['name'] for c in configs]})"
        )
        return configs

    def _detect_languages_from_codecommit(self, branch: str = None) -> List[str]:
        """
        Detect programming languages by analyzing file extensions directly from CodeCommit.

        This method uses the CodeCommit API to list files without cloning the repository.

        Args:
            branch: Branch name to scan (defaults to repository's default branch)

        Returns:
            List of detected programming languages, sorted by frequency
        """
        # Define language mappings based on file extensions
        language_extensions = {
            "python": [".py", ".pyw", ".pyx"],
            "javascript": [".js", ".jsx", ".mjs", ".cjs"],
            "typescript": [".ts", ".tsx"],
            "java": [".java"],
            "c#": [".cs", ".csx"],
            "go": [".go"],
            "ruby": [".rb", ".rake"],
            "php": [".php", ".phtml"],
            "c++": [".cpp", ".cc", ".cxx", ".hpp", ".h", ".hxx"],
            "c": [".c", ".h"],
            "rust": [".rs"],
            "kotlin": [".kt", ".kts"],
            "swift": [".swift"],
            "scala": [".scala"],
        }

        # Directories to skip
        skip_dirs = {
            "node_modules",
            "vendor",
            "__pycache__",
            "venv",
            "env",
            ".git",
            "dist",
            "build",
            "target",
            ".idea",
            ".vscode",
        }

        language_counts = defaultdict(int)
        total_files = 0

        try:
            # Get default branch if not specified
            if not branch:
                repo_response = self.codecommit_client.get_repository(
                    repositoryName=self._repo_name
                )
                branch = repo_response.get("repositoryMetadata", {}).get(
                    "defaultBranch", "main"
                )

            logger.info(f"Detecting languages from CodeCommit on branch: {branch}")

            # Recursively list all files from the repository
            def list_files_recursive(folder_path: str = "/"):
                """Recursively list all files in the repository."""
                nonlocal total_files

                try:
                    response = self.codecommit_client.get_folder(
                        repositoryName=self._repo_name,
                        commitSpecifier=branch,
                        folderPath=folder_path,
                    )

                    # Process files in current folder
                    for file_info in response.get("files", []):
                        file_path = file_info.get("relativePath", "")
                        if not file_path:
                            continue

                        # Get file extension
                        _, ext = os.path.splitext(file_path)
                        ext = ext.lower()

                        # Check which language this extension belongs to
                        for language, extensions in language_extensions.items():
                            if ext in extensions:
                                language_counts[language] += 1
                                total_files += 1
                                break

                    # Process subfolders recursively
                    for subfolder in response.get("subFolders", []):
                        subfolder_path = subfolder.get("relativePath", "")
                        if not subfolder_path:
                            continue

                        # Skip common directories that don't contain source code
                        folder_name = os.path.basename(subfolder_path)
                        if folder_name not in skip_dirs:
                            list_files_recursive(subfolder_path)

                except ClientError as e:
                    error_code = e.response.get("Error", {}).get("Code", "Unknown")
                    # Silently skip folders we can't access or don't exist
                    if error_code not in [
                        "FolderDoesNotExistException",
                        "AccessDeniedException",
                    ]:
                        logger.warning(f"Error listing folder {folder_path}: {str(e)}")
                except Exception as e:
                    logger.warning(
                        f"Unexpected error listing folder {folder_path}: {str(e)}"
                    )

            # Start recursive listing from root
            list_files_recursive("/")

            # Build result array sorted by frequency
            if language_counts:
                # Sort languages by count (descending)
                sorted_languages = sorted(
                    language_counts.items(), key=lambda x: x[1], reverse=True
                )

                detected_languages = [lang for lang, count in sorted_languages]

                logger.info(
                    f"Detected {len(detected_languages)} languages from {total_files} files: "
                    f"{dict(language_counts)}"
                )

                return detected_languages
            else:
                logger.warning("No programming language files detected")
                return []

        except Exception as e:
            logger.error(f"Error detecting languages from CodeCommit: {str(e)}")
            return []

    def validate_credentials(self) -> Dict[str, Any]:
        """
        Verify that the provided credentials and repository name are valid and accessible.

        Uses boto3 to verify repository access with IAM credentials.

        Returns:
            Dict containing validation results with keys:
                - success (bool): Whether validation was successful
                - message (str): Description of validation result
                - details (Dict): Additional information about the repository
                - languages (List[str]): Detected programming languages

        Raises:
            Exception: If validation fails with specific error details
        """
        logger.info(
            f"Validating credentials for CodeCommit repository: {self._repo_name}"
        )

        try:
            logger.info("Using IAM credentials for authentication")

            # Attempt to get repository metadata
            response = self.codecommit_client.get_repository(
                repositoryName=self._repo_name
            )

            repo_metadata = response.get("repositoryMetadata", {})

            # Try to get the clone URL
            clone_url_http = repo_metadata.get("cloneUrlHttp")

            if not clone_url_http:
                return {
                    "success": False,
                    "message": "Repository exists but clone URL not available",
                    "details": {},
                }

            # Store the repository URL for later use
            self._repo_url = clone_url_http

            # Mark as validated
            self._validated = True

            # Detect languages from repository files
            default_branch = repo_metadata.get("defaultBranch", "main")
            detected_languages = self._detect_languages_from_codecommit(default_branch)

            logger.info(
                f"Successfully validated access to repository: {self._repo_name}"
            )

            return {
                "success": True,
                "message": f"Successfully validated access to repository: {self._repo_name}",
                "details": {
                    "repository_name": repo_metadata.get("repositoryName"),
                    "repository_id": repo_metadata.get("repositoryId"),
                    "arn": repo_metadata.get("Arn"),
                    "default_branch": default_branch,
                    "clone_url_http": clone_url_http,
                    "clone_url_ssh": repo_metadata.get("cloneUrlSsh"),
                    "created_date": str(repo_metadata.get("creationDate", "")),
                    "last_modified_date": str(
                        repo_metadata.get("lastModifiedDate", "")
                    ),
                    "auth_type": "iam_credentials",
                },
                "languages": detected_languages,
            }
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            error_message = e.response.get("Error", {}).get("Message", str(e))

            logger.error(
                f"AWS ClientError during validation: {error_code} - {error_message}"
            )

            if error_code == "RepositoryDoesNotExistException":
                raise ValueError(
                    f"Repository '{self._repo_name}' does not exist in region '{self.region}'"
                )
            elif error_code in ["AccessDeniedException", "UnauthorizedException"]:
                raise PermissionError(
                    f"Access denied to repository '{self._repo_name}'. Check your credentials and permissions."
                )
            elif error_code == "InvalidRepositoryNameException":
                raise ValueError(f"Invalid repository name: '{self._repo_name}'")
            else:
                raise Exception(
                    f"AWS error during validation: {error_code} - {error_message}"
                )

        except BotoCoreError as e:
            logger.error(f"BotoCoreError during validation: {str(e)}")
            raise Exception(f"AWS connection error: {str(e)}")

        except Exception as e:
            logger.error(f"Unexpected error during validation: {str(e)}")
            raise Exception(f"Validation failed: {str(e)}")

    async def _clone_repository(self, branch: str) -> str:
        """
        Clone the CodeCommit repository to a temporary directory with size validation.

        Args:
            branch: Branch name to clone

        Returns:
            Path to the cloned repository

        Raises:
            Exception: If clone operation fails or repository exceeds size limit
        """
        if not self._validated:
            validation_result = self.validate_credentials()
            if not validation_result["success"]:
                raise Exception(
                    f"Cannot clone repository: {validation_result['message']}"
                )

        try:
            logger.info(f"Cloning repository from CodeCommit (branch: {branch})...")

            import re

            url_pattern = (
                r"https://git-codecommit\.([^.]+)\.amazonaws\.com/v1/repos/(.+)"
            )
            match = re.match(url_pattern, self._repo_url)

            if not match:
                raise ValueError(f"Unable to parse CodeCommit URL: {self._repo_url}")

            region = match.group(1)
            repo_name = match.group(2)

            # Build codecommit:// URL for git-remote-codecommit helper
            codecommit_url = f"codecommit::{region}://{repo_name}"
            logger.info(f"Using codecommit URL: codecommit::{region}://{repo_name}")

            # Set up environment variables with AWS credentials
            # git-remote-codecommit will use these credentials
            env = os.environ.copy()
            env["AWS_ACCESS_KEY_ID"] = self._aws_access_key_id
            env["AWS_SECRET_ACCESS_KEY"] = self._aws_secret_access_key
            env["AWS_DEFAULT_REGION"] = self._region

            logger.info(f"Using IAM credentials for clone in region: {self._region}")

            # Optimize clone operation with similar options to GitHub clone
            git_options = [
                "--depth=1",
                "--single-branch",
                "--no-tags",
                f"--branch={branch}",
            ]

            if self._clone_dir and os.path.exists(self._clone_dir):
                logger.info(f"Using existing clone directory: {self._clone_dir}")
                return self._clone_dir

            # Generate a unique directory name using timestamp and random identifier
            unique_id = uuid.uuid4().hex[:8]
            self._clone_dir = os.path.join(
                tempfile.gettempdir(),
                f"scanner_codecommit/repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{unique_id}",
            )
            logger.info(f"Created temporary directory for cloning: {self._clone_dir}")

            repo = Repo.clone_from(
                codecommit_url,
                self._clone_dir,
                multi_options=git_options,
                env=env,
                allow_unsafe_protocols=True,  # codecommit protocol is considered unsafe by default
            )

            logger.info(f"Successfully cloned repository to {self._clone_dir}")

            # Check actual repository size after cloning
            # CodeCommit doesn't provide size in API, so we verify after clone
            actual_size_mb = self._get_directory_size(self._clone_dir)
            logger.info(
                f"Cloned repository size: {actual_size_mb:.2f}MB "
                f"(limit: {self.config.max_total_size_mb}MB)"
            )

            if actual_size_mb > self.config.max_total_size_mb:
                # Clean up oversized repository
                if self._clone_dir and os.path.exists(self._clone_dir):
                    shutil.rmtree(self._clone_dir, ignore_errors=True)
                    self._clone_dir = None

                raise ValueError(
                    f"Repository size ({actual_size_mb:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            # Detect language manually since CodeCommit API doesn't provide this
            self._detect_language_from_files(self._clone_dir)

            return self._clone_dir

        except GitCommandError as e:
            logger.error(f"Git clone failed: {str(e)}")

            # Clean up on failure
            if self._clone_dir and os.path.exists(self._clone_dir):
                shutil.rmtree(self._clone_dir, ignore_errors=True)
                self._clone_dir = None

            # Provide helpful error messages
            error_str = str(e)
            if (
                "fatal: could not read Username" in error_str
                or "Authentication failed" in error_str
            ):
                raise PermissionError(
                    f"Authentication failed when cloning repository. "
                    f"Please verify your AWS credentials are correct."
                )
            elif "Repository not found" in error_str:
                raise ValueError(
                    f"Repository '{self._repo_name}' not found or inaccessible."
                )
            elif f"fatal: Remote branch {branch} not found" in error_str:
                raise ValueError(
                    f"Branch '{branch}' not found in repository. "
                    f"Try using 'main' or 'master' as the branch name."
                )
            elif "git-remote-codecommit" in error_str:
                raise Exception(
                    f"git-remote-codecommit helper not found. "
                    f"Install it with: pip install git-remote-codecommit"
                )
            else:
                raise Exception(f"Failed to clone repository: {str(e)}")

        except Exception as e:
            logger.error(f"Unexpected error during clone: {str(e)}")

            # Clean up on failure
            if self._clone_dir and os.path.exists(self._clone_dir):
                shutil.rmtree(self._clone_dir, ignore_errors=True)
                self._clone_dir = None

            raise Exception(f"Failed to clone repository: {str(e)}")

    def _get_directory_size(self, directory: str) -> float:
        """
        Calculate the total size of a directory in megabytes.

        Args:
            directory: Path to the directory

        Returns:
            Size in megabytes
        """
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
                except (OSError, FileNotFoundError):
                    # Skip files that can't be accessed
                    continue
        return total_size / (1024 * 1024)  # Convert bytes to MB

    def _detect_language_from_files(self, directory: str) -> None:
        """
        Detect the primary programming language by analyzing file extensions in the repository.

        Since AWS CodeCommit doesn't provide language information via API,
        this method manually scans the cloned repository to determine the language.

        Args:
            directory: Path to the cloned repository directory
        """
        # Define language mappings based on file extensions
        language_extensions = {
            "python": [".py", ".pyw", ".pyx"],
            "javascript": [".js", ".jsx", ".mjs", ".cjs"],
            "typescript": [".ts", ".tsx"],
            "java": [".java"],
            "c#": [".cs", ".csx"],
            "go": [".go"],
            "ruby": [".rb", ".rake"],
            "php": [".php", ".phtml"],
            "c++": [".cpp", ".cc", ".cxx", ".hpp", ".h", ".hxx"],
            "c": [".c", ".h"],
            "rust": [".rs"],
            "kotlin": [".kt", ".kts"],
            "swift": [".swift"],
            "scala": [".scala"],
        }

        # Count files by language
        language_counts = defaultdict(int)
        total_files = 0

        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                # Skip .git directory and other common directories to ignore
                dirnames[:] = [
                    d
                    for d in dirnames
                    if d
                    not in [
                        ".git",
                        "node_modules",
                        "vendor",
                        "__pycache__",
                        "venv",
                        "env",
                    ]
                ]

                for filename in filenames:
                    # Get file extension
                    _, ext = os.path.splitext(filename)
                    ext = ext.lower()

                    # Check which language this extension belongs to
                    for language, extensions in language_extensions.items():
                        if ext in extensions:
                            language_counts[language] += 1
                            total_files += 1
                            break

            # Determine primary language (the one with most files)
            if language_counts:
                primary_language = max(language_counts.items(), key=lambda x: x[1])[0]
                self.detected_language = primary_language

                # Calculate percentage for logging
                primary_count = language_counts[primary_language]
                percentage = (
                    (primary_count / total_files * 100) if total_files > 0 else 0
                )

                logger.info(
                    f"Detected primary language: {self.detected_language} "
                    f"({primary_count}/{total_files} files, {percentage:.1f}%)"
                )
                logger.info(f"Language breakdown: {dict(language_counts)}")
            else:
                logger.warning("Could not detect language from file extensions")
                self.detected_language = None

        except Exception as e:
            logger.error(f"Error detecting language from files: {str(e)}")
            self.detected_language = None

    async def _run_semgrep_scan(self, target_dir: Path, scan_config: Dict) -> Dict:
        """Execute semgrep scan with enhanced error handling and monitoring"""
        semgrepignore_path = target_dir / ".semgrepignore"
        start_time = time.time()
        scan_name = scan_config["name"]

        try:
            # Create .semgrepignore file
            with open(semgrepignore_path, "w") as f:
                for pattern in self.config.exclude_patterns:
                    f.write(f"{pattern}\n")

            timeout = self.config.timeout_map.get(
                scan_name, self.config.default_timeout
            )
            logger.info(f"Starting {scan_name} scan with {timeout}s timeout")

            cmd = [
                "semgrep",
                "scan",
                "--config",
                scan_config["config"],
                "--json",
                "--verbose",
                "--metrics=on",
                "--no-git-ignore",
                "--optimizations=all",
                str(target_dir),
            ]

            memory_before = psutil.Process().memory_info().rss / (1024 * 1024)
            logger.info(f"Memory usage before {scan_name}: {memory_before:.2f}MB")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir),
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                elapsed_time = time.time() - start_time
                error_msg = f"Scan {scan_name} timed out after {elapsed_time:.2f}s"
                logger.error(error_msg)
                return self._create_empty_result(error=error_msg)

            memory_after = psutil.Process().memory_info().rss / (1024 * 1024)
            memory_diff = memory_after - memory_before
            logger.info(
                f"Memory usage after {scan_name}: {memory_after:.2f}MB (Δ: {memory_diff:+.2f}MB)"
            )

            stderr_output = stderr.decode() if stderr else ""
            if stderr_output:
                logger.warning(f"Semgrep stderr ({scan_name}): {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result(error=f"No output from {scan_name}")

            try:
                results = json.loads(output)
                processed_results = self._process_scan_results(results)
                scan_duration = time.time() - start_time
                self.scan_stats["scan_durations"][scan_name] = scan_duration

                processed_results["scan_source"] = scan_name
                processed_results["scan_duration"] = scan_duration
                processed_results["memory_usage"] = {
                    "before": memory_before,
                    "after": memory_after,
                    "difference": memory_diff,
                }

                logger.info(f"Completed {scan_name} scan in {scan_duration:.2f}s")
                return processed_results

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse {scan_name} output: {str(e)}"
                logger.error(error_msg)
                return self._create_empty_result(error=error_msg)

        except Exception as e:
            error_msg = f"Error in {scan_name} scan: {str(e)}"
            logger.error(error_msg)
            return self._create_empty_result(error=error_msg)

        finally:
            if semgrepignore_path.exists():
                semgrepignore_path.unlink()

    async def run_multiple_semgrep_scans(self, target_dir: Path) -> Dict:
        """Run multiple semgrep scans based on detected language"""
        try:
            logger.info(f"Detected repository language: {self.detected_language}")

            # Get relevant configs based on language
            selected_configs = self.get_language_specific_configs(
                self.detected_language
            )

            # Add these lines for progress tracking
            user_id = getattr(self, "_user_id", "")
            repo_name = getattr(self, "_repo_name")
            total_configs = len(selected_configs)

            all_results = []
            merged_findings = []
            total_files_scanned = 0
            total_files_skipped = 0
            severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            category_counts = defaultdict(int)
            seen_findings = set()
            errors = []

            # Run selected scans sequentially
            for i, scan_config in enumerate(selected_configs):
                try:
                    # Update progress here
                    progress = (i / total_configs) * 100
                    update_scan_progress(
                        user_id, f"{self._region}/{repo_name}", "analyzing", progress
                    )

                    logger.info(
                        f"Starting scan with config: {scan_config['name']} ({scan_config['rules_count']} rules)"
                    )
                    result = await self._run_semgrep_scan(target_dir, scan_config)
                    all_results.append(result)

                    findings = result.get("findings", [])
                    stats = result.get("stats", {})

                    # Update counters
                    total_files_scanned = max(
                        total_files_scanned,
                        stats.get("scan_stats", {}).get("files_scanned", 0),
                    )
                    total_files_skipped += stats.get("scan_stats", {}).get(
                        "skipped_files", 0
                    )

                    # Process and deduplicate findings
                    for finding in findings:
                        finding_id = (
                            finding.get("file", ""),
                            finding.get("line_start", 0),
                            finding.get("line_end", 0),
                            finding.get("code_snippet", ""),
                        )

                        if finding_id not in seen_findings:
                            seen_findings.add(finding_id)
                            finding["scan_source"] = scan_config["name"]
                            merged_findings.append(finding)
                            severity = finding.get("severity", "INFO").upper()
                            category = finding.get("category", "unknown")

                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            else:
                                severity_counts["INFO"] += 1

                            category_counts[category] += 1

                except Exception as e:
                    error_msg = f"Error in {scan_config['name']} scan: {str(e)}"
                    logger.error(error_msg)
                    errors.append({"scan": scan_config["name"], "error": str(e)})

            logger.info(
                f"Completed all scans. Total findings: {len(merged_findings)} "
                f"(after deduplication)"
            )

            return {
                "findings": merged_findings,
                "stats": {
                    "total_findings": len(merged_findings),
                    "severity_counts": severity_counts,
                    "category_counts": dict(category_counts),
                    "scan_stats": {
                        "files_scanned": total_files_scanned,
                        "files_with_findings": len(
                            set(f.get("file") for f in merged_findings if f.get("file"))
                        ),
                        "skipped_files": total_files_skipped,
                        "total_scans": len(selected_configs),
                        "successful_scans": len(selected_configs) - len(errors),
                    },
                    "memory_usage_mb": self.scan_stats.get("memory_usage_mb", 0),
                },
                "errors": errors,
            }

        except Exception as e:
            error_msg = f"Error in run_multiple_semgrep_scans: {str(e)}"
            logger.error(error_msg)
            logger.error(traceback.format_exc())
            return self._create_empty_result(error=error_msg)

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and normalize scan results"""
        findings = results.get("results", [])
        stats = results.get("stats", {})
        paths = results.get("paths", {})
        parse_metrics = results.get("parse_metrics", {})

        processed_findings = []
        severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        category_counts = defaultdict(int)
        files_with_findings = set()

        for finding in findings:
            file_path = finding.get("path", "")
            if file_path:
                files_with_findings.add(file_path)

            severity = finding.get("extra", {}).get("severity", "INFO").upper()
            category = (
                finding.get("extra", {}).get("metadata", {}).get("category", "security")
            )

            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["INFO"] += 1

            category_counts[category] += 1

            processed_findings.append(
                {
                    "id": finding.get("check_id"),
                    "file": file_path,
                    "line_start": finding.get("start", {}).get("line"),
                    "line_end": finding.get("end", {}).get("line"),
                    "code_snippet": finding.get("extra", {}).get("lines", ""),
                    "message": finding.get("extra", {}).get("message", ""),
                    "severity": severity,
                    "category": category,
                    "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": finding.get("extra", {})
                    .get("metadata", {})
                    .get("owasp", []),
                    "fix_recommendations": finding.get("extra", {})
                    .get("metadata", {})
                    .get("fix", ""),
                    "references": finding.get("extra", {})
                    .get("metadata", {})
                    .get("references", []),
                }
            )

        scan_stats = {
            "total_files": stats.get("total", {}).get("files", 0),
            "files_scanned": len(paths.get("scanned", [])),
            "files_with_findings": len(files_with_findings),
            "skipped_files": len(paths.get("skipped", [])),
            "partially_scanned": parse_metrics.get("partially_parsed_files", 0),
        }

        return {
            "findings": processed_findings,
            "stats": {
                "total_findings": len(processed_findings),
                "severity_counts": severity_counts,
                "category_counts": dict(category_counts),
                "scan_stats": scan_stats,
                "memory_usage_mb": self.scan_stats.get("memory_usage_mb", 0),
            },
        }

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure with optional error information"""
        return {
            "findings": [],
            "stats": {
                "total_findings": 0,
                "severity_counts": {
                    "CRITICAL": 0,
                    "ERROR": 0,
                    "WARNING": 0,
                    "INFO": 0,
                },
                "category_counts": {},
                "scan_stats": self.scan_stats,
                "memory_usage_mb": self.scan_stats["memory_usage_mb"],
            },
            "errors": [error] if error else [],
        }

    async def scan_repository(
        self,
        repo_name: str,
        region: str,
        user_id: str,
        multi_scan: bool = True,
    ) -> Dict:
        """
        Execute complete security scan on CodeCommit repository.

        Args:
            repo_name: Name of the repository
            region: AWS region
            user_id: User ID for progress tracking
            multi_scan: Whether to run multiple scan configurations

        Returns:
            Dict containing scan results and metadata
        """
        try:
            self._user_id = user_id
            self._repo_name = repo_name

            clear_scan_progress(user_id, f"{region}/{repo_name}")
            update_scan_progress(user_id, f"{region}/{repo_name}", "initializing", 0)

            # Validate RAG API URL
            RAG_URL = os.getenv("RAG_URL")
            if not RAG_URL:
                raise ValueError("RAG_URL not configured")
            AI_RERANK_URL = f"{RAG_URL}/vulnerability_reranker_labelled"
            if not AI_RERANK_URL:
                raise ValueError("AI_RERANK_URL not configured")

            # Set repo_dir to clone directory
            self.repo_dir = Path(self._clone_dir)

            # Initial scan
            scan_results = (
                await self.run_multiple_semgrep_scans(self.repo_dir)
                if multi_scan
                else await self._run_semgrep_scan(
                    self.repo_dir, self.config.scan_configs[0]
                )
            )
            update_scan_progress(user_id, f"{region}/{repo_name}", "processing", 0)

            # Get all findings
            all_findings = scan_results.get("findings", [])
            logger.info(f"Found {len(all_findings)} total findings")

            # Initialize variables
            rag_responses = []
            semgrep_rag_response = None
           
            # Send findings to semgrep RAG API
            update_scan_progress(
                user_id,
                f"{region}/{repo_name}",
                "analyzing_vulnerabilities",
                30,
            )
            if all_findings:
                from .utils import create_secure_client_session

                async with create_secure_client_session() as session:
                    from .utils import send_findings_to_semgrep_rag

                    semgrep_rag_response = await send_findings_to_semgrep_rag(
                        session=session,
                        findings=all_findings,
                        user_id=user_id,
                        repo_name=repo_name,
                    )
                    if semgrep_rag_response and not semgrep_rag_response.get("error"):
                        logger.info("Successfully received semgrep RAG analysis")
                    else:
                        error_msg = (
                            semgrep_rag_response.get("error", "Unknown error")
                            if semgrep_rag_response
                            else "Empty response"
                        )
                        logger.warning(
                            f"Semgrep RAG analysis failed or returned error: {error_msg}"
                        )

            # Note: CodeCommit doesn't have the same file content API as Azure DevOps
            # We skip the file content RAG processing since we already have the cloned repo
            # and the findings include the code snippets
            update_scan_progress(
                user_id, f"{region}/{repo_name}", "analyzing_files", 60
            )
            logger.info("Skipping file content RAG (already have local clone)")

            # Prepare reranking data
            update_scan_progress(user_id, f"{region}/{repo_name}", "reranking", 80)
            rerank_data = {
                "findings": [
                    {
                        "ID": idx + 1,
                        "file": finding["file"],
                        "code_snippet": finding["code_snippet"],
                        "message": finding["message"],
                        "severity": finding["severity"],
                    }
                    for idx, finding in enumerate(all_findings)
                ],
                "metadata": {
                    "repository": repo_name,
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "scan_id": self.analysis_id,
                    "rag_processed": bool(rag_responses),
                    "rag_responses": rag_responses,
                },
            }

            # Handle reranking
            RAG_URL = os.getenv("RAG_URL")
            if not RAG_URL:
                raise ValueError("RAG_URL not configured")
            rerank_api_url = f"{RAG_URL}/vulnerability_reranker_labelled"
            reordered_findings = all_findings.copy()
            if all_findings and rerank_api_url:
                import aiohttp
                rerank_data = [{"ID": f["ID"], "file": f.get("file"), "severity": f.get("severity","")} for f in all_findings]
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(rerank_api_url, json=rerank_data) as resp:
                            if resp.status == 200:
                                rerank_response = await resp.json()
                                tuples = extract_rerank_tuples(rerank_response["llm_response"], all_findings)
                                if tuples:
                                    id_to_finding = {f["ID"]: f.copy() for f in all_findings}
                                    reordered_findings = {}
                                    reordered_findings_list = []
                                    for t_id, sev in tuples:
                                        f = id_to_finding.get(t_id)
                                        if f:
                                            f["severity"] = sev
                                            reordered_findings_list.append(f)
                                    reordered_findings["findings"] = reordered_findings_list
                                    reordered_findings["stats"] = scan_results.get("stats", {})
                                    reordered_findings["stats"]["severity_counts"] = {
                                        "CRITICAL": len([f for f in reordered_findings_list if f["severity"] == "CRITICAL"]),
                                        "HIGH": len([f for f in reordered_findings_list if f["severity"] == "HIGH"]),
                                        "MEDIUM": len([f for f in reordered_findings_list if f["severity"] == "MEDIUM"]),
                                        "LOW": len([f for f in reordered_findings_list if f["severity"] == "LOW"]),
                                    }
                                else:
                                    pass  # use original order
                except Exception as e:
                    pass  # fallback
            else:
                logger.info("No findings to rerank")

            update_scan_progress(user_id, f"{region}/{repo_name}", "finalizing", 90)

            results_data = {
                "findings": reordered_findings,
                "stats": reordered_findings.get("stats", {}),
                "metadata": {
                    "repository_name": repo_name,
                    "region": region,
                    "user_id": user_id,
                    "scan_start": self.scan_stats["start_time"].isoformat(),
                    "scan_end": datetime.now().isoformat(),
                    "scan_duration_seconds": (
                        datetime.now() - self.scan_stats["start_time"]
                    ).total_seconds(),
                    "rag_processed": bool(rag_responses),
                    "rag_responses_count": len(rag_responses),
                },
            }

            # Update database
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(RepositoryScanResult).get(
                        self.analysis_id
                    )
                    if analysis:
                        analysis.results = results_data  # All findings
                        analysis.rerank = reordered_findings["findings"]  # Selected findings
                        analysis.status = "completed"
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                        logger.info(
                            f"Successfully stored in database - results: {len(all_findings)}, rerank: {len(reordered_findings['findings'])}"
                        )
                except Exception as e:
                    self.db_session.rollback()
                    logger.error(f"Database update failed: {str(e)}")

            update_scan_progress(user_id, f"{region}/{repo_name}", "completed", 100)

            return {"success": True, "data": results_data}

        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            logger.error(traceback.format_exc())
            update_scan_progress(user_id, f"{region}/{repo_name}", "error", 0)

            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(RepositoryScanResult).get(
                        self.analysis_id
                    )
                    if analysis:
                        analysis.status = "error"
                        analysis.error = str(e)
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                except Exception as db_error:
                    logger.error(f"Database error update failed: {str(db_error)}")
                    self.db_session.rollback()

            return {
                "success": False,
                "error": {
                    "message": str(e),
                    "code": "SCAN_ERROR",
                    "type": type(e).__name__,
                    "timestamp": datetime.now().isoformat(),
                },
            }

    async def __aenter__(self):
        """Initialize scanner resources"""
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup scanner resources"""
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner with enhanced error handling"""
        try:
            ssl_context = create_ssl_context()
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)

            self._session = aiohttp.ClientSession(
                connector=conn, timeout=timeout, raise_for_status=True
            )

            self.scan_stats["start_time"] = datetime.now()
            logger.info("Scanner initialization completed")

        except Exception as e:
            logger.error(f"Scanner initialization failed: {str(e)}")
            raise

    async def _cleanup(self):
        """Cleanup scanner resources with proper error handling"""
        try:
            if self._session and not self._session.closed:
                await self._session.close()
                logger.info("Closed aiohttp session")

            if self._clone_dir and os.path.exists(self._clone_dir):
                shutil.rmtree(self._clone_dir)
                logger.info(f"Cleaned up temporary directory: {self._clone_dir}")

            self.scan_stats["end_time"] = datetime.now()

        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")


async def run_semgrep_scan(repo_dir: str, multi_scan: bool = True) -> Dict[str, Any]:
    """
    Run Semgrep security scan on the cloned repository.

    Args:
        repo_dir: Path to the cloned repository
        user_id: User ID for progress tracking
        repo_name: Repository name for progress tracking
        multi_scan: Whether to use multiple scan configurations

    Returns:
        Dict containing scan results
    """
    logger.info(f"Running Semgrep scan on directory: {repo_dir}")
    start_time = datetime.now()

    try:
        # Prepare Semgrep command
        # Using common security rulesets
        semgrep_configs = [
            "p/security-audit",
            "p/owasp-top-ten",
            "p/secrets",
        ]

        if multi_scan:
            # Add more comprehensive rulesets
            semgrep_configs.extend(
                [
                    "p/command-injection",
                    "p/sql-injection",
                    "p/xss",
                ]
            )

        config_arg = " ".join([f"--config {config}" for config in semgrep_configs])

        # Build Semgrep command
        cmd = [
            "semgrep",
            "--json",
            "--quiet",
            "--no-git-ignore",
            "--max-memory",
            "4096",
        ]

        # Add configs
        for config in semgrep_configs:
            cmd.extend(["--config", config])

        # Add target directory
        cmd.append(repo_dir)

        logger.info(f"Running Semgrep with configs: {', '.join(semgrep_configs)}")

        # Run Semgrep
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=600  # 10 minute timeout
        )

        # Parse results
        if result.returncode not in [0, 1]:  # 0 = success, 1 = findings found
            logger.error(f"Semgrep failed with return code {result.returncode}")
            logger.error(f"Stderr: {result.stderr}")

            return {
                "success": False,
                "error": f"Semgrep execution failed: {result.stderr}",
            }

        # Parse JSON output
        try:
            semgrep_output = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON output: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to parse scan results: {str(e)}",
            }

        # Extract and process findings
        raw_findings = semgrep_output.get("results", [])
        logger.info(f"Found {len(raw_findings)} raw findings")

        # Process findings into structured format
        findings = []
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        files_scanned = set()

        for idx, finding in enumerate(raw_findings, 1):
            file_path = finding.get("path", "")
            files_scanned.add(file_path)

            # Extract severity
            severity = finding.get("extra", {}).get("severity", "INFO").upper()
            severity_counts[severity] += 1

            # Extract category
            category = finding.get("check_id", "").split(".")[-1]
            category_counts[category] += 1

            # Build structured finding
            processed_finding = {
                "ID": idx,
                "file": file_path,
                "line": finding.get("start", {}).get("line", 0),
                "end_line": finding.get("end", {}).get("line", 0),
                "column": finding.get("start", {}).get("col", 0),
                "severity": severity,
                "category": category,
                "message": finding.get("extra", {}).get("message", ""),
                "rule_id": finding.get("check_id", ""),
                "code_snippet": finding.get("extra", {}).get("lines", ""),
                "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp", []),
                "references": finding.get("extra", {})
                .get("metadata", {})
                .get("references", []),
                "fix_recommendations": finding.get("extra", {}).get("fix", ""),
                "scan_source": "semgrep",
            }

            findings.append(processed_finding)

        duration = (datetime.now() - start_time).total_seconds()

        # Build stats
        stats = {
            "total_findings": len(findings),
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "scan_stats": {
                "files_scanned": len(files_scanned),
                "files_with_findings": len(set(f["file"] for f in findings)),
                "scan_duration_seconds": duration,
            },
        }

        logger.info(f"Scan completed in {duration:.2f}s with {len(findings)} findings")

        return {
            "success": True,
            "findings": findings,
            "stats": stats,
            "duration": duration,
        }

    except subprocess.TimeoutExpired:
        logger.error("Semgrep scan timed out")
        return {"success": False, "error": "Scan timed out after 10 minutes"}
    except Exception as e:
        logger.error(f"Scan execution error: {str(e)}")
        logger.error(traceback.format_exc())
        return {"success": False, "error": f"Scan execution error: {str(e)}"}


def extract_rerank_tuples(response, selected_findings=None):
    """Parse [(ID, severity), ...] tuples from response (list or string); returns list of (ID, SEVERITY_UPPER) in order."""
    if isinstance(response, str):
        response = ast.literal_eval(response.strip())
    tuples = response if isinstance(response, list) else []
    normalize = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "error": "ERROR",
    }
    logger.info(f"OBSERVING RERANKING RESPONSE: Extracting rerank tuples: {tuples}")
    logger.info(f"OBSERVING RERANKING RESPONSE: Normalize: {normalize}")
    return [
        (int(i), normalize.get(str(s).lower(), str(s).upper()))
        for i, s in tuples
        if isinstance(i, (int, float, str)) and isinstance(s, str)
    ]
