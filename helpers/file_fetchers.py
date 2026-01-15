from typing import Dict, Optional, Any
import aiohttp
import asyncio
import base64
import logging
import os
from urllib.parse import quote
import boto3
from botocore.exceptions import ClientError

from dotenv import load_dotenv
from .utils import create_ssl_context, get_github_token_from_installation_id

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


async def fetch_file_contents_from_repo_provider(
    repo_type: str,
    org_name: str,
    repo_name: str,
    file_path: str,
    project_name: Optional[str] = None,
    hosted_git_url: Optional[str] = None,
    branch: Optional[str] = None,
    **credentials,
) -> Dict[str, Any]:
    """
    Fetch file contents from a repository provider.

    Args:
        repo_type: Type of repository ('github', 'gitlab', 'azure-devops', 'codecommit')
        org_name: Organization/user name or region for CodeCommit
        repo_name: Repository name
        file_path: Path to the file in the repository
        project_name: Project name (required for Azure DevOps)
        hosted_git_url: Base URL for self-hosted instances
        branch: Branch name (default: "main")
        **credentials: Provider-specific credentials:
            - GitHub: installation_id (uses GitHub App to get token)
            - GitLab: access_token
            - Azure DevOps: PAT or access_token
            - CodeCommit: aws_access_key_id, aws_secret_access_key

    Returns:
        Dict with keys:
            - success: bool
            - content: str or None
            - error: Dict with message, code, details or None
    """
    # CodeCommit uses boto3, doesn't need aiohttp session
    if repo_type == "codecommit":
        return await fetch_codecommit_file_contents(
            repo_name=repo_name,
            region=org_name,
            file_path=file_path,
            aws_access_key_id=credentials.get("aws_access_key_id"),
            aws_secret_access_key=credentials.get("aws_secret_access_key"),
            branch=branch,
        )

    # Create SSL context and aiohttp session for other providers
    ssl_context = create_ssl_context()
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        if repo_type == "github":
            return await fetch_github_file_contents(
                session=session,
                org_name=org_name,
                repo_name=repo_name,
                file_path=file_path,
                installation_id=credentials.get("installation_id"),
                branch=branch,
                hosted_git_url=hosted_git_url,
            )
        elif repo_type == "gitlab":
            return await fetch_gitlab_file_contents(
                session=session,
                org_name=org_name,
                repo_name=repo_name,
                file_path=file_path,
                access_token=credentials.get("access_token"),
                hosted_git_url=hosted_git_url,
                branch=branch,
            )
        elif repo_type == "azure-devops":
            return await fetch_azure_devops_file_contents(
                session=session,
                organization_name=org_name,
                project_name=project_name,
                repo_name=repo_name,
                file_path=file_path,
                branch=branch,
                PAT=credentials.get("PAT"),
                access_token=credentials.get("access_token"),
            )
        else:
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": f"Unsupported repository type: {repo_type}",
                    "code": "UNSUPPORTED_REPO_TYPE",
                    "details": f"Supported types are: github, gitlab, azure-devops, codecommit",
                },
            }


async def fetch_github_file_contents(
    session: aiohttp.ClientSession,
    org_name: str,
    repo_name: str,
    file_path: str,
    installation_id: int,
    branch: Optional[str] = None,
    hosted_git_url: Optional[str] = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Dict[str, Any]:
    try:
        # Get token from installation ID
        github_token_response = get_github_token_from_installation_id(
            int(installation_id),
            os.getenv("GITHUB_APP_ID"),
            os.getenv("GITHUB_APP_PRIVATE_KEY"),
        )
        token = github_token_response.get("token")
        if not token:
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": "Failed to get GitHub token from installation ID",
                    "code": "AUTH_FAILED",
                    "details": "Could not retrieve access token from GitHub App",
                },
            }

        base_url = hosted_git_url or "https://github.com"
        api_base = base_url.replace("https://", "https://api.")

        if not branch:
            branch = "HEAD"
            logger.info(f"Falling back to repository default branch -> {branch}")

        # Handle potential URL-unsafe characters in the file path
        safe_path = quote(file_path, safe="")
        api_url = f"{api_base}/repos/{org_name}/{repo_name}/contents/{safe_path}?ref={quote(branch)}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecurityScanner",
        }

        logger.info(
            f"Fetching GitHub file: {org_name}/{repo_name}/{file_path} using branch {branch}"
        )

        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                async with session.get(api_url, headers=headers) as response:
                    status = response.status

                    if status == 200:
                        data = await response.json()
                        if "content" in data:
                            content = base64.b64decode(data["content"]).decode("utf-8")
                            logger.info(f"Successfully fetched content for {file_path}")
                            return {"success": True, "content": content, "error": None}
                        else:
                            return {
                                "success": False,
                                "content": None,
                                "error": {
                                    "message": "No content field in response",
                                    "code": "EMPTY_RESPONSE",
                                    "details": f"File {file_path} response did not contain content",
                                },
                            }

                    elif status == 404:
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

                    elif status == 403:
                        error_data = await response.json()
                        if "rate limit" in error_data.get("message", "").lower():
                            retry_delay = base_delay * (2**retry_count)
                            logger.warning(
                                f"Rate limited. Waiting {retry_delay}s before retry"
                            )
                            await asyncio.sleep(retry_delay)
                            retry_count += 1
                            continue
                        else:
                            return {
                                "success": False,
                                "content": None,
                                "error": {
                                    "message": f"Access denied: {error_data.get('message', 'Unknown error')}",
                                    "code": "ACCESS_DENIED",
                                    "details": "You don't have permission to access this file",
                                },
                            }

                    elif status in {502, 503, 504}:
                        retry_delay = base_delay * (2**retry_count)
                        logger.warning(
                            f"Gateway error {status}. Retrying in {retry_delay}s"
                        )
                        await asyncio.sleep(retry_delay)
                        retry_count += 1
                        continue

                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "content": None,
                            "error": {
                                "message": f"GitHub API error: {status}",
                                "code": "API_ERROR",
                                "details": (
                                    error_text[:200]
                                    if error_text
                                    else f"HTTP {status} error"
                                ),
                            },
                        }

            except aiohttp.ClientError as e:
                last_error = e
                retry_delay = base_delay * (2**retry_count)
                logger.warning(f"Network error: {str(e)}. Retrying in {retry_delay}s")
                await asyncio.sleep(retry_delay)
                retry_count += 1
                continue

        return {
            "success": False,
            "content": None,
            "error": {
                "message": f"Failed after {max_retries} retries: {str(last_error)}",
                "code": "NETWORK_ERROR",
                "details": "Failed to connect to GitHub API after multiple attempts",
            },
        }

    except Exception as e:
        logger.error(f"Unexpected error fetching GitHub file content: {str(e)}")
        return {
            "success": False,
            "content": None,
            "error": {
                "message": f"Unexpected error: {str(e)}",
                "code": "UNEXPECTED_ERROR",
                "details": str(e),
            },
        }


async def fetch_azure_devops_file_contents(
    session: aiohttp.ClientSession,
    organization_name: str,
    project_name: str,
    repo_name: str,
    file_path: str,
    branch: Optional[str] = None,
    PAT: Optional[str] = None,
    access_token: Optional[str] = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Dict[str, Any]:
    try:
        if not PAT and not access_token:
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": "Authentication required",
                    "code": "AUTH_REQUIRED",
                    "details": "Either PAT or access_token must be provided",
                },
            }

        # Create auth header
        if PAT:
            token = base64.b64encode(f":{PAT}".encode()).decode()
            auth_header = {"Authorization": f"Basic {token}"}
        else:
            auth_header = {"Authorization": f"Bearer {access_token}"}

        if not branch:
            branch = "HEAD"
            logger.info(f"Falling back to repository default branch -> {branch}")

        api_url = f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/git/repositories/{quote(repo_name)}/items?path={quote(file_path)}&commitOrBranch={quote(branch)}&api-version=7.1"

        headers = {**auth_header, "Content-Type": "text/plain"}

        logger.info(
            f"Fetching Azure DevOps file: {organization_name}/{project_name}/{repo_name}/{file_path} using branch {branch}"
        )

        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                async with session.get(api_url, headers=headers) as response:
                    status = response.status

                    if status == 200:
                        data = await response.text()
                        if data:
                            logger.info(f"Successfully fetched content for {file_path}")
                            return {"success": True, "content": data, "error": None}
                        else:
                            return {
                                "success": False,
                                "content": None,
                                "error": {
                                    "message": "File exists but contains no content",
                                    "code": "EMPTY_FILE",
                                    "details": f"File {file_path} was found but is empty",
                                },
                            }
                    else:
                        error_text = await response.text()
                        return {
                            "success": False,
                            "content": None,
                            "error": {
                                "message": f"Azure DevOps API error: {status}",
                                "code": "API_ERROR",
                                "details": (
                                    error_text[:200]
                                    if error_text
                                    else f"HTTP {status} error"
                                ),
                            },
                        }

            except aiohttp.ClientResponseError as e:
                status = e.status

                if status == 404:
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": f"File not found: {file_path}",
                            "code": "FILE_NOT_FOUND",
                            "details": f"The file '{file_path}' does not exist in the repository",
                        },
                    }
                elif status == 403:
                    error_message = str(e)
                    if "rate limit" in error_message.lower():
                        retry_delay = base_delay * (2**retry_count)
                        logger.warning(
                            f"Rate limited. Waiting {retry_delay}s before retry"
                        )
                        await asyncio.sleep(retry_delay)
                        retry_count += 1
                        continue
                    else:
                        return {
                            "success": False,
                            "content": None,
                            "error": {
                                "message": "Access denied",
                                "code": "ACCESS_DENIED",
                                "details": "You don't have permission to access this file or the authentication token is invalid",
                            },
                        }
                elif status in {502, 503, 504}:
                    retry_delay = base_delay * (2**retry_count)
                    logger.warning(
                        f"Gateway error {status}. Retrying in {retry_delay}s"
                    )
                    await asyncio.sleep(retry_delay)
                    retry_count += 1
                    continue
                else:
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": f"Azure DevOps API error: {status}",
                            "code": "API_ERROR",
                            "details": str(e),
                        },
                    }

            except aiohttp.ClientError as e:
                last_error = e
                retry_delay = base_delay * (2**retry_count)
                logger.warning(f"Network error: {str(e)}. Retrying in {retry_delay}s")
                await asyncio.sleep(retry_delay)
                retry_count += 1
                continue

        return {
            "success": False,
            "content": None,
            "error": {
                "message": f"Failed after {max_retries} retries: {str(last_error)}",
                "code": "NETWORK_ERROR",
                "details": "Failed to connect to Azure DevOps API after multiple attempts",
            },
        }

    except Exception as e:
        logger.error(f"Unexpected error fetching Azure DevOps file content: {str(e)}")
        return {
            "success": False,
            "content": None,
            "error": {
                "message": f"Unexpected error: {str(e)}",
                "code": "UNEXPECTED_ERROR",
                "details": str(e),
            },
        }


async def fetch_gitlab_file_contents(
    session: aiohttp.ClientSession,
    org_name: str,
    repo_name: str,
    file_path: str,
    access_token: str,
    hosted_git_url: Optional[str] = None,
    branch: str = "HEAD",  # using head will fetch from the default branch
) -> Dict[str, Any]:
    try:
        base_url = hosted_git_url or "https://gitlab.com"

        # GitLab requires project ID or URL-encoded path
        project_path = quote(f"{org_name}/{repo_name}", safe="")
        encoded_file_path = quote(file_path, safe="")

        api_url = f"{base_url}/api/v4/projects/{project_path}/repository/files/{encoded_file_path}/raw"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        if not branch:
            branch = "HEAD"
            logger.info(f"Falling back to repository default branch -> {branch}")
        params = {"ref": branch}

        logger.info(
            f"Fetching GitLab file: {org_name}/{repo_name}/{file_path} using branch {branch}"
        )

        try:
            async with session.get(api_url, headers=headers, params=params) as response:
                status = response.status

                if status == 200:
                    content = await response.text()
                    logger.info(f"Successfully fetched content for {file_path}")
                    return {"success": True, "content": content, "error": None}

                elif status == 404:
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": f"File not found: {file_path}",
                            "code": "FILE_NOT_FOUND",
                            "details": f"The file '{file_path}' does not exist in the repository or branch '{branch}'",
                        },
                    }

                elif status == 401:
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": "Authentication failed",
                            "code": "AUTH_FAILED",
                            "details": "The provided access token is invalid or expired",
                        },
                    }

                elif status == 403:
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": "Access denied",
                            "code": "ACCESS_DENIED",
                            "details": "You don't have permission to access this file",
                        },
                    }

                else:
                    error_text = await response.text()
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": f"GitLab API error: {status}",
                            "code": "API_ERROR",
                            "details": (
                                error_text[:200]
                                if error_text
                                else f"HTTP {status} error"
                            ),
                        },
                    }

        except aiohttp.ClientError as e:
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": f"Network error: {str(e)}",
                    "code": "NETWORK_ERROR",
                    "details": "Failed to connect to GitLab API",
                },
            }

    except Exception as e:
        logger.error(f"Unexpected error fetching GitLab file content: {str(e)}")
        return {
            "success": False,
            "content": None,
            "error": {
                "message": f"Unexpected error: {str(e)}",
                "code": "UNEXPECTED_ERROR",
                "details": str(e),
            },
        }


async def fetch_codecommit_file_contents(
    repo_name: str,
    region: str,
    file_path: str,
    aws_access_key_id: str,
    aws_secret_access_key: str,
    branch: str,
) -> Dict[str, Any]:
    try:
        # Initialize boto3 client
        codecommit_client = boto3.client(
            "codecommit",
            region_name=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

        logger.info(f"Fetching CodeCommit file: {repo_name}/{file_path}")

        if not branch:
            response = codecommit_client.get_repository(repositoryName=repo_name)
            branch = response.get("repositoryMetadata", {}).get("defaultBranch", "main")
            logger.info(f"Falling back to repository default branch -> {branch}")

        # Get the branch reference to find the commit ID
        try:
            branch_response = codecommit_client.get_branch(
                repositoryName=repo_name, branchName=branch
            )
            commit_id = branch_response["branch"]["commitId"]
            logger.info(f"Found commit ID: {commit_id} for branch: {branch}")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
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

            file_response = codecommit_client.get_file(
                repositoryName=repo_name,
                commitSpecifier=commit_id,
                filePath=clean_file_path,
            )

            # boto3 automatically decodes base64, fileContent is already bytes
            file_content = file_response["fileContent"].decode(
                "utf-8", errors="replace"
            )

            logger.info(
                f"Successfully fetched content for {file_path} ({len(file_content)} bytes)"
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

            if error_code == "FileDoesNotExistException":
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
        logger.error(f"Unexpected error fetching CodeCommit file content: {str(e)}")
        return {
            "success": False,
            "content": None,
            "error": {
                "message": "Internal server error",
                "code": "INTERNAL_ERROR",
                "details": str(e),
            },
        }
