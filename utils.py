from urllib.parse import unquote
import re
import logging
import certifi
import ssl
import aiohttp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def extract_clean_file_path(file_path: str) -> str:
    """
    Extract the clean file path by removing temporary directory prefixes.

    Args:
        file_path (str): The file path that may contain temporary directory prefixes

    Returns:
        str: The clean file path, or original path if no cleanup was possible
    """
    # URL decode the file path first in case it comes in already encoded
    decoded_file_path = unquote(file_path)

    # Primary pattern for Linux/Unix: /tmp/scanner_*/repo_*/
    temp_dir_pattern_linux = r"^/tmp/scanner_[^/]+/repo_[^/]+/"
    actual_path = re.sub(temp_dir_pattern_linux, "", decoded_file_path)

    # Fallback pattern for macOS: /var/folders/.../T/scanner_*/repo_*/
    if actual_path == decoded_file_path:
        temp_dir_pattern_macos = (
            r"^/var/folders/[^/]+/[^/]+/T/scanner_[^/]+/repo_[^/]+/"
        )
        actual_path = re.sub(temp_dir_pattern_macos, "", decoded_file_path)

    # Last fallback using the repo_ string match
    if actual_path == decoded_file_path:
        idx_of_repo_substring = decoded_file_path.find("repo_")
        if idx_of_repo_substring != -1:
            actual_path = "/".join(
                decoded_file_path[idx_of_repo_substring:].split("/")[1:]
            )

    # Log only if transformation occurred
    if actual_path != decoded_file_path:
        logger.debug(f"Cleaned file path: {decoded_file_path} -> {actual_path}")

    return actual_path


def get_repository_identifier(repo_type: str, **kwargs) -> str:
    """
    Generate a repository identifier URL based on the repository type and provided arguments.

    Args:
        repo_type (str): The type of repository ('github', 'gitlab', 'azure_devops', 'codecommit')
        **kwargs: Variable keyword arguments for repository-specific parameters:
            - owner (str): Repository owner (GitHub, GitLab)
            - repo (str): Repository name (GitHub, GitLab, Azure DevOps, CodeCommit)
            - org (str): Organization name (Azure DevOps)
            - project (str): Project name (Azure DevOps)
            - region (str): AWS region (CodeCommit)

    Returns:
        str: The repository identifier URL

    Raises:
        ValueError: If required parameters for the repo_type are missing

    Examples:
        >>> get_repository_identifier('github', owner='octocat', repo='Hello-World')
        'https://github.com/octocat/Hello-World'

        >>> get_repository_identifier('codecommit', region='us-east-1', repo='my-repo')
        'https://git-codecommit.us-east-1.amazonaws.com/v1/repos/my-repo'
    """
    repo_type = repo_type.lower()

    if repo_type == "github":
        owner = kwargs.get("owner")
        repo = kwargs.get("repo")
        if not owner or not repo:
            raise ValueError("GitHub requires 'owner' and 'repo' parameters")
        return f"https://github.com/{owner}/{repo}"

    elif repo_type == "gitlab":
        owner = kwargs.get("owner")
        repo = kwargs.get("repo")
        if not owner or not repo:
            raise ValueError("GitLab requires 'owner' and 'repo' parameters")
        return f"https://gitlab.com/{owner}/{repo}"

    elif repo_type in ["azure_devops", "azure"]:
        org = kwargs.get("org")
        project = kwargs.get("project")
        repo = kwargs.get("repo")
        if not org or not project or not repo:
            raise ValueError(
                "Azure DevOps requires 'org', 'project', and 'repo' parameters"
            )
        return f"https://dev.azure.com/{org}/{project}/_git/{repo}"

    elif repo_type in ["codecommit", "aws_codecommit"]:
        region = kwargs.get("region")
        repo = kwargs.get("repo")
        if not region or not repo:
            raise ValueError("AWS CodeCommit requires 'region' and 'repo' parameters")
        return f"https://git-codecommit.{region}.amazonaws.com/v1/repos/{repo}"

    else:
        raise ValueError(
            f"Unsupported repo_type: {repo_type}. Supported types: 'github', 'gitlab', 'azure_devops', 'codecommit'"
        )


def create_ssl_context() -> ssl.SSLContext:
    """
    Create SSL context with certifi certificate bundle for secure HTTPS connections.

    Returns:
        ssl.SSLContext: Configured SSL context with certifi certificates
    """
    try:
        # Create default SSL context
        ssl_context = ssl.create_default_context()

        # Load certificate bundle from certifi
        cert_bundle_path = certifi.where()
        ssl_context.load_verify_locations(cert_bundle_path)

        logger.info(
            f"SSL context configured with certifi certificate bundle: {cert_bundle_path}"
        )
        return ssl_context

    except Exception as e:
        logger.warning(f"Failed to configure SSL context with certifi: {e}")
        logger.info("Falling back to default SSL context")
        return ssl.create_default_context()


def create_secure_client_session(timeout: int = 30) -> aiohttp.ClientSession:
    """
    Create aiohttp ClientSession with secure SSL configuration using certifi.

    Args:
        timeout: Request timeout in seconds

    Returns:
        aiohttp.ClientSession: Configured client session with secure SSL
    """
    ssl_context = create_ssl_context()
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    client_timeout = aiohttp.ClientTimeout(total=timeout)

    return aiohttp.ClientSession(
        connector=conn, timeout=client_timeout, raise_for_status=False
    )
