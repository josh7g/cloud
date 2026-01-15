import time
import jwt
import requests
import ssl
import logging
import certifi


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def get_github_token_from_installation_id(installation_id, app_id, private_key):
    if not installation_id:
        raise ValueError("installation_id is required")
    if not app_id or not private_key:
        raise RuntimeError("GitHub App credentials not configured")
    formatted_private_key = private_key.replace("\\n", "\n")
    now = int(time.time())
    payload = {
        "iat": now - 60,
        "exp": now + 600,
        "iss": app_id,
    }
    token = jwt.encode(payload, formatted_private_key, algorithm="RS256")
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    response = requests.post(url, json={}, headers=headers)
    response.raise_for_status()
    data = response.json()
    return {
        "token": data["token"],
        "expires_at": data["expires_at"],
    }


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


def extract_gitlab_project_id(project_url_or_path, access_token):
    from urllib.parse import urlparse

    try:
        project_path = ""
        if "://" in project_url_or_path:  # it's a full url
            project_path = urlparse(project_url_or_path).path.lstrip("/").rstrip(".git")
        elif project_url_or_path:
            project_path = project_url_or_path.lstrip("/")
        else:
            raise ValueError("Gitlab project url or path is empty")

        if not access_token:
            raise ValueError("Gitlab access token to extract project id is empty")

        url = f"https://gitlab.com/api/v4/projects/{project_path.replace('/', '%2F')}"
        headers = {"Authorization": f"Bearer {access_token}"}

        logger.info(f"Fetching project ID for path: {project_path}")
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            project_data = response.json()
            project_id = str(project_data["id"])
            logger.info(f"Successfully got project ID: {project_id}")
            return project_id

        raise ValueError(
            f"Failed to get project id for gitlab project {project_url_or_path}, Response: {response.text}"
        )

    except Exception as e:
        logger.error(f"Error extracting project ID: {str(e)}")
        raise ValueError(
            f"Failed to get project id for gitlab project {project_url_or_path}, Response: {e}"
        )


def detect_language_from_directory(directory: str) -> str:
    """
    Detect the dominant programming language by analyzing file extensions in a directory.

    This function scans a cloned repository directory to determine the primary
    programming language based on file extension frequency. Useful for providers
    like AWS CodeCommit that don't expose language information via API.

    Args:
        directory: Path to the repository directory to analyze

    Returns:
        The dominant programming language name (lowercase), or "unknown" if no
        language files are detected or an error occurs.

    Example:
        >>> language = detect_language_from_directory("/tmp/my-repo")
        >>> print(language)  # "python"
    """
    import os
    from collections import defaultdict

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
        "c++": [".cpp", ".cc", ".cxx", ".hpp", ".hxx"],
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
        for dirpath, dirnames, filenames in os.walk(directory):
            # Skip common directories that don't contain source code
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]

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
            primary_count = language_counts[primary_language]
            percentage = (primary_count / total_files * 100) if total_files > 0 else 0

            logger.info(
                f"Detected primary language: {primary_language} "
                f"({primary_count}/{total_files} files, {percentage:.1f}%)"
            )
            logger.info(f"Language breakdown: {dict(language_counts)}")

            return primary_language
        else:
            logger.warning("No programming language files detected in directory")
            return "unknown"

    except Exception as e:
        logger.error(f"Error detecting language from directory: {str(e)}")
        return "unknown"


def get_directory_size_mb(directory: str) -> float:
    """
    Calculate the total size of a directory in megabytes.

    Recursively walks through all files in the directory and sums their sizes.
    Files that cannot be accessed are silently skipped.

    Args:
        directory: Path to the directory to measure

    Returns:
        Size of the directory in megabytes (float)

    Example:
        >>> size = get_directory_size_mb("/tmp/my-repo")
        >>> print(f"Repository size: {size:.2f}MB")
    """
    import os

    total_size = 0
    try:
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                try:
                    if os.path.exists(filepath):
                        total_size += os.path.getsize(filepath)
                except (OSError, FileNotFoundError):
                    # Skip files that can't be accessed
                    continue
    except Exception as e:
        logger.error(f"Error calculating directory size: {str(e)}")
        return 0.0

    size_mb = total_size / (1024 * 1024)
    logger.info(f"Directory size: {size_mb:.2f}MB")
    return size_mb
