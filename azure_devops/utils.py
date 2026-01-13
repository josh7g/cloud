import os
import logging
from sqlalchemy import create_engine
from pydantic import BaseModel, ValidationError, model_validator
import ssl
import certifi
import aiohttp
from typing import Optional
from datetime import datetime
from models import AzureDevOpsAnalysisResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class ScanAzureDevopsRepoModel(BaseModel):
    workspace_id: str
    PAT: Optional[str] = None
    access_token: Optional[str] = None
    organization_name: str
    project: str
    repo: str
    user_id: str

    @model_validator(mode="after")
    def validate_auth(self):
        if not self.PAT and not self.access_token:
            raise ValueError("Either PAT or access_token must be provided")
        if self.PAT and self.access_token:
            raise ValueError("Only one of PAT or access_token should be provided")
        return self


class GetAzureDevopsFileModel(BaseModel):
    PAT: Optional[str] = None
    access_token: Optional[str] = None
    organization_name: str
    project: str
    repo: str
    file_name: str
    user_id: str

    @model_validator(mode="after")
    def validate_auth(self):
        if not self.PAT and not self.access_token:
            raise ValueError("Either PAT or access_token must be provided")
        if self.PAT and self.access_token:
            raise ValueError("Only one of PAT or access_token should be provided")
        return self


def stringify_pydantic_error(error: ValidationError) -> str:
    user_friendly_message = map(
        lambda e: f"'{e['loc'][0]}' field {e['type']}", error.errors()
    )
    return ", ".join(list(user_friendly_message))


def create_auth_header(
    PAT: Optional[str] = None, access_token: Optional[str] = None
) -> dict:
    """
    Create authorization header for Azure DevOps API requests.

    Args:
        PAT: Personal Access Token (uses Basic auth)
        access_token: OAuth access token (uses Bearer auth)

    Returns:
        dict: Authorization header
    """
    import base64

    if PAT:
        token = base64.b64encode(f":{PAT}".encode()).decode()
        return {"Authorization": f"Basic {token}"}
    elif access_token:
        return {"Authorization": f"Bearer {access_token}"}
    else:
        raise ValueError("Either PAT or access_token must be provided")


def get_api_error_format_dict(message: str, code: str):
    return {
        "success": False,
        "error": {
            "message": message,
            "code": code,
        },
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
        connector=conn, timeout=client_timeout, raise_for_status=True
    )


def create_api_engine():
    """Create database engine using individual DB environment variables"""
    # Get database credentials from environment
    db_host = os.getenv("DB_HOST")
    db_name = os.getenv("DB_NAME")
    db_port = os.getenv("DB_PORT", "5432")
    db_username = os.getenv("DB_USERNAME")
    db_password = os.getenv("DB_PASSWORD")

    # Validate all required variables are present
    missing_vars = []
    if not db_host:
        missing_vars.append("DB_HOST")
    if not db_name:
        missing_vars.append("DB_NAME")
    if not db_username:
        missing_vars.append("DB_USERNAME")
    if not db_password:
        missing_vars.append("DB_PASSWORD")

    if missing_vars:
        logger.error(f"Missing database environment variables: {missing_vars}")
        raise ValueError(
            f"Missing required database variables: {', '.join(missing_vars)}"
        )

    # Construct the PostgreSQL connection URL
    database_url = (
        f"postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"
    )

    # Log success (without exposing password)
    logger.info(
        f"Database URL constructed: postgresql://{db_username}:***@{db_host}:{db_port}/{db_name}"
    )

    return create_engine(
        database_url,
        pool_size=2,  # Small pool for API
        max_overflow=1,  # Limited overflow
        pool_timeout=60,  # Longer timeout
        pool_recycle=300,
        pool_pre_ping=True,
        pool_reset_on_return="rollback",
    )


def validate_workspace_id(workspace_id):
    """
    Validate workspace_id format (MongoDB ObjectId - 24 hex characters)

    Args:
        workspace_id (str): The workspace_id to validate

    Returns:
        dict: {"valid": bool, "error": str|None}
    """
    if not workspace_id:
        return {"valid": False, "error": "workspace_id is required"}

    if not isinstance(workspace_id, str):
        return {"valid": False, "error": "workspace_id must be a string"}

    if len(workspace_id) != 24:
        return {"valid": False, "error": "workspace_id must be 24 characters long"}

    # Check if it's valid hex
    try:
        int(workspace_id, 16)
    except ValueError:
        return {
            "valid": False,
            "error": "workspace_id must be a valid hexadecimal string",
        }

    return {"valid": True, "error": None}


def build_workspace_query(query, user_id=None, workspace_id=None):
    """
    Helper function to build database queries with workspace and user filtering

    Args:
        query: SQLAlchemy query object
        user_id (str, optional): User ID to filter by
        workspace_id (str, optional): Workspace ID to filter by

    Returns:
        SQLAlchemy query object with applied filters
    """
    # Priority: workspace_id > user_id
    if workspace_id:
        query = query.filter(AzureDevOpsAnalysisResult.workspace_id == workspace_id)
        logger.info(f"Applied workspace filter: {workspace_id}")
    elif user_id:
        query = query.filter(AzureDevOpsAnalysisResult.user_id == user_id)
        logger.info(f"Applied user filter: {user_id} (no workspace filter)")

    return query


async def get_workspace_from_user(user_id):
    """
    Get workspace_id for a user from the customer API (for backwards compatibility)

    Args:
        user_id (str): User ID to lookup

    Returns:
        str|None: workspace_id if found, None otherwise
    """
    try:
        dashboard_url = os.getenv("DASHBOARD_URL")
        if not dashboard_url:
            logger.warning("DASHBOARD_URL not configured")
            return None

        customer_endpoint = f"{dashboard_url.rstrip('/')}/v1/customer"

        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.get(customer_endpoint) as response:
                if response.status == 200:
                    data = await response.json()
                    customers = data.get("customers", [])

                    for customer in customers:
                        if customer.get("userId") == user_id:
                            workspace_id = customer.get("currentWorkspace")
                            if workspace_id:
                                logger.info(
                                    f"Found workspace {workspace_id} for user {user_id}"
                                )
                                return workspace_id

                    logger.warning(f"User {user_id} not found in customer API")
                    return None
                else:
                    logger.error(f"Customer API returned status {response.status}")
                    return None

    except Exception as e:
        logger.error(f"Error fetching workspace for user {user_id}: {str(e)}")
        return None


def prepare_scan_metadata(user_id, workspace_id, include_workspace_lookup=False):
    """
    Prepare metadata for scan responses including workspace information

    Args:
        user_id (str): User ID
        workspace_id (str): Workspace ID
        include_workspace_lookup (bool): Whether to include workspace lookup info

    Returns:
        dict: Metadata dictionary
    """
    metadata = {
        "user_id": user_id,
        "workspace_id": workspace_id,
        "workspace_filtering": bool(workspace_id),
        "timestamp": datetime.now().isoformat(),
    }

    if include_workspace_lookup:
        metadata.update(
            {
                "workspace_support": True,
                "transition_phase": "workspace_enabled",  # Indicates we're in the transition phase
            }
        )

    return metadata


async def get_latest_commit_sha(organization, project, repo_name, PAT=None, access_token=None, branch_name=None):
    """
    Get latest commit SHA for the given Azure DevOps repo (on the given branch).
    """
    from urllib.parse import quote
    logger.critical(f"*** URGENT: Fetching latest commit SHA for Azure DevOps {organization}/{project}/{repo_name}")
    logger.debug(f"Azure DevOps commit SHA request: branch={branch_name}, org={organization}, project={project}")
    
    headers = create_auth_header(PAT=PAT, access_token=access_token)
    branch_param = f"&searchCriteria.itemVersion.version={quote(branch_name)}" if branch_name else ""
    url = f"https://dev.azure.com/{quote(organization)}/{quote(project)}/_apis/git/repositories/{quote(repo_name)}/commits?searchCriteria.$top=1{branch_param}&api-version=6.0"

    async with create_secure_client_session() as session:
        async with session.get(url, headers=headers) as response:
            if response.status != 200:
                logger.error(f"Azure DevOps commit SHA fetch failed: {response.status} {await response.text()}")
                raise Exception(f"Failed to fetch latest commit SHA: {response.status} {await response.text()}")
            data = await response.json()
            commits = data.get("value", [])
            if not commits:
                logger.error(f"Azure DevOps no commits found for {organization}/{project}/{repo_name}")
                raise Exception("No commits found on repo/branch")
            commit_sha = commits[0]["commitId"]
            logger.critical(f"*** URGENT: Azure DevOps latest commit SHA: {commit_sha}")
            logger.debug(f"Azure DevOps commit details: sha={commit_sha}, author={commits[0].get('author', {}).get('name', 'unknown')}")
            return commit_sha

async def get_changed_files_between_commits(organization, project, repo_name, from_commit, to_commit, PAT=None, access_token=None):
    """
    Get list of changed files between from_commit and to_commit using Azure DevOps REST API.
    """
    from urllib.parse import quote
    logger.critical(f"*** URGENT: Fetching changed files for Azure DevOps {organization}/{project}/{repo_name} between {from_commit} and {to_commit}")
    logger.debug(f"Azure DevOps diff request: from_commit={from_commit}, to_commit={to_commit}")
    
    headers = create_auth_header(PAT=PAT, access_token=access_token)
    diff_url = (
        f"https://dev.azure.com/{quote(organization)}/{quote(project)}/_apis/git/repositories/{quote(repo_name)}/diffs/commits?"
        f"baseVersion={from_commit}&targetVersion={to_commit}&api-version=6.0"
    )
    async with create_secure_client_session() as session:
        async with session.get(diff_url, headers=headers) as response:
            if response.status != 200:
                logger.error(f"Azure DevOps diff fetch failed: {response.status} {await response.text()}")
                raise Exception(f"Failed to fetch diff: {response.status} {await response.text()}")
            data = await response.json()
            changes = data.get("changes", [])
            files = [c["item"]["path"] for c in changes if "item" in c and "path" in c["item"]]
            logger.critical(f"*** URGENT: Azure DevOps found {len(files)} changed files")
            logger.debug(f"Azure DevOps changed files: {files[:10]}{'...' if len(files) > 10 else ''}")
            return files
