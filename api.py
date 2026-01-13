from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc, create_engine, text
from sqlalchemy.orm import sessionmaker
from models import (
    db,
    AnalysisResult,
    AzureDevOpsAnalysisResult,
    GitLabAnalysisResult,
    IgnoredFinding,
    RepositoryScanResult,
    FixRequest,
)
from collections import defaultdict
import os
import ssl
import fnmatch
import logging
from pathlib import Path
from github import Github, GithubIntegration
import asyncio
import aiohttp
import json
from scanner import (
    scan_repository_handler,
    deduplicate_findings,
    process_findings_with_rag,
    extract_enriched_rerank_data,
    SecurityScanner,
    ScanConfig,
)
from db_utils import create_db_engine
from progress_tracking import update_scan_progress
from ignore_utils import (
    add_ignore_status_to_findings,
    create_ignore_record,
    remove_ignore_record,
    get_user_ignores,
    normalize_file_path,
    calculate_affected_findings_for_ignore,
)
from fix_utils import (
    add_fix_status_to_findings,
    get_finding_key,
)
from utils import (
    extract_clean_file_path,
    get_repository_identifier,
    create_secure_client_session,
)
import base64
from datetime import datetime, timezone

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ============================================================================
# INPUT SANITIZATION - Security helper functions
# ============================================================================


def sanitize_string_input(value, max_length=500, allow_special=False):
    """Sanitize string input to prevent injection attacks"""
    if not isinstance(value, str):
        return value
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    value = value.replace("\x00", "")
    if not allow_special:
        dangerous_chars = [
            "<",
            ">",
            '"',
            "'",
            "\\",
            ";",
            "&",
            "|",
            "`",
            "$",
            "(",
            ")",
            "{",
            "}",
            "[",
            "]",
        ]
        for char in dangerous_chars:
            value = value.replace(char, "")
    return value


def sanitize_request_data(data):
    """Recursively sanitize all string values in request data"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            allow_special = key in [
                "code_snippet",
                "reason",
                "description",
                "message",
                "fix_description",
                "target",
            ]
            if isinstance(value, str):
                sanitized[key] = sanitize_string_input(
                    value, allow_special=allow_special
                )
            elif isinstance(value, dict):
                sanitized[key] = sanitize_request_data(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    (
                        sanitize_request_data(item)
                        if isinstance(item, (dict, str))
                        else item
                    )
                    for item in value
                ]
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, str):
        return sanitize_string_input(data)
    else:
        return data


# ============================================================================


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
        query = query.filter(AnalysisResult.workspace_id == workspace_id)
        logger.info(f"Applied workspace filter: {workspace_id}")
    elif user_id:
        query = query.filter(AnalysisResult.user_id == user_id)
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


def create_api_engine():
    """Create database engine using individual DB environment variables"""
    import os

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


api = Blueprint("api", __name__, url_prefix="/api/v1")


@api.route("/files", methods=["POST"])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitHub using POST with all parameters in request body"""
    from app import git_integration

    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return (
            jsonify(
                {"success": False, "error": {"message": "Request body is required"}}
            ),
            400,
        )

    # Get required parameters from request body

    # Sanitize input data
    request_data = sanitize_request_data(request_data)
    owner = request_data.get("owner")
    owner = request_data.get("owner")
    repo = request_data.get("repo")
    installation_id = request_data.get("installation_id")
    filename = request_data.get("file_name")
    user_id = request_data.get("user_id")

    # Validate required parameters
    required_params = {
        "owner": owner,
        "repo": repo,
        "installation_id": installation_id,
        "file_name": filename,
        "user_id": user_id,
    }

    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": f'Missing required parameters: {", ".join(missing_params)}'
                    },
                }
            ),
            400,
        )

    try:
        # Get GitHub token
        installation_token = git_integration.get_access_token(
            int(installation_id)
        ).token
        gh = Github(installation_token)

        repository = gh.get_repo(f"{owner}/{repo}")
        default_branch = repository.default_branch
        latest_commit = repository.get_branch(default_branch).commit
        commit_sha = latest_commit.sha

        # Get file content from GitHub
        try:
            file_content = repository.get_contents(
                extract_clean_file_path(filename), ref=commit_sha
            )
            content = file_content.decoded_content.decode("utf-8")

            return jsonify(
                {
                    "success": True,
                    "data": {
                        "file": content,
                        "user_id": user_id,
                        "version": commit_sha,
                        "reponame": f"{owner}/{repo}",
                        "filename": filename,
                    },
                }
            )

        except Exception as e:
            logger.error(f"Error fetching file: {str(e)}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": "File not found or inaccessible"},
                    }
                ),
                404,
            )

    except Exception as e:
        logger.error(f"GitHub API error: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


analysis_bp = Blueprint("analysis", __name__, url_prefix="/api/v1/analysis")


@analysis_bp.route("/<owner>/<repo>/result", methods=["GET"])
def get_analysis_findings(owner: str, repo: str):
    """Get analysis findings with workspace filtering and ignore status included"""
    engine = None
    db_session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get query parameters
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(400, max(1, int(request.args.get("limit", 30))))
        severity = request.args.get("severity", "").upper()
        category = request.args.get("category", "")
        file_path = request.args.get("file", "")
        user_id = request.args.get("user_id")
        workspace_id = request.args.get("workspace_id")  # NEW: Add workspace_id filter

        repo_name = f"{owner}/{repo}"

        # Build query for latest analysis result with workspace filtering
        query = db_session.query(AnalysisResult).filter_by(repository_name=repo_name)

        # Apply workspace filtering if provided
        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)
            logger.info(f"Filtering analysis results by workspace_id: {workspace_id}")

        # Apply user filtering if provided (fallback for compatibility)
        if user_id and not workspace_id:
            query = query.filter_by(user_id=user_id)
            logger.info(
                f"Filtering analysis results by user_id: {user_id} (no workspace filter)"
            )

        result = query.order_by(desc(AnalysisResult.timestamp)).first()

        if not result:
            error_message = "No analysis found"
            if workspace_id:
                error_message += f" for workspace {workspace_id}"
            if user_id:
                error_message += f" for user {user_id}"

            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": error_message,
                            "code": "ANALYSIS_NOT_FOUND",
                        },
                    }
                ),
                404,
            )

        # Extract results dynamically
        results = result.results or {}
        stats = results.get("stats", {})
        metadata = results.get("metadata", {})
        findings = results.get("findings", [])

        # Add ignore status to findings if user_id is provided
        if user_id and findings:
            findings = add_ignore_status_to_findings(
                user_id, repo_name, findings, workspace_id, "github"
            )

            # Add fix request status to findings
            findings = add_fix_status_to_findings(
                user_id, repo_name, findings, workspace_id, "github", db_session
            )

        # Apply filters
        if severity:
            findings = [
                f for f in findings if f.get("severity", "").upper() == severity
            ]
        if category:
            findings = [
                f for f in findings if f.get("category", "").lower() == category.lower()
            ]
        if file_path:
            # Apply normalization to file filter as well
            from ignore_utils import normalize_file_path

            normalized_filter_path = normalize_file_path(file_path)
            findings = [
                f
                for f in findings
                if normalized_filter_path in normalize_file_path(f.get("file", ""))
            ]

        # Prepare findings with ID
        indexed_findings = [
            {
                **finding,
                "ID": idx + 1,
                "cwe": finding.get("cwe", []),
                "owasp": finding.get("owasp", []),
                "references": finding.get("references", []),
                "fix_recommendations": finding.get("fix_recommendations", ""),
                "scan_source": finding.get("scan_source", ""),
                # Include ignore status fields
                "ignored": finding.get("ignored", False),
                "ignore_reason": finding.get("ignore_reason"),
                "ignore_type": finding.get("ignore_type"),
                "ignored_at": finding.get("ignored_at"),
                "ignored_by": finding.get("ignored_by"),
                # Include fix request status fields
                "fix_status": finding.get("fix_status"),
                "pr_url": finding.get("pr_url"),
                "pr_number": finding.get("pr_number"),
                "pr_title": finding.get("pr_title"),
                "pr_created_at": finding.get("pr_created_at"),
                "pr_merged_at": finding.get("pr_merged_at"),
                "pr_closed_at": finding.get("pr_closed_at"),
                "fix_error": finding.get("fix_error"),
                "fix_description": finding.get("fix_description"),
                "fix_request_id": finding.get("fix_request_id"),
                "webhook_enabled": finding.get("webhook_enabled"),
                "webhook_url": finding.get("webhook_url"),
            }
            for idx, finding in enumerate(findings)
        ]

        # Total findings after filtering
        total_findings = len(indexed_findings)

        # Pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_findings = indexed_findings[start_idx:end_idx]

        # Calculate ignore statistics if user_id provided
        ignore_stats = {}
        if user_id and indexed_findings:
            total_ignored = sum(1 for f in indexed_findings if f.get("ignored", False))
            ignore_stats = {
                "total_ignored": total_ignored,
                "total_active": total_findings - total_ignored,
                "ignore_percentage": (
                    round((total_ignored / total_findings) * 100, 1)
                    if total_findings > 0
                    else 0
                ),
            }

        # **NEW: Calculate adjusted severity counts based on ignore status**
        original_severity_counts = stats.get("severity_counts", {})
        complete_severity_counts = {
            "CRITICAL": int(original_severity_counts.get("CRITICAL", 0) or 0),
            "HIGH": int(original_severity_counts.get("HIGH", 0) or 0),
            "MEDIUM": int(original_severity_counts.get("MEDIUM", 0) or 0),
            "LOW": int(original_severity_counts.get("LOW", 0) or 0),
        }

        # If user_id provided, adjust severity counts by removing ignored findings
        if user_id and indexed_findings:
            # Recalculate severity counts excluding ignored findings
            adjusted_severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            }

            ignored_severity_counts = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
            }

            for finding in indexed_findings:
                severity_level = str(finding.get("severity", "LOW")).upper()
                is_ignored = finding.get("ignored", False)

                if is_ignored:
                    # Count ignored findings separately
                    if severity_level in ignored_severity_counts:
                        ignored_severity_counts[severity_level] += 1
                else:
                    # Count active (non-ignored) findings
                    if severity_level in adjusted_severity_counts:
                        adjusted_severity_counts[severity_level] += 1

            # Use adjusted counts instead of original
            complete_severity_counts = adjusted_severity_counts

            # Add ignored counts to ignore_stats for transparency
            ignore_stats["ignored_severity_counts"] = ignored_severity_counts

        # Prepare summary
        summary = {
            "category_counts": stats.get("category_counts", {}),
            "files_scanned": stats.get("scan_stats", {}).get("files_scanned", 0),
            "files_with_findings": stats.get("scan_stats", {}).get(
                "files_with_findings", 0
            ),
            "partially_scanned": 0,
            "severity_counts": complete_severity_counts,  # **NOW ADJUSTED FOR IGNORES**
            "skipped_files": stats.get("scan_stats", {}).get("skipped_files", 0),
            "total_findings": total_findings
            - (
                ignore_stats.get("total_ignored", 0) if user_id else 0
            ),  # **ADJUSTED TOTAL**
            "ignore_stats": ignore_stats,
        }

        # Prepare filters
        available_categories = sorted(
            set(f.get("category", "").lower() for f in findings)
        )
        available_severities = sorted(
            set(f.get("severity", "").upper() for f in findings)
        )

        return jsonify(
            {
                "success": True,
                "data": {
                    "repository": {
                        "name": repo_name,
                        "owner": owner,
                        "repo": repo.split("/")[-1],
                    },
                    "metadata": {
                        "analysis_id": result.id,
                        "duration_seconds": metadata.get("scan_duration_seconds", 0),
                        "status": result.status,
                        "timestamp": result.timestamp.isoformat(),
                        "user_id": user_id,
                        "workspace_id": workspace_id,  # NEW: Include workspace_id in response
                        "actual_workspace_id": result.workspace_id,  # NEW: Show actual workspace from DB
                        "ignore_support": bool(user_id),
                        "workspace_filtering": bool(
                            workspace_id
                        ),  # NEW: Indicate if workspace filtering was applied
                    },
                    "pagination": {
                        "current_page": page,
                        "per_page": per_page,
                        "total_items": total_findings,
                        "total_pages": (total_findings + per_page - 1) // per_page,
                    },
                    "filters": {
                        "available_categories": available_categories,
                        "available_severities": available_severities,
                    },
                    "summary": summary,
                    "findings": paginated_findings,
                },
            }
        )

    except Exception as e:
        logger.error(f"Error getting findings: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": "Internal server error",
                        "code": "INTERNAL_ERROR",
                        "details": str(e),
                    },
                }
            ),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/scan/<owner>/<repo>", methods=["DELETE"])
def delete_scan_results(owner: str, repo: str):
    """Delete scan results for a specific repository"""
    engine = None
    db_session = None
    try:
        repo_name = f"{owner}/{repo}"
        logger.info(f"[GitHub] Starting delete request for repository: {repo_name}")

        # Get user_id from query parameter or request body
        user_id = request.args.get("user_id") or (request.get_json() or {}).get(
            "user_id"
        )

        logger.info(
            f"[GitHub] Delete request - repo_name: {repo_name}, user_id: {user_id}"
        )

        if not user_id:
            logger.warning(
                f"[GitHub] Delete request failed - missing user_id for repo: {repo_name}"
            )
            return (
                jsonify(
                    {"success": False, "error": {"message": "user_id is required"}}
                ),
                400,
            )

        # Create engine using the new function
        logger.info(f"[GitHub] Creating database connection for delete operation")
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get all analyses for this repository
        logger.info(
            f"[GitHub] Querying analyses for repository: {repo_name}, user_id: {user_id}"
        )
        analyses = (
            db_session.query(AnalysisResult)
            .filter(
                AnalysisResult.repository_name == repo_name,
                AnalysisResult.user_id == user_id,
            )
            .all()
        )

        logger.info(
            f"[GitHub] Found {len(analyses)} analyses to delete for repository: {repo_name}"
        )

        # Even if no analyses, continue to remove any ignore records for this repo
        if not analyses:
            logger.info(
                f"[GitHub] No analyses found for repository: {repo_name}, user_id: {user_id}"
            )
        else:
            # Log details about analyses being deleted
            for i, analysis in enumerate(analyses):
                logger.info(
                    f"[GitHub] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                    f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                    f"Workspace ID: {analysis.workspace_id}"
                )

            # Delete all analyses
            logger.info(f"[GitHub] Starting deletion of {len(analyses)} analyses")
            for analysis in analyses:
                db_session.delete(analysis)
                logger.debug(f"[GitHub] Marked analysis {analysis.id} for deletion")

            logger.info(f"[GitHub] Committing deletion transaction")
            db_session.commit()
            logger.info(
                f"[GitHub] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
            )
        # Delete associated ignore records for this repo and user
        logger.info(
            f"[GitHub] Removing ignore records for repo: {repo_name}, user_id: {user_id}"
        )
        ignore_query = (
            db_session.query(IgnoredFinding)
            .filter(IgnoredFinding.repo_name == repo_name)
            .filter(IgnoredFinding.user_id == user_id)
            .filter(IgnoredFinding.repo_type == "github")
        )
        ignore_records = ignore_query.all()
        logger.info(
            f"[GitHub] Found {len(ignore_records)} ignore records to delete for repo: {repo_name}"
        )
        for record in ignore_records:
            db_session.delete(record)
        db_session.commit()
        logger.info(
            f"[GitHub] Successfully deleted {len(ignore_records)} ignore records for repository: {repo_name}"
        )

        return jsonify("DONE")

    except Exception as e:
        logger.error(
            f"[GitHub] Error deleting scan results for repository {repo_name}: {str(e)}",
            exc_info=True,
        )
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": "Internal server error",
                        "code": "INTERNAL_ERROR",
                        "details": str(e),
                    },
                }
            ),
            500,
        )
    finally:
        if db_session:
            logger.debug(f"[GitHub] Closing database session")
            db_session.close()
        if engine:
            logger.debug(f"[GitHub] Disposing database engine")
            engine.dispose()


@api.route("/users/severity-counts", methods=["POST"])
def get_user_severity_counts():
    engine = None
    db_session = None
    try:
        request_data = request.get_json()
        if not request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        user_id = request_data.get("user_id")
        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")  # NEW: Accept workspace_id
        include_ignored = request_data.get("include_ignored", False)

        # Validate required parameters
        if not user_id:
            return (
                jsonify(
                    {"success": False, "error": {"message": "user_id is required"}}
                ),
                400,
            )

        logger.info(
            f"Processing severity counts for user_id: {user_id}, workspace_id: {workspace_id}, include_ignored: {include_ignored}"
        )

        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Build query for completed analyses
        query = db_session.query(AnalysisResult).filter(
            AnalysisResult.status == "completed",
            AnalysisResult.results.isnot(None),
        )

        # Apply workspace filtering if provided
        if workspace_id:
            query = query.filter(AnalysisResult.workspace_id == workspace_id)
            logger.info(f"Filtering by workspace_id: {workspace_id}")
        else:
            query = query.filter(AnalysisResult.user_id == user_id)

        all_analyses = query.order_by(AnalysisResult.timestamp.desc()).all()

        logger.info(f"Found {len(all_analyses)} analyses after workspace filtering")

        # Get latest analysis per repository
        latest_analyses = {}
        for analysis in all_analyses:
            repo_name = analysis.repository_name
            if repo_name not in latest_analyses:
                latest_analyses[repo_name] = analysis

        if not latest_analyses:
            error_message = "No analyses found for this user"
            if workspace_id:
                error_message += f" in workspace {workspace_id}"

            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": error_message},
                    }
                ),
                404,
            )

        repository_data = {}
        # These counts represent ACTIVE findings only (unless include_ignored=True)
        total_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        # Separate tracking for ignored findings (always tracked for transparency)
        total_ignored_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_findings = 0  # Active findings count
        total_ignored_findings = 0  # Always tracked separately
        latest_scan_time = None

        for repo_name, analysis in latest_analyses.items():
            results = analysis.results or {}

            # Get findings and add ignore status
            findings = results.get("findings", [])
            if findings:
                findings = add_ignore_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "github"
                )

            repo_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            repo_ignored_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

            repo_total_findings = 0  # Active findings for this repo
            repo_ignored_findings = 0  # Ignored findings for this repo

            for finding in findings:
                severity = str(finding.get("severity", "LOW")).upper()
                is_ignored = finding.get("ignored", False)

                if is_ignored:
                    # Always track ignored findings separately
                    if severity in repo_ignored_counts:
                        repo_ignored_counts[severity] += 1
                    if severity in total_ignored_counts:
                        total_ignored_counts[severity] += 1
                    repo_ignored_findings += 1
                    total_ignored_findings += 1

                    # Only include in main counts if explicitly requested
                    if include_ignored:
                        if severity in repo_severity_counts:
                            repo_severity_counts[severity] += 1
                        if severity in total_severity_counts:
                            total_severity_counts[severity] += 1
                        repo_total_findings += 1
                        total_findings += 1
                else:
                    # Always count active findings
                    if severity in repo_severity_counts:
                        repo_severity_counts[severity] += 1
                    if severity in total_severity_counts:
                        total_severity_counts[severity] += 1
                    repo_total_findings += 1
                    total_findings += 1

            current_scan_time = analysis.timestamp
            latest_scan_time = (
                max(latest_scan_time, current_scan_time)
                if latest_scan_time
                else current_scan_time
            )

            repository_data[repo_name] = {
                "name": repo_name,
                "workspace_id": analysis.workspace_id,  # NEW: Include workspace_id for each repo
                "severity_counts": repo_severity_counts,  # Active findings (+ ignored if include_ignored=True)
                "ignored_counts": repo_ignored_counts,  # Always shows ignored counts
                "total_findings": repo_total_findings,  # Active findings (+ ignored if include_ignored=True)
                "total_ignored": repo_ignored_findings,  # Always shows ignored count
            }

        return jsonify(
            {
                "success": True,
                "data": {
                    "user_id": user_id,
                    "workspace_id": workspace_id,  # NEW: Include workspace_id in response
                    "total_findings": total_findings,  # Active findings (+ ignored if include_ignored=True)
                    "total_ignored_findings": total_ignored_findings,  # Always shows ignored count
                    "total_repositories": len(repository_data),
                    "severity_counts": total_severity_counts,  # Active findings (+ ignored if include_ignored=True)
                    "ignored_severity_counts": total_ignored_counts,  # Always shows ignored breakdown
                    "repositories": repository_data,
                    "metadata": {
                        "last_scan": (
                            latest_scan_time.isoformat() if latest_scan_time else None
                        ),
                        "scans_analyzed": len(repository_data),
                        "include_ignored": include_ignored,
                        "ignore_support": True,
                        "workspace_filtering": bool(
                            workspace_id
                        ),  # NEW: Indicate if workspace filtering was applied
                    },
                },
            }
        )

    except Exception as e:
        logger.error(f"Error getting severity counts: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/users/<user_id>/top-vulnerabilities", methods=["GET"])
def get_top_vulnerabilities(user_id):
    engine = None
    db_session = None
    try:
        # Get query parameters
        include_ignored = request.args.get("include_ignored", "true").lower() == "true"
        workspace_id = request.args.get(
            "workspace_id"
        )  # NEW: Accept workspace_id filter

        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Build query for analyses
        query = db_session.query(AnalysisResult).filter(
            AnalysisResult.status == "completed",
            AnalysisResult.results.isnot(None),
        )

        # Apply workspace filtering if provided
        if workspace_id:
            query = query.filter(AnalysisResult.workspace_id == workspace_id)
            logger.info(
                f"Filtering top vulnerabilities by workspace_id: {workspace_id}"
            )
        else:
            query = query.filter(AnalysisResult.user_id == user_id)

        analyses = query.order_by(AnalysisResult.timestamp.desc()).all()

        if not analyses:
            error_message = "No analyses found"
            if workspace_id:
                error_message += f" for workspace {workspace_id}"

            return (
                jsonify({"success": False, "error": {"message": error_message}}),
                404,
            )

        # Track statistics with ignore awareness
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        repo_counts = defaultdict(int)
        workspace_counts = defaultdict(int)  # NEW: Track workspace distribution
        ignored_severity_counts = defaultdict(int)
        ignored_category_counts = defaultdict(int)
        unique_vulns = {}
        total_ignored_vulnerabilities = 0

        for analysis in analyses:
            findings = analysis.results.get("findings", [])
            repo_name = analysis.repository_name
            analysis_workspace_id = analysis.workspace_id

            # Add ignore status to findings
            if findings:
                findings = add_ignore_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "github"
                )

            for finding in findings:
                vuln_id = finding.get("id")
                is_ignored = finding.get("ignored", False)
                severity = finding.get("severity")
                category = finding.get("category")

                # Track ignored statistics
                if is_ignored:
                    ignored_severity_counts[severity] += 1
                    ignored_category_counts[category] += 1
                    total_ignored_vulnerabilities += 1

                # Only include vulnerability in results based on include_ignored parameter
                if include_ignored or not is_ignored:
                    if vuln_id not in unique_vulns:
                        unique_vulns[vuln_id] = {
                            "vulnerability_id": vuln_id,
                            "severity": severity,
                            "category": category,
                            "message": finding.get("message"),
                            "code_snippet": finding.get("code_snippet"),
                            "file": finding.get("file"),
                            "line_range": {
                                "start": finding.get("line_start"),
                                "end": finding.get("line_end"),
                            },
                            "security_references": {
                                "cwe": finding.get("cwe", []),
                                "owasp": finding.get("owasp", []),
                            },
                            "fix_recommendations": {
                                "description": finding.get("fix_recommendations", ""),
                                "references": finding.get("references", []),
                            },
                            "repository": {
                                "name": repo_name.split("/")[-1],
                                "full_name": repo_name,
                                "analyzed_at": analysis.timestamp.isoformat(),
                                "workspace_id": analysis_workspace_id,  # NEW: Include workspace info
                            },
                            # Include ignore status in vulnerability data
                            "ignored": is_ignored,
                            "ignore_reason": finding.get("ignore_reason"),
                            "ignore_type": finding.get("ignore_type"),
                            "ignored_at": finding.get("ignored_at"),
                            "ignored_by": finding.get("ignored_by"),
                            # Include fix status fields
                            "fix_status": finding.get("fix_status"),
                            "pr_url": finding.get("pr_url"),
                            "pr_number": finding.get("pr_number"),
                            "pr_title": finding.get("pr_title"),
                            "pr_created_at": finding.get("pr_created_at"),
                            "pr_merged_at": finding.get("pr_merged_at"),
                            "pr_closed_at": finding.get("pr_closed_at"),
                            "fix_error": finding.get("fix_error"),
                            "fix_description": finding.get("fix_description"),
                            "fix_request_id": finding.get("fix_request_id"),
                            "webhook_enabled": finding.get("webhook_enabled"),
                            "webhook_url": finding.get("webhook_url"),
                        }

                        severity_counts[severity] += 1
                        category_counts[category] += 1
                        repo_counts[repo_name] += 1
                        if analysis_workspace_id:  # Count workspace distribution
                            workspace_counts[analysis_workspace_id] += 1

        return jsonify(
            {
                "success": True,
                "data": {
                    "metadata": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,  # NEW: Include workspace filter info
                        "total_vulnerabilities": len(unique_vulns),
                        "total_ignored_vulnerabilities": total_ignored_vulnerabilities,
                        "total_repositories": len(repo_counts),
                        "total_workspaces": len(
                            workspace_counts
                        ),  # NEW: Workspace count
                        "severity_breakdown": dict(severity_counts),
                        "ignored_severity_breakdown": dict(ignored_severity_counts),
                        "category_breakdown": dict(category_counts),
                        "ignored_category_breakdown": dict(ignored_category_counts),
                        "repository_breakdown": dict(repo_counts),
                        "workspace_breakdown": dict(
                            workspace_counts
                        ),  # NEW: Workspace breakdown
                        "last_scan": (
                            analyses[0].timestamp.isoformat() if analyses else None
                        ),
                        "repository": None,
                        "include_ignored": include_ignored,
                        "ignore_support": True,
                        "workspace_filtering": bool(
                            workspace_id
                        ),  # NEW: Indicate if workspace filtering applied
                    },
                    "vulnerabilities": list(unique_vulns.values()),
                },
            }
        )

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/scan", methods=["POST"])
def trigger_repository_scan():
    """Trigger a semgrep security scan for a repository and get reranking"""
    from app import git_integration, socketio
    import time

    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return (
            jsonify(
                {"success": False, "error": {"message": "Request body is required"}}
            ),
            400,
        )

    # Get required parameters

    # Sanitize input data
    request_data = sanitize_request_data(request_data)
    owner = request_data.get("owner")
    owner = request_data.get("owner")
    repo = request_data.get("repo")
    installation_id = request_data.get("installation_id")
    user_id = request_data.get("user_id")
    workspace_id = request_data.get("workspace_id")  # NEW: Required workspace_id

    # Validate required parameters
    required_params = {
        "owner": owner,
        "repo": repo,
        "installation_id": installation_id,
        "user_id": user_id,
        "workspace_id": workspace_id,  # NEW: Make workspace_id required
    }

    missing_params = [param for param, value in required_params.items() if not value]
    if missing_params:
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": f'Missing required parameters: {", ".join(missing_params)}',
                        "code": "INVALID_PARAMETERS",
                    },
                }
            ),
            400,
        )

    # NEW: Validate workspace_id format (MongoDB ObjectId - 24 hex characters)
    if workspace_id and len(workspace_id) != 24:
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": "workspace_id must be a 24-character MongoDB ObjectId",
                        "code": "INVALID_WORKSPACE_ID",
                    },
                }
            ),
            400,
        )

    analysis = None
    engine = None
    db_session = None

    try:
        # Format repo name consistently for progress tracking
        repo_name = f"{owner}/{repo}"

        # Clear both progress AND completion cache for this repo
        from progress_tracking import get_redis_client

        redis_client = get_redis_client()

        # Define keys
        completion_key = f"scan_complete:{user_id}:{repo_name}"
        progress_key = f"scan_progress:{user_id}:{repo_name}"

        # Delete cached data
        redis_client.delete(completion_key)
        redis_client.delete(progress_key)
        logger.info(f"Cleared previous scan data for {repo_name}")

        # Send a reset message to all subscribers
        reset_data = {
            "s": "reset",
            "p": 0,
            "o": 0,
            "t": int(time.time()),
            "id": f"scan_{int(time.time())}",
        }

        room = f"scan_{user_id}_{repo_name}"
        socketio.emit("progress_update", reset_data, room=room)
        logger.info(f"Sent reset signal to room {room}")

        # Create engine using the function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # REUSING EXISTING ANALYSIS RECORD IF AVAILABLE (same repo/workspace)
        analysis = (
            db_session.query(AnalysisResult)
            .filter(
                AnalysisResult.repository_name == repo_name,
                AnalysisResult.workspace_id == workspace_id,
            )
            .order_by(desc(AnalysisResult.timestamp))
            .first()
        )

        if analysis:
            # REUSING EXISTING RECORD: only update status and timestamp; keepING results for merge
            analysis.status = "queued"
            analysis.timestamp = datetime.utcnow()
            db_session.commit()
            logger.info(
                f"Reusing existing analysis record ID: {analysis.id} for {repo_name} (workspace={workspace_id})"
            )
        else:
            analysis = AnalysisResult(
                repository_name=repo_name,
                user_id=user_id,
                workspace_id=workspace_id,
                status="queued",
            )
            db_session.add(analysis)
            db_session.commit()
            logger.info(
                f"Created analysis record with ID: {analysis.id}, workspace: {workspace_id}"
            )

        # Initialize progress tracking
        from progress_tracking import clear_scan_progress, update_scan_progress

        clear_scan_progress(user_id, repo_name)
        update_scan_progress(user_id, repo_name, "initializing", 5)

        # Get GitHub token
        installation_token = git_integration.get_access_token(
            int(installation_id)
        ).token

        # Start scan in background thread (runs directly in Flask app)
        def run_scan_in_background():
            # Create a new database session for this thread
            thread_engine = None
            thread_db_session = None
            try:
                # Create new engine and session for this thread
                thread_engine = create_api_engine()
                ThreadSession = sessionmaker(bind=thread_engine)
                thread_db_session = ThreadSession()

                # Get the analysis record in this thread's session
                thread_analysis = (
                    thread_db_session.query(AnalysisResult)
                    .filter_by(id=analysis.id)
                    .first()
                )

                if not thread_analysis:
                    logger.error(
                        f"Could not find analysis record {analysis.id} in thread"
                    )
                    return

                # Update status to in_progress
                thread_analysis.status = "in_progress"
                thread_db_session.commit()
                logger.info(
                    f"[GitHub Scan {analysis.id}] Status updated to in_progress"
                )

                # Run scan directly in this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    results = loop.run_until_complete(
                        scan_repository_handler(
                            repo_url=f"https://github.com/{owner}/{repo}",
                            installation_token=installation_token,
                            user_id=user_id,
                            db_session=thread_db_session,
                            analysis_record=thread_analysis,
                        )
                    )
                    logger.info(f"[GitHub Scan {analysis.id}] Completed successfully")
                finally:
                    loop.close()

            except Exception as e:
                # Handle errors
                logger.error(
                    f"[GitHub Scan {analysis.id}] Background scan error: {str(e)}",
                    exc_info=True,
                )
                if thread_db_session and thread_analysis:
                    try:
                        thread_analysis.status = "error"
                        thread_analysis.error = str(e)
                        thread_db_session.commit()
                        logger.info(
                            f"[GitHub Scan {analysis.id}] Error status saved to database"
                        )
                    except Exception as db_error:
                        logger.error(
                            f"[GitHub Scan {analysis.id}] Failed to save error status: {str(db_error)}"
                        )
                        thread_db_session.rollback()

                update_scan_progress(user_id, repo_name, "error", 100)
            finally:
                # Clean up thread resources
                if thread_db_session:
                    thread_db_session.close()
                if thread_engine:
                    thread_engine.dispose()
                logger.info(f"[GitHub Scan {analysis.id}] Thread cleanup completed")

        # Start the background thread
        from threading import Thread

        thread = Thread(target=run_scan_in_background, name=f"scan-{repo_name}")
        thread.daemon = True
        thread.start()
        logger.info(f"[GitHub Scan {analysis.id}] Background scan thread started")

        # Return immediately with instructions to poll progress
        return (
            jsonify(
                {
                    "success": True,
                    "message": "Scan queued successfully - running directly in Flask app",
                    "scan_id": analysis.id,
                    "status": "queued",
                    "repository": repo_name,
                    "workspace_id": workspace_id,
                    "scan_mode": "direct",  # Indicates scan runs in main app, not ECS
                }
            ),
            202,
        )

    except Exception as e:
        logger.error(f"Scan initialization error: {str(e)}")
        if analysis and db_session:
            try:
                analysis.status = "error"
                analysis.error = str(e)
                db_session.commit()
            except Exception as commit_error:
                logger.error(f"Failed to update analysis status: {str(commit_error)}")
                db_session.rollback()
        return (
            jsonify(
                {"success": False, "error": {"message": str(e), "code": "SCAN_ERROR"}}
            ),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@analysis_bp.route("/<owner>/<repo>/reranked", methods=["GET"])
def get_reranked_findings(owner: str, repo: str):
    engine = None
    session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        # Get query parameters
        user_id = request.args.get("user_id")
        logger.info(f"Reranked request: {owner}/{repo}, user_id={user_id}")

        # Get latest analysis result
        result = (
            session.query(AnalysisResult)
            .filter_by(repository_name=f"{owner}/{repo}")
            .order_by(desc(AnalysisResult.timestamp))
            .first()
        )

        if not result:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "No analysis found",
                            "code": "ANALYSIS_NOT_FOUND",
                        },
                    }
                ),
                404,
            )

        if not result.rerank:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "No reranked results available",
                            "code": "NO_RERANK_RESULTS",
                        },
                    }
                ),
                404,
            )

        # Get the reranked results
        reranked_data = (
            result.rerank.copy() if isinstance(result.rerank, dict) else result.rerank
        )

        logger.info(f"Reranked data type: {type(reranked_data)}")

        # Handle different reranked data structures
        findings_to_process = None

        if isinstance(reranked_data, list):
            # If reranked_data is directly a list of findings
            findings_to_process = reranked_data
            reranked_data = {"findings": reranked_data}
        elif isinstance(reranked_data, dict):
            if "findings" in reranked_data:
                findings_to_process = reranked_data["findings"]
            elif "reranked_findings" in reranked_data:
                findings_to_process = reranked_data["reranked_findings"]
            elif "results" in reranked_data:
                findings_to_process = reranked_data["results"]
            else:
                # Try to find findings in any key that looks like a list
                for key, value in reranked_data.items():
                    if isinstance(value, list) and value and isinstance(value[0], dict):
                        findings_to_process = value
                        break

        logger.info(
            f"Found findings to process: {len(findings_to_process) if findings_to_process else 0}"
        )

        # Add ignore status if user_id is provided and we have findings
        if user_id and findings_to_process:
            repo_name = f"{owner}/{repo}"
            logger.info(f"Adding ignore status for {len(findings_to_process)} findings")

            # Process findings with ignore status
            processed_findings = add_ignore_status_to_findings(
                user_id, repo_name, findings_to_process, None, "github"
            )

            # Add fix request status
            processed_findings = add_fix_status_to_findings(
                user_id, repo_name, processed_findings, None, "github", session
            )

            # Count ignored findings
            ignored_count = sum(
                1 for f in processed_findings if f.get("ignored", False)
            )
            logger.info(
                f"Processed findings: {len(processed_findings)}, ignored: {ignored_count}"
            )

            # Update the findings in the response
            if isinstance(reranked_data, dict):
                if "findings" in reranked_data:
                    reranked_data["findings"] = processed_findings
                elif "reranked_findings" in reranked_data:
                    reranked_data["reranked_findings"] = processed_findings
                elif "results" in reranked_data:
                    reranked_data["results"] = processed_findings
                else:
                    # Find the key we used for findings and update it
                    for key, value in reranked_data.items():
                        if (
                            isinstance(value, list)
                            and value
                            and isinstance(value[0], dict)
                        ):
                            reranked_data[key] = processed_findings
                            break
                    else:
                        # Fallback: add as 'findings' key
                        reranked_data["findings"] = processed_findings

                # Update metadata
                if "metadata" not in reranked_data:
                    reranked_data["metadata"] = {}
                reranked_data["metadata"]["ignore_support"] = True
                reranked_data["metadata"]["user_id"] = user_id

                # Calculate ignore statistics
                if processed_findings:
                    total_ignored = sum(
                        1 for f in processed_findings if f.get("ignored", False)
                    )
                    reranked_data["ignore_stats"] = {
                        "total_ignored": total_ignored,
                        "total_active": len(processed_findings) - total_ignored,
                        "ignore_percentage": (
                            round((total_ignored / len(processed_findings)) * 100, 1)
                            if processed_findings
                            else 0
                        ),
                    }
            else:
                # If it's still a list, return it as a dict
                reranked_data = {
                    "findings": processed_findings,
                    "metadata": {"ignore_support": True, "user_id": user_id},
                    "ignore_stats": {
                        "total_ignored": sum(
                            1 for f in processed_findings if f.get("ignored", False)
                        ),
                        "total_active": len(processed_findings)
                        - sum(1 for f in processed_findings if f.get("ignored", False)),
                        "ignore_percentage": (
                            round(
                                (
                                    sum(
                                        1
                                        for f in processed_findings
                                        if f.get("ignored", False)
                                    )
                                    / len(processed_findings)
                                )
                                * 100,
                                1,
                            )
                            if processed_findings
                            else 0
                        ),
                    },
                }

        logger.info(
            f"Final response structure: {list(reranked_data.keys()) if isinstance(reranked_data, dict) else type(reranked_data)}"
        )
        return jsonify(reranked_data)

    except Exception as e:
        logger.error(f"Error getting reranked findings: {str(e)}", exc_info=True)
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": "Internal server error",
                        "code": "INTERNAL_ERROR",
                    },
                }
            ),
            500,
        )
    finally:
        if session:
            session.close()
        if engine:
            engine.dispose()


# Add these imports to the top of your existing api.py
from models import db, AnalysisResult, IgnoredFinding
from ignore_utils import (
    add_ignore_status_to_findings,
    create_ignore_record,
    remove_ignore_record,
    get_user_ignores,
)


@api.route("/ignore-finding", methods=["POST"])
def ignore_finding():
    """
    Create ignore record for findings with workspace support

    Expected payload for different ignore types:

    1. Specific finding:
    {
        "user_id": "...",
        "workspace_id": "68c7530c1338b2befdcbc532",  // NEW: Optional workspace filter
        "repo_name": "owner/repo",
        "ignore_type": "finding",
        "finding_id": "rule.id",
        "file_path": "/path/to/file",
        "code_snippet": "vulnerable code",
        "reason": "explanation"
    }

    2. CWE in specific file:
    {
        "user_id": "...",
        "workspace_id": "68c7530c1338b2befdcbc532",  // NEW: Optional workspace filter
        "repo_name": "owner/repo",
        "ignore_type": "cwe_in_file",
        "cwe_id": "CWE-250",
        "file_path": "/path/to/file",
        "reason": "explanation"
    }

    // ... other ignore types follow same pattern
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Get required parameters

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        user_id = request_data.get("user_id")
        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")  # NEW: Optional workspace_id
        repo_name = request_data.get("repo_name")
        ignore_type = request_data.get("ignore_type")
        reason = request_data.get("reason", "")
        repo_type = request_data.get("repo_type", "")

        # Validate basic required fields
        if not all([user_id, repo_name, ignore_type, repo_type]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "user_id, repo_name, ignore_type and repo_type are required"
                        },
                    }
                ),
                400,
            )

        # NEW: Validate workspace_id format if provided
        if workspace_id:
            validation = validate_workspace_id(workspace_id)
            if not validation["valid"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": f"Invalid workspace_id: {validation['error']}"
                            },
                        }
                    ),
                    400,
                )

        # NEW: Validate that the repo belongs to the specified workspace
        if workspace_id:
            engine = create_api_engine()
            Session = sessionmaker(bind=engine)
            db_session = Session()

            try:
                # Check if repo exists in the specified workspace
                # apply filter to github by default
                # query github by default
                # Check if repo exists in the specified workspace
                repo_filter = None
                if repo_type == "github":
                    repo_filter = (
                        db_session.query(AnalysisResult)
                        .filter(
                            AnalysisResult.repository_name == repo_name,
                            AnalysisResult.workspace_id == workspace_id,
                        )
                        .order_by(desc(AnalysisResult.timestamp))
                    )
                elif repo_type == "azure-devops":
                    organization_name, project_name, repository_name = repo_name.split(
                        "/"
                    )
                    repo_filter = (
                        db_session.query(AzureDevOpsAnalysisResult)
                        .filter(
                            AzureDevOpsAnalysisResult.repository_name
                            == repository_name,
                            AzureDevOpsAnalysisResult.project_name == project_name,
                            AzureDevOpsAnalysisResult.organization_name
                            == organization_name,
                            AzureDevOpsAnalysisResult.workspace_id == workspace_id,
                        )
                        .order_by(desc(AzureDevOpsAnalysisResult.timestamp))
                    )
                elif repo_type == "gitlab":
                    repo_filter = (
                        db_session.query(GitLabAnalysisResult)
                        .filter(
                            GitLabAnalysisResult.repository_name == repo_name,
                            GitLabAnalysisResult.workspace == workspace_id,
                        )
                        .order_by(desc(GitLabAnalysisResult.timestamp))
                    )
                else:
                    region, repo = repo_name.split("/")
                    repo_identifier = get_repository_identifier(
                        repo_type, region=region, repo=repo
                    )
                    repo_filter = (
                        db_session.query(RepositoryScanResult)
                        .filter(
                            RepositoryScanResult.workspace_id == workspace_id,
                            RepositoryScanResult.repo_identifier == repo_identifier,
                        )
                        .order_by(desc(RepositoryScanResult.timestamp))
                    )

                repo_exists = repo_filter.first()

                if not repo_exists:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": {
                                    "message": f"Repository {repo_name} ({repo_type}) not found in workspace {workspace_id} for user {user_id}"
                                },
                            }
                        ),
                        404,
                    )
            finally:
                db_session.close()

        # Validate ignore_type
        valid_ignore_types = [
            "finding",
            "rule_in_file",
            "file",
            "rule_in_repo",
            "cwe_in_file",
            "cwe_in_repo",
        ]
        if ignore_type not in valid_ignore_types:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f'Invalid ignore_type. Must be one of: {", ".join(valid_ignore_types)}'
                        },
                    }
                ),
                400,
            )

        # Extract and validate type-specific fields
        finding_id = request_data.get("finding_id")
        file_path = request_data.get("file_path")
        code_snippet = request_data.get("code_snippet")
        cwe_id = request_data.get("cwe_id")

        # Normalize file path if provided
        if file_path:
            from ignore_utils import normalize_file_path

            file_path = normalize_file_path(file_path)

        # Validate CWE ID format if provided
        if cwe_id:
            # Ensure CWE ID is in correct format (CWE-XXX)
            if not cwe_id.startswith("CWE-"):
                # Try to extract CWE ID from full description like "CWE-250: Execution with..."
                if ":" in cwe_id:
                    cwe_id = cwe_id.split(":")[0].strip()

                # If still doesn't start with CWE-, reject it
                if not cwe_id.startswith("CWE-"):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": {
                                    "message": 'cwe_id must be in format "CWE-XXX" (e.g., "CWE-250")'
                                },
                            }
                        ),
                        400,
                    )

        # Validate required fields based on ignore type (same validation as before)
        # Validate required fields based on ignore type (same validation as ignore endpoint)
        validation_errors = []

        if ignore_type == "finding":
            if not all([finding_id, file_path, code_snippet]):
                validation_errors.append(
                    "finding_id, file_path, and code_snippet are required for finding ignore_type"
                )
        elif ignore_type == "rule_in_file":
            if not all([finding_id, file_path]):
                validation_errors.append(
                    "finding_id and file_path are required for rule_in_file ignore_type"
                )
        elif ignore_type == "file":
            if not file_path:
                validation_errors.append("file_path is required for file ignore_type")
        elif ignore_type == "rule_in_repo":
            if not finding_id:
                validation_errors.append(
                    "finding_id is required for rule_in_repo ignore_type"
                )
        elif ignore_type == "cwe_in_file":
            if not all([cwe_id, file_path]):
                validation_errors.append(
                    "cwe_id and file_path are required for cwe_in_file ignore_type"
                )
        elif ignore_type == "cwe_in_repo":
            # TEMPORARY: Allow deletion without cwe_id for cleanup
            if not cwe_id and not finding_id:
                validation_errors.append(
                    "Either cwe_id or finding_id is required for cwe_in_repo ignore_type cleanup"
                )

        # Log the request for debugging
        logger.info(
            f"Creating ignore record - Type: {ignore_type}, Workspace: {workspace_id}, CWE: {cwe_id}, File: {file_path}, Finding: {finding_id}"
        )

        # Prepare ignore data (enhanced with workspace context)
        ignore_data = {
            "ignore_type": ignore_type,
            "finding_id": finding_id,
            "file_path": file_path,
            "code_snippet": code_snippet,
            "cwe_id": cwe_id,
            "reason": reason,
            "workspace_context": workspace_id,  # NEW: Add workspace context for logging
        }

        # Create ignore record using the utility function
        result = create_ignore_record(
            user_id, repo_name, ignore_data, workspace_id, repo_type
        )

        if result["success"]:
            # NEW: Enhanced success response with workspace info
            success_response = {
                **result,
                "workspace_id": workspace_id,
                "workspace_validated": bool(workspace_id),
            }
            logger.info(
                f"Successfully created ignore record: {ignore_type} for {repo_name} in workspace {workspace_id}"
            )
            return jsonify(success_response), 201
        else:
            status_code = 409 if "already ignored" in result["message"] else 400
            logger.warning(f"Failed to create ignore record: {result['message']}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": result["message"],
                            "existing_reason": result.get("existing_reason"),
                            "workspace_id": workspace_id,
                        },
                    }
                ),
                status_code,
            )

    except Exception as e:
        logger.error(f"Error in ignore_finding endpoint: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@api.route("/ignore-finding", methods=["DELETE"])
def unignore_finding():
    """
    Remove ignore status from a finding/file/rule/CWE with workspace support

    Expected payload for different ignore types:

    1. Specific finding:
    {
        "user_id": "...",
        "workspace_id": "68c7530c1338b2befdcbc532",  // NEW: Optional workspace filter
        "repo_name": "owner/repo",
        "ignore_type": "finding",
        "finding_id": "rule.id",
        "file_path": "/path/to/file",
        "code_snippet": "vulnerable code"
    }

    2. CWE in specific file:
    {
        "user_id": "...",
        "workspace_id": "68c7530c1338b2befdcbc532",  // NEW: Optional workspace filter
        "repo_name": "owner/repo",
        "ignore_type": "cwe_in_file",
        "cwe_id": "CWE-269",
        "file_path": "/path/to/file"
    }

    // ... other ignore types follow same pattern
    """
    try:
        request_data = request.get_json()
        if not request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Get required parameters

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        user_id = request_data.get("user_id")
        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")  # NEW: Optional workspace_id
        repo_name = request_data.get("repo_name")
        ignore_type = request_data.get("ignore_type")
        repo_type = request_data.get("repo_type", "")

        print(
            f"request data: repo_type = {repo_type}, repo_name = {repo_name}, workspace_id = {workspace_id}\n\n\n\n\n"
        )

        # Validate basic required fields
        if not all([user_id, repo_name, ignore_type]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "user_id, repo_name, ignore_type and repo_type are required"
                        },
                    }
                ),
                400,
            )

        # NEW: Validate workspace_id format if provided
        if workspace_id:
            validation = validate_workspace_id(workspace_id)
            if not validation["valid"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": f"Invalid workspace_id: {validation['error']}"
                            },
                        }
                    ),
                    400,
                )

        # NEW: Validate that the repo belongs to the specified workspace
        if workspace_id:
            engine = create_api_engine()
            Session = sessionmaker(bind=engine)
            db_session = Session()

            try:
                # Check if repo exists in the specified workspace
                repo_filter = None
                if repo_type == "github":
                    repo_filter = (
                        db_session.query(AnalysisResult)
                        .filter(
                            AnalysisResult.repository_name == repo_name,
                            AnalysisResult.workspace_id == workspace_id,
                        )
                        .order_by(desc(AnalysisResult.timestamp))
                    )
                elif repo_type == "azure-devops":
                    organization_name, project_name, repository_name = repo_name.split(
                        "/"
                    )
                    repo_filter = (
                        db_session.query(AzureDevOpsAnalysisResult)
                        .filter(
                            AzureDevOpsAnalysisResult.repository_name
                            == repository_name,
                            AzureDevOpsAnalysisResult.project_name == project_name,
                            AzureDevOpsAnalysisResult.organization_name
                            == organization_name,
                            AzureDevOpsAnalysisResult.workspace_id == workspace_id,
                        )
                        .order_by(desc(AzureDevOpsAnalysisResult.timestamp))
                    )
                elif repo_type == "gitlab":
                    repo_filter = (
                        db_session.query(GitLabAnalysisResult)
                        .filter(
                            GitLabAnalysisResult.repository_name == repo_name,
                            GitLabAnalysisResult.workspace == workspace_id,
                        )
                        .order_by(desc(GitLabAnalysisResult.timestamp))
                    )
                else:
                    region, repo = repo_name.split("/")
                    repo_identifier = get_repository_identifier(
                        repo_type, region=region, repo=repo
                    )
                    repo_filter = (
                        db_session.query(RepositoryScanResult)
                        .filter(
                            RepositoryScanResult.workspace_id == workspace_id,
                            RepositoryScanResult.repo_identifier == repo_identifier,
                        )
                        .order_by(desc(RepositoryScanResult.timestamp))
                    )

                repo_exists = repo_filter.first()

                if not repo_exists:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": {
                                    "message": f"Repository {repo_name} ({repo_type}) not found in workspace {workspace_id} for user {user_id}"
                                },
                            }
                        ),
                        404,
                    )
            finally:
                db_session.close()

        # Validate ignore_type
        valid_ignore_types = [
            "finding",
            "rule_in_file",
            "file",
            "rule_in_repo",
            "cwe_in_file",
            "cwe_in_repo",
        ]
        if ignore_type not in valid_ignore_types:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f'Invalid ignore_type. Must be one of: {", ".join(valid_ignore_types)}'
                        },
                    }
                ),
                400,
            )

        # Extract and validate type-specific fields
        finding_id = request_data.get("finding_id")
        file_path = request_data.get("file_path")
        code_snippet = request_data.get("code_snippet")
        cwe_id = request_data.get("cwe_id")

        # Normalize file path if provided
        if file_path:
            from ignore_utils import normalize_file_path

            file_path = normalize_file_path(file_path)

        # Validate and normalize CWE ID if provided
        if cwe_id:
            # Ensure CWE ID is in correct format (CWE-XXX)
            if not cwe_id.startswith("CWE-"):
                # Try to extract CWE ID from full description like "CWE-269: Execution with..."
                if ":" in cwe_id:
                    cwe_id = cwe_id.split(":")[0].strip()

                # If still doesn't start with CWE-, reject it
                if not cwe_id.startswith("CWE-"):
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": {
                                    "message": 'cwe_id must be in format "CWE-XXX" (e.g., "CWE-269")'
                                },
                            }
                        ),
                        400,
                    )

        # FIXED: Validate required fields based on ignore type with proper cleanup support
        validation_errors = []

        if ignore_type == "finding":
            if not all([finding_id, file_path, code_snippet]):
                validation_errors.append(
                    "finding_id, file_path, and code_snippet are required for finding ignore_type"
                )
        elif ignore_type == "rule_in_file":
            if not all([finding_id, file_path]):
                validation_errors.append(
                    "finding_id and file_path are required for rule_in_file ignore_type"
                )
        elif ignore_type == "file":
            if not file_path:
                validation_errors.append("file_path is required for file ignore_type")
        elif ignore_type == "rule_in_repo":
            if not finding_id:
                validation_errors.append(
                    "finding_id is required for rule_in_repo ignore_type"
                )
        elif ignore_type == "cwe_in_file":
            # FIXED: Allow either valid cwe_id structure OR malformed finding_id for cleanup
            if not ((cwe_id and file_path) or (finding_id and file_path)):
                validation_errors.append(
                    "Either (cwe_id and file_path) or (finding_id and file_path) are required for cwe_in_file ignore_type cleanup"
                )
        elif ignore_type == "cwe_in_repo":
            # FIXED: Allow either valid cwe_id OR malformed finding_id for cleanup
            if not (cwe_id or finding_id):
                validation_errors.append(
                    "Either cwe_id or finding_id is required for cwe_in_repo ignore_type cleanup"
                )

        if validation_errors:
            return (
                jsonify({"success": False, "error": {"message": validation_errors[0]}}),
                400,
            )

        # Log the unignore request for debugging
        logger.info(
            f"Removing ignore record - Type: {ignore_type}, Workspace: {workspace_id}, "
            f"CWE: {cwe_id}, Finding: {finding_id}, File: {file_path}"
        )

        # Prepare ignore data for removal (enhanced with workspace context)
        ignore_data = {
            "ignore_type": ignore_type,
            "finding_id": finding_id,
            "file_path": file_path,
            "code_snippet": code_snippet,
            "cwe_id": cwe_id,
            "workspace_context": workspace_id,  # NEW: Add workspace context for logging
        }

        # Remove ignore record using the utility function
        result = remove_ignore_record(
            user_id, repo_name, ignore_data, workspace_id, repo_type
        )

        if result["success"]:
            # NEW: Enhanced success response with workspace info
            success_response = {
                "success": True,
                "message": result["message"],
                "workspace_id": workspace_id,
                "workspace_validated": bool(workspace_id),
                "deleted_record_id": result.get("deleted_record_id"),
            }
            logger.info(
                f"Successfully removed ignore record: {ignore_type} for {repo_name} in workspace {workspace_id}"
            )
            return jsonify(success_response), 200
        else:
            logger.warning(f"Failed to remove ignore record: {result['message']}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": result["message"],
                            "workspace_id": workspace_id,
                        },
                    }
                ),
                404,
            )

    except Exception as e:
        logger.error(f"Error in unignore_finding endpoint: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@api.route("/ignores/<user_id>", methods=["GET"])
def get_user_ignore_list(user_id: str):
    """
    Get all ignore records for a user with workspace filtering and enhanced metadata extraction

    Query parameters:
    - repo_name: Optional repository filter
    - workspace_id: Optional workspace filter (NEW)
    """
    engine = None
    db_session = None
    try:
        repo_name = request.args.get("repo_name")
        workspace_id = request.args.get("workspace_id")  # NEW: Add workspace_id filter
        repo_type = request.args.get("repo_type")

        # NEW: Validate workspace_id format if provided
        if workspace_id:
            validation = validate_workspace_id(workspace_id)
            if not validation["valid"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": f"Invalid workspace_id: {validation['error']}"
                            },
                        }
                    ),
                    400,
                )

        # Use the updated get_user_ignores function with workspace and repo_type filtering
        ignore_records_dict = get_user_ignores(
            user_id, repo_name, workspace_id, repo_type
        )

        # Create database session for metadata extraction
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Convert to dictionaries and enhance with metadata
        enhanced_ignores = []

        # Get analysis data for metadata extraction (group by repo for efficiency)
        repo_analyses = {}

        # Import the new function
        from ignore_utils import calculate_affected_findings_for_ignore

        # Track totals for summary
        total_ignore_rules = len(ignore_records_dict)
        total_ignored_findings = 0
        breakdown_by_type = {}

        for record in ignore_records_dict:
            record_repo = record["repo_name"]

            # Get analysis data for this repo if we haven't already
            if record_repo not in repo_analyses:
                try:
                    # Build query for latest analysis of this repo
                    analysis_query = db_session.query(AnalysisResult).filter_by(
                        repository_name=record_repo
                    )

                    # Apply workspace filtering to analysis lookup if specified
                    if workspace_id:
                        analysis_query = analysis_query.filter_by(
                            workspace_id=workspace_id
                        )

                    analysis = analysis_query.order_by(
                        desc(AnalysisResult.timestamp)
                    ).first()

                    repo_analyses[record_repo] = (
                        analysis.results.get("findings", [])
                        if (analysis and analysis.results)
                        else []
                    )
                except Exception as e:
                    logger.warning(
                        f"Could not get analysis for repo {record_repo}: {str(e)}"
                    )
                    repo_analyses[record_repo] = []

            # Extract metadata for this ignore record (same logic as before)
            severity = None
            cwe = []
            owasp = []
            category = None
            message = None

            findings = repo_analyses[record_repo]

            # Calculate affected findings count
            affected_findings_info = calculate_affected_findings_for_ignore(
                record, findings
            )
            affected_count = affected_findings_info["count"]
            affected_ids = affected_findings_info["finding_ids"]

            # Update totals
            total_ignored_findings += affected_count
            ignore_type = record["ignore_type"]
            if ignore_type not in breakdown_by_type:
                breakdown_by_type[ignore_type] = {"rules": 0, "findings": 0}
            breakdown_by_type[ignore_type]["rules"] += 1
            breakdown_by_type[ignore_type]["findings"] += affected_count

            if findings:
                # Find matching finding for metadata extraction
                normalized_record_path = (
                    normalize_file_path(record["file_path"])
                    if record["file_path"]
                    else None
                )

                for finding in findings:
                    finding_file = normalize_file_path(finding.get("file", ""))

                    # Match based on ignore type
                    match_found = False

                    if record["ignore_type"] == "finding":
                        # Exact match: rule + file + code snippet
                        if (
                            finding.get("id") == record["finding_id"]
                            and finding_file == normalized_record_path
                            and finding.get("code_snippet", "")
                            == record["code_snippet"]
                        ):
                            match_found = True
                    elif record["ignore_type"] == "rule_in_file":
                        # Rule in specific file
                        if (
                            finding.get("id") == record["finding_id"]
                            and finding_file == normalized_record_path
                        ):
                            match_found = True
                    elif record["ignore_type"] == "file":
                        # Any finding in this file
                        if finding_file == normalized_record_path:
                            match_found = True
                    elif record["ignore_type"] == "rule_in_repo":
                        # This rule anywhere in repo
                        if finding.get("id") == record["finding_id"]:
                            match_found = True
                    elif record["ignore_type"] == "cwe_in_file":
                        # CWE in specific file
                        finding_cwes = finding.get("cwe", [])
                        cwe_id = record.get("cwe_id")
                        if (
                            cwe_id
                            and cwe_id in finding_cwes
                            and finding_file == normalized_record_path
                        ):
                            match_found = True
                    elif record["ignore_type"] == "cwe_in_repo":
                        # CWE anywhere in repo
                        finding_cwes = finding.get("cwe", [])
                        cwe_id = record.get("cwe_id")
                        if cwe_id and cwe_id in finding_cwes:
                            match_found = True

                    if match_found:
                        severity = finding.get("severity", "").upper()
                        cwe = finding.get("cwe", [])
                        owasp = finding.get("owasp", [])
                        category = finding.get("category", "")
                        message = finding.get("message", "")
                        break

            # Build enhanced ignore record
            enhanced_ignore = {
                "id": record["id"],
                "user_id": record["user_id"],
                "repo_name": record["repo_name"],
                "ignore_type": record["ignore_type"],
                "finding_id": record["finding_id"],
                "file_path": record["file_path"],
                "code_snippet": record["code_snippet"],
                "cwe_id": record.get("cwe_id", ""),  # Include cwe_id from database
                "reason": record["reason"],
                "ignored_at": record[
                    "ignored_at"
                ],  # Already in ISO format from get_user_ignores
                "ignored_by": record["ignored_by"],
                # Enhanced metadata
                "severity": severity,
                "cwe": record.get("cwe_id", []),
                "owasp": owasp if owasp else [],
                "category": category,
                "message": message,
                # NEW: Affected findings information
                "affected_findings_count": affected_count,
                "affected_finding_ids": affected_ids,
            }

            enhanced_ignores.append(enhanced_ignore)

        # NEW: Get workspace information for response metadata
        workspace_info = {}
        if workspace_id:
            try:
                # Get workspace statistics
                workspace_repo_count = (
                    db_session.query(AnalysisResult.repository_name)
                    .filter(
                        AnalysisResult.user_id == user_id,
                        AnalysisResult.workspace_id == workspace_id,
                    )
                    .distinct()
                    .count()
                )

                workspace_info = {
                    "workspace_id": workspace_id,
                    "total_repositories_in_workspace": workspace_repo_count,
                    "workspace_filtering_applied": True,
                }
            except Exception as e:
                logger.warning(f"Could not get workspace statistics: {str(e)}")
                workspace_info = {
                    "workspace_id": workspace_id,
                    "workspace_filtering_applied": True,
                }

        return (
            jsonify(
                {
                    "success": True,
                    "data": {
                        "user_id": user_id,
                        "repo_name": repo_name,
                        "workspace_info": workspace_info,  # NEW: Include workspace information
                        "ignores": enhanced_ignores,
                        "total_count": len(enhanced_ignores),  # Total ignore rules
                        "total_ignore_rules": total_ignore_rules,  # Explicit count of rules
                        "total_ignored_findings": total_ignored_findings,  # Actual findings affected
                        "breakdown": breakdown_by_type,  # Breakdown by ignore type
                        "metadata_support": True,
                        "workspace_support": True,  # NEW: Indicate workspace support
                    },
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error getting enhanced user ignores: {str(e)}")
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/debug/rerank-structure/<owner>/<repo>", methods=["GET"])
def debug_rerank_structure(owner: str, repo: str):
    """Debug endpoint to see reranked data structure"""
    engine = None
    session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        result = (
            session.query(AnalysisResult)
            .filter_by(repository_name=f"{owner}/{repo}")
            .order_by(desc(AnalysisResult.timestamp))
            .first()
        )

        if not result or not result.rerank:
            return jsonify({"error": "No reranked data found"})

        rerank_data = result.rerank

        return jsonify(
            {
                "rerank_type": str(type(rerank_data)),
                "rerank_keys": (
                    list(rerank_data.keys())
                    if isinstance(rerank_data, dict)
                    else "not_dict"
                ),
                "is_list": isinstance(rerank_data, list),
                "sample_structure": (
                    rerank_data
                    if isinstance(rerank_data, list) and len(rerank_data) < 2
                    else (
                        {k: type(v).__name__ for k, v in rerank_data.items()}
                        if isinstance(rerank_data, dict)
                        else str(rerank_data)[:200]
                    )
                ),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        if session:
            session.close()
        if engine:
            engine.dispose()


# Add this to your api.py file


@api.route("/admin/backfill-workspaces", methods=["POST"])
def trigger_workspace_backfill():
    """
    Administrative endpoint to backfill workspace_id for existing analysis_results records
    Uses DASHBOARD_URL environment variable to fetch customer data

    Expected payload:
    {
        "admin_key": "your-admin-key"  // Optional: for security
    }
    """
    try:
        request_data = request.get_json() or {}
        admin_key = request_data.get("admin_key")

        # Check if DASHBOARD_URL is configured
        dashboard_url = os.getenv("DASHBOARD_URL")
        if not dashboard_url:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "DASHBOARD_URL environment variable is not configured"
                        },
                    }
                ),
                500,
            )

        # Optional: Check admin key for security
        expected_admin_key = os.getenv("ADMIN_BACKFILL_KEY")
        if expected_admin_key and admin_key != expected_admin_key:
            return (
                jsonify({"success": False, "error": {"message": "Invalid admin key"}}),
                403,
            )

        logger.info(f"Starting workspace backfill using DASHBOARD_URL: {dashboard_url}")

        # Import the backfill function
        from create_tables import backfill_workspace_ids

        # Run the backfill process
        import asyncio

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            success = loop.run_until_complete(backfill_workspace_ids())
        finally:
            loop.close()

        if success:
            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Workspace backfill completed successfully",
                        "dashboard_url": dashboard_url,
                        "timestamp": datetime.now().isoformat(),
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": "Workspace backfill failed"},
                        "timestamp": datetime.now().isoformat(),
                    }
                ),
                500,
            )

    except Exception as e:
        logger.error(f"Error in workspace backfill endpoint: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {"message": "Internal server error"},
                    "details": str(e),
                    "timestamp": datetime.now().isoformat(),
                }
            ),
            500,
        )


@api.route("/admin/workspace-status", methods=["GET"])
def check_workspace_status():
    """
    Check the current status of workspace_id population
    """
    engine = None
    db_session = None
    try:
        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Check if workspace_id column exists
        column_exists = db_session.execute(
            text(
                """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='workspace_id'
        """
            )
        ).scalar()

        if not column_exists:
            return jsonify(
                {
                    "success": True,
                    "data": {
                        "workspace_column_exists": False,
                        "message": "workspace_id column has not been added yet",
                    },
                }
            )

        # Get statistics about workspace_id population
        stats = db_session.execute(
            text(
                """
            SELECT 
                COUNT(*) as total_records,
                COUNT(workspace_id) as records_with_workspace,
                COUNT(*) - COUNT(workspace_id) as records_without_workspace,
                COUNT(DISTINCT user_id) as unique_users,
                COUNT(DISTINCT workspace_id) as unique_workspaces
            FROM analysis_results
        """
            )
        ).fetchone()

        # Get sample of records without workspace_id
        sample_records = db_session.execute(
            text(
                """
            SELECT id, user_id, repository_name, timestamp
            FROM analysis_results 
            WHERE workspace_id IS NULL 
            ORDER BY timestamp DESC 
            LIMIT 5
        """
            )
        ).fetchall()

        # Get sample of records with workspace_id
        sample_records_with_workspace = db_session.execute(
            text(
                """
            SELECT id, user_id, repository_name, workspace_id, timestamp
            FROM analysis_results 
            WHERE workspace_id IS NOT NULL 
            ORDER BY timestamp DESC 
            LIMIT 3
        """
            )
        ).fetchall()

        return jsonify(
            {
                "success": True,
                "data": {
                    "workspace_column_exists": True,
                    "dashboard_url_configured": bool(os.getenv("DASHBOARD_URL")),
                    "statistics": {
                        "total_records": stats.total_records,
                        "records_with_workspace": stats.records_with_workspace,
                        "records_without_workspace": stats.records_without_workspace,
                        "unique_users": stats.unique_users,
                        "unique_workspaces": stats.unique_workspaces,
                        "completion_percentage": round(
                            (
                                (
                                    stats.records_with_workspace
                                    / stats.total_records
                                    * 100
                                )
                                if stats.total_records > 0
                                else 0
                            ),
                            2,
                        ),
                    },
                    "sample_records_without_workspace": [
                        {
                            "id": record.id,
                            "user_id": record.user_id,
                            "repository_name": record.repository_name,
                            "timestamp": record.timestamp.isoformat(),
                        }
                        for record in sample_records
                    ],
                    "sample_records_with_workspace": [
                        {
                            "id": record.id,
                            "user_id": record.user_id,
                            "repository_name": record.repository_name,
                            "workspace_id": str(record.workspace_id),
                            "timestamp": record.timestamp.isoformat(),
                        }
                        for record in sample_records_with_workspace
                    ],
                    "needs_backfill": stats.records_without_workspace > 0,
                },
            }
        )

    except Exception as e:
        logger.error(f"Error checking workspace status: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {"message": "Internal server error"},
                    "details": str(e),
                }
            ),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/get-branches", methods=["POST"])
def get_repository_branches():
    """Get all branches for a repository"""

    async def get_branches_async():
        # Get data from POST request body
        request_data = request.get_json()
        if not request_data:
            return (
                {"success": False, "error": {"message": "Request body is required"}},
                400,
            )

        # Get required parameters from request body

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        repo_owner = request_data.get("repo_owner")
        repo_owner = request_data.get("repo_owner")
        repo_name = request_data.get("repo_name")
        token = request_data.get("token")

        # Validate required parameters
        required_params = {
            "repoOwner": repo_owner,
            "repoName": repo_name,
            "token": token,
        }

        missing_params = [
            param for param, value in required_params.items() if not value
        ]
        if missing_params:
            return (
                {
                    "success": False,
                    "error": {
                        "message": f'Missing required parameters: {", ".join(missing_params)}'
                    },
                },
                400,
            )

        # GitHub API base URL
        api_base = "https://api.github.com"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            async with create_secure_client_session(timeout=30) as session:
                # Get repository to find default branch
                repo_url = f"{api_base}/repos/{repo_owner}/{repo_name}"
                async with session.get(repo_url, headers=headers) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        try:
                            error_json = json.loads(error_text)
                            error_message = error_json.get("message", "Unknown error")
                        except:
                            error_message = error_text
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to access repository: {error_message}"
                                },
                            },
                            response.status,
                        )

                    repo_data = await response.json()
                    default_branch = repo_data.get("default_branch", "main")

                # Get all branches
                branches_url = f"{api_base}/repos/{repo_owner}/{repo_name}/branches"
                async with session.get(branches_url, headers=headers) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        try:
                            error_json = json.loads(error_text)
                            error_message = error_json.get("message", "Unknown error")
                        except:
                            error_message = error_text
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to fetch branches: {error_message}"
                                },
                            },
                            response.status,
                        )

                    branches_data = await response.json()

                    # Check if 'rezliant' branch exists, if not create it from default branch
                    branch_names = [branch["name"] for branch in branches_data]
                    if "rezliant" not in branch_names:
                        logger.info(
                            f"'rezliant' branch not found, creating it from {default_branch}"
                        )

                        # Get the SHA of the default branch
                        default_branch_url = f"{api_base}/repos/{repo_owner}/{repo_name}/git/ref/heads/{default_branch}"
                        async with session.get(
                            default_branch_url, headers=headers
                        ) as ref_response:
                            if ref_response.status == 200:
                                ref_data = await ref_response.json()
                                default_branch_sha = ref_data["object"]["sha"]

                                # Create the rezliant branch
                                create_ref_url = f"{api_base}/repos/{repo_owner}/{repo_name}/git/refs"
                                create_ref_payload = {
                                    "ref": "refs/heads/rezliant",
                                    "sha": default_branch_sha,
                                }
                                async with session.post(
                                    create_ref_url,
                                    headers=headers,
                                    json=create_ref_payload,
                                ) as create_response:
                                    if create_response.status == 201:
                                        logger.info(
                                            f"Successfully created 'rezliant' branch"
                                        )
                                        # Add the new branch to branches_data
                                        branches_data.append({"name": "rezliant"})
                                    else:
                                        error_text = await create_response.text()
                                        logger.warning(
                                            f"Failed to create 'rezliant' branch: {error_text}"
                                        )
                            else:
                                logger.warning(
                                    f"Failed to get default branch SHA: {ref_response.status}"
                                )

                    # Sort branches with priority: default, rezliant, develop/dev, staging/stg, production/prod, then rest
                    def get_branch_priority(branch_name, default_branch):
                        name_lower = branch_name.lower()
                        if branch_name == default_branch:
                            return 0
                        elif name_lower == "rezliant":
                            return 1
                        elif name_lower in ["develop", "dev"]:
                            return 2
                        elif name_lower in ["staging", "stg"]:
                            return 3
                        elif name_lower in ["production", "prod"]:
                            return 4
                        else:
                            return 5

                    branches = [
                        {
                            "name": branch["name"],
                            "isDefault": branch["name"] == default_branch,
                        }
                        for branch in branches_data
                    ]

                    # Sort branches by priority
                    branches.sort(
                        key=lambda b: (
                            get_branch_priority(b["name"], default_branch),
                            b["name"],
                        )
                    )

                    logger.info(
                        f"Retrieved {len(branches)} branches for {repo_owner}/{repo_name}"
                    )

                    return (
                        {
                            "success": True,
                            "data": {
                                "branches": branches,
                                "defaultBranch": default_branch,
                            },
                        },
                        200,
                    )

        except aiohttp.ClientError as e:
            logger.error(f"HTTP request error: {str(e)}")
            return (
                {
                    "success": False,
                    "error": {"message": f"HTTP request failed: {str(e)}"},
                },
                500,
            )
        except Exception as e:
            logger.error(f"Error fetching branches: {str(e)}")
            return (
                {
                    "success": False,
                    "error": {"message": f"Internal server error: {str(e)}"},
                },
                500,
            )

    # Run the async function and return the result
    try:
        result, status_code = asyncio.run(get_branches_async())
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error running async get branches: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {"message": f"Internal server error: {str(e)}"},
                }
            ),
            500,
        )


@api.route("/create-pr", methods=["POST"])
def create_pull_request():
    """Create a pull request with the fixed file content using async GitHub API calls"""

    async def ensure_webhook_exists(session, api_base, headers, repo_owner, repo_name):
        """
        Checks if a webhook exists for the pull_request event and creates one if it doesn't.
        Returns a tuple of (webhook_enabled: bool, webhook_url: str or None, error_message: str or None)
        """
        try:
            # Get webhook base URL from environment variable
            webhook_base_url = os.getenv("WEBHOOK_BASE_URL")
            if not webhook_base_url:
                logger.info(
                    "WEBHOOK_BASE_URL environment variable not set, skipping webhook creation"
                )
                return (False, None, "WEBHOOK_BASE_URL not configured")

            webhook_url = f"{webhook_base_url}/api/v1/pr/webhook"

            # Get webhook secret for signature verification
            webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
            if not webhook_secret:
                logger.info(
                    "GITHUB_WEBHOOK_SECRET not set, skipping webhook creation for security"
                )
                return (False, None, "GITHUB_WEBHOOK_SECRET not configured")

            # Get all webhooks for the repository
            list_webhooks_url = f"{api_base}/repos/{repo_owner}/{repo_name}/hooks"
            async with session.get(list_webhooks_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.warning(
                        f"Failed to list webhooks (status {response.status}): {error_text}"
                    )
                    return (
                        False,
                        None,
                        f"Failed to list webhooks: HTTP {response.status}",
                    )

                hooks = await response.json()

            # Check if a webhook already exists for this URL AND is configured for pull_request events
            # We need to verify both the URL matches and the events include pull_request
            existing_hook = None
            for hook in hooks:
                hook_url = hook.get("config", {}).get("url")
                hook_events = hook.get("events", [])

                # Webhook must match URL and have pull_request events enabled
                if hook_url == webhook_url and "pull_request" in hook_events:
                    existing_hook = hook
                    break

            if existing_hook:
                logger.info(
                    f"Webhook already exists for {webhook_url} with pull_request events for repository {repo_owner}/{repo_name}"
                )
                return (True, webhook_url, None)

            # Create a new webhook with signature verification
            logger.info(f"Creating webhook for {webhook_url}")
            webhook_config = {
                "url": webhook_url,
                "content_type": "json",
                "insecure_ssl": "0",
            }

            # Add secret for signature verification if available
            if webhook_secret:
                webhook_config["secret"] = webhook_secret
                logger.info("Webhook will be created with signature verification")

            create_webhook_payload = {
                "config": webhook_config,
                "events": ["pull_request"],
                "active": True,
            }

            async with session.post(
                list_webhooks_url, headers=headers, json=create_webhook_payload
            ) as response:
                if response.status not in [200, 201]:
                    error_text = await response.text()
                    logger.warning(
                        f"Failed to create webhook (status {response.status}): {error_text}"
                    )
                    return (
                        False,
                        None,
                        f"Failed to create webhook: HTTP {response.status}",
                    )

                new_hook = await response.json()
                logger.info(
                    f"Webhook created successfully with ID: {new_hook.get('id')}"
                )
                return (True, webhook_url, None)

        except Exception as e:
            logger.warning(f"Error ensuring webhook exists: {str(e)}", exc_info=True)
            return (False, None, f"Exception: {str(e)}")

    async def create_pr_async():
        # Get data from POST request body
        request_data = request.get_json()
        if not request_data:
            return (
                {"success": False, "error": {"message": "Request body is required"}},
                400,
            )

        # Get required parameters from request body

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        repo_owner = request_data.get("repo_owner")
        repo_owner = request_data.get("repo_owner")
        repo_name = request_data.get("repo_name")
        base_branch = request_data.get("base_branch")
        temp_file_path = request_data.get("file_path")
        file_path = extract_clean_file_path(temp_file_path)
        token = request_data.get("token")
        file_content = request_data.get("file_content")

        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")
        finding_id = request_data.get(
            "finding_id"
        )  # Should be in format: id-filepath-linestart
        line_number = request_data.get("line_number")
        cwe_id = request_data.get("cwe_id")
        severity = request_data.get("severity")

        # Optional parameters with defaults
        # Generate unique branch name with timestamp to avoid conflicts
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        # Sanitize file path for use in branch name - replace invalid characters
        # Git ref names cannot contain spaces, ~, ^, :, ?, *, [, \, and other special chars
        sanitized_path = file_path.replace("/", "-").replace(" ", "-").replace("~", "-")
        sanitized_path = (
            sanitized_path.replace("^", "-").replace(":", "-").replace("?", "-")
        )
        sanitized_path = (
            sanitized_path.replace("*", "-").replace("[", "-").replace("\\", "-")
        )
        sanitized_path = sanitized_path.replace("..", "-").replace("@{", "-")
        # Remove any consecutive dashes and strip leading/trailing dashes
        sanitized_path = "-".join(filter(None, sanitized_path.split("-")))
        default_branch_name = f"rezliant-fix/{sanitized_path}-{timestamp}"
        new_branch = request_data.get("new_branch", default_branch_name)
        # Ensure branch name doesn't start with refs/heads (will be added in API call)
        if new_branch.startswith("refs/heads/"):
            new_branch = new_branch[11:]  # Remove 'refs/heads/' prefix
        commit_message = request_data.get(
            "commit_message", f"Fix vulnerability in {file_path}"
        )
        pr_title = request_data.get(
            "pr_title", f"Fix: Security vulnerability in {file_path}"
        )
        pr_body = request_data.get(
            "pr_body", f"This PR fixes a security vulnerability in {file_path}"
        )

        # Validate required parameters
        required_params = {
            "repoOwner": repo_owner,
            "repoName": repo_name,
            "filePath": file_path,
            "token": token,
            "fileContent": file_content,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "finding_id": finding_id,
            "line_number": line_number,
        }

        missing_params = [
            param for param, value in required_params.items() if not value
        ]
        if missing_params:
            return (
                {
                    "success": False,
                    "error": {
                        "message": f'Missing required parameters: {", ".join(missing_params)}'
                    },
                },
                400,
            )

        # GitHub API base URL
        api_base = "https://api.github.com"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        try:
            async with create_secure_client_session(timeout=60) as session:
                # Step 1: Get repository default branch if base_branch not provided or verify it exists
                repo_url = f"{api_base}/repos/{repo_owner}/{repo_name}"
                async with session.get(repo_url, headers=headers) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        try:
                            error_json = json.loads(error_text)
                            error_message = error_json.get("message", "Unknown error")
                        except:
                            error_message = error_text
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to access repository: {error_message}"
                                },
                            },
                            response.status,
                        )

                    repo_data = await response.json()
                    default_branch = repo_data.get("default_branch", "main")

                # If base_branch is provided, verify it exists; otherwise use default
                if base_branch:
                    branch_check_url = f"{api_base}/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}"
                    async with session.get(
                        branch_check_url, headers=headers
                    ) as response:
                        if response.status == 404:
                            logger.warning(
                                f"Base branch '{base_branch}' not found, using default branch '{default_branch}'"
                            )
                            base_branch = default_branch
                        elif response.status != 200:
                            error_text = await response.text()
                            try:
                                error_json = json.loads(error_text)
                                error_message = error_json.get(
                                    "message", "Unknown error"
                                )
                            except:
                                error_message = error_text
                            return (
                                {
                                    "success": False,
                                    "error": {
                                        "message": f"Failed to verify base branch: {error_message}"
                                    },
                                },
                                response.status,
                            )
                else:
                    base_branch = default_branch

                logger.info(f"Using base branch: {base_branch}")

                # Step 2: Get the reference to the base branch
                ref_url = f"{api_base}/repos/{repo_owner}/{repo_name}/git/ref/heads/{base_branch}"
                async with session.get(ref_url, headers=headers) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        try:
                            error_json = json.loads(error_text)
                            error_message = error_json.get("message", "Unknown error")
                        except:
                            error_message = error_text
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to get base branch reference: {error_message}"
                                },
                            },
                            response.status,
                        )

                    ref_data = await response.json()
                    base_sha = ref_data["object"]["sha"]
                    logger.info(f"Base branch SHA: {base_sha}")

                # Step 3: Create a new branch from the base branch
                create_ref_url = f"{api_base}/repos/{repo_owner}/{repo_name}/git/refs"
                create_ref_payload = {
                    "ref": f"refs/heads/{new_branch}",
                    "sha": base_sha,
                }

                logger.info(f"Creating branch '{new_branch}' from SHA {base_sha}")
                logger.info(f"Branch creation URL: {create_ref_url}")
                logger.info(f"Branch creation payload: {create_ref_payload}")

                async with session.post(
                    create_ref_url, headers=headers, json=create_ref_payload
                ) as response:
                    response_text = await response.text()
                    logger.info(f"Branch creation response status: {response.status}")
                    logger.info(f"Branch creation response body: {response_text}")

                    if response.status not in [
                        201,
                        422,
                    ]:  # 422 means branch already exists
                        try:
                            error_json = json.loads(response_text)
                            error_message = error_json.get("message", "Unknown error")
                            error_details = error_json.get("errors", [])
                            logger.error(
                                f"Failed to create branch. Message: {error_message}, Details: {error_details}"
                            )
                        except:
                            error_message = response_text
                            logger.error(
                                f"Failed to create branch. Raw response: {response_text}"
                            )
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to create new branch: {error_message}"
                                },
                            },
                            response.status,
                        )

                    if response.status == 422:
                        try:
                            error_json = json.loads(response_text)
                            error_message = error_json.get(
                                "message", "Branch already exists"
                            )
                            error_details = error_json.get("errors", [])
                            logger.warning(
                                f"Branch creation returned 422. Message: {error_message}, Details: {error_details}"
                            )
                        except:
                            logger.warning(
                                f"Branch creation returned 422. Raw response: {response_text}"
                            )
                        logger.warning(
                            f"Branch '{new_branch}' already exists, will update it"
                        )
                    else:
                        logger.info(f"Created new branch: {new_branch}")

                # Step 4: Check if file exists to get its SHA (required for updates)
                file_sha = None
                get_file_url = (
                    f"{api_base}/repos/{repo_owner}/{repo_name}/contents/{file_path}"
                )
                async with session.get(
                    f"{get_file_url}?ref={new_branch}", headers=headers
                ) as response:
                    if response.status == 200:
                        file_data = await response.json()
                        if isinstance(file_data, dict) and "sha" in file_data:
                            file_sha = file_data["sha"]
                            logger.info(f"File exists with SHA: {file_sha}")
                    elif response.status != 404:
                        logger.warning(
                            f"Unexpected response when checking file: {response.status}"
                        )

                # Step 5: Create or update the file
                encoded_content = base64.b64encode(file_content.encode("utf-8")).decode(
                    "utf-8"
                )
                update_file_payload = {
                    "message": commit_message,
                    "content": encoded_content,
                    "branch": new_branch,
                }

                if file_sha:
                    update_file_payload["sha"] = file_sha

                async with session.put(
                    get_file_url, headers=headers, json=update_file_payload
                ) as response:
                    if response.status not in [200, 201]:
                        error_text = await response.text()
                        try:
                            error_json = json.loads(error_text)
                            error_message = error_json.get("message", "Unknown error")
                        except:
                            error_message = error_text
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to update file: {error_message}"
                                },
                            },
                            response.status,
                        )

                    logger.info(f"File updated successfully in branch {new_branch}")

                # Step 6: Create a pull request
                create_pr_url = f"{api_base}/repos/{repo_owner}/{repo_name}/pulls"
                create_pr_payload = {
                    "title": pr_title,
                    "body": pr_body,
                    "head": new_branch,
                    "base": base_branch,
                }

                async with session.post(
                    create_pr_url, headers=headers, json=create_pr_payload
                ) as response:
                    if response.status != 201:
                        error_text = await response.text()
                        try:
                            error_json = json.loads(error_text)
                            error_message = error_json.get("message", "Unknown error")
                        except:
                            error_message = error_text
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Failed to create pull request: {error_message}"
                                },
                            },
                            response.status,
                        )

                    pr_data = await response.json()
                    logger.info(f"Pull request created: {pr_data['html_url']}")

                    pr_url = pr_data["html_url"]
                    pr_number = str(pr_data["number"])
                    pr_title_actual = pr_data["title"]

                    # Step 7: Attempt to create webhook for PR updates (non-blocking)
                    webhook_enabled = False
                    webhook_url = None
                    webhook_error = None

                    try:
                        webhook_enabled, webhook_url, webhook_error = (
                            await ensure_webhook_exists(
                                session, api_base, headers, repo_owner, repo_name
                            )
                        )
                        if not webhook_enabled:
                            logger.warning(
                                f"Webhook creation skipped or failed: {webhook_error}. "
                                "PR will not have live updates."
                            )
                    except Exception as webhook_exc:
                        logger.warning(
                            f"Exception while creating webhook: {str(webhook_exc)}. "
                            "PR will not have live updates.",
                            exc_info=True,
                        )
                        webhook_error = f"Exception: {str(webhook_exc)}"

                    # Create fix request record if tracking parameters were provided
                    if user_id and finding_id and workspace_id:
                        try:
                            # Create database session for fix request
                            fix_engine = create_api_engine()
                            FixSession = sessionmaker(bind=fix_engine)
                            fix_session = FixSession()

                            try:
                                # Build repo identifier (GitHub format)
                                repo_identifier = (
                                    f"https://github.com/{repo_owner}/{repo_name}"
                                )

                                # Create fix request with separate fields
                                fix_request = FixRequest(
                                    user_id=user_id,
                                    workspace_id=workspace_id,
                                    repo_type="github",
                                    repo_identifier=repo_identifier,
                                    branch_name=base_branch or "main",
                                    finding_id=finding_id,
                                    file_path=file_path,
                                    line_start=line_number,  # Use line_number from request
                                    cwe_id=cwe_id,
                                    severity=severity,
                                    pr_url=pr_url,
                                    pr_number=pr_number,
                                    pr_title=pr_title_actual,
                                    status="pr_created",
                                    fix_description=f"Automated fix for {file_path}",
                                    pr_created_at=datetime.now(timezone.utc),
                                    webhook_url=webhook_url,
                                )

                                fix_session.add(fix_request)
                                fix_session.commit()

                                logger.info(
                                    f"Created fix request {fix_request.id} for finding {finding_id}"
                                )
                            finally:
                                fix_session.close()
                                fix_engine.dispose()
                        except Exception as fix_err:
                            logger.error(
                                f"Failed to create fix request: {str(fix_err)}",
                                exc_info=True,
                            )
                            # Don't fail the PR creation if fix request fails

                    return (
                        {
                            "success": True,
                            "data": {
                                "pullRequest": {
                                    "number": pr_number,
                                    "url": pr_url,
                                    "title": pr_title_actual,
                                    "branch": new_branch,
                                    "baseBranch": base_branch,
                                },
                                "webhook": {
                                    "enabled": webhook_enabled,
                                    "url": webhook_url,
                                    "error": webhook_error,
                                    "liveUpdates": webhook_enabled,
                                },
                            },
                        },
                        200,
                    )

        except aiohttp.ClientError as e:
            logger.error(f"HTTP request error: {str(e)}")
            return (
                {
                    "success": False,
                    "error": {"message": f"HTTP request failed: {str(e)}"},
                },
                500,
            )
        except Exception as e:
            logger.error(f"Error creating pull request: {str(e)}")
            return (
                {
                    "success": False,
                    "error": {"message": f"Internal server error: {str(e)}"},
                },
                500,
            )

    # Run the async function and return the result
    try:
        result, status_code = asyncio.run(create_pr_async())
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error running async create PR: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {"message": f"Internal server error: {str(e)}"},
                }
            ),
            500,
        )


@api.route("/fix-requests", methods=["POST"])
def create_fix_request():
    """
    Create a fix request record to track PR status for a security finding.
    Call this after successfully creating a PR.

    Expected payload:
    {
        "user_id": "user123",
        "workspace_id": "68c7530c1338b2befdcbc532",  // optional
        "repo_type": "github",  // github, gitlab, azure_devops, etc.
        "repo_identifier": "https://github.com/owner/repo",
        "branch_name": "main",  // optional, defaults to "main"
        "finding_id": "rule.id",
        "file_path": "/path/to/file",
        "cwe_id": "CWE-89",  // optional
        "severity": "high",  // optional
        "pr_url": "https://github.com/owner/repo/pull/123",
        "pr_number": "123",
        "pr_title": "Fix: SQL injection vulnerability",
        "fix_description": "Fixed SQL injection by using parameterized queries",  // optional
        "metadata": {}  // optional additional data
    }
    """
    engine = None
    db_session = None

    try:
        request_data = request.get_json()
        if not request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Get required parameters

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        user_id = request_data.get("user_id")
        user_id = request_data.get("user_id")
        repo_type = request_data.get("repo_type")
        repo_identifier = request_data.get("repo_identifier")
        finding_id = request_data.get("finding_id")  # Rule ID only
        file_path = request_data.get("file_path")
        line_start = request_data.get("line_start")  # Line number of the finding

        # Validate required fields
        if not all(
            [user_id, repo_type, repo_identifier, finding_id, file_path, line_start]
        ):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "user_id, repo_type, repo_identifier, finding_id, file_path, and line_start are required"
                        },
                    }
                ),
                400,
            )

        # Get optional parameters
        workspace_id = request_data.get("workspace_id")
        branch_name = request_data.get("branch_name", "main")
        cwe_id = request_data.get("cwe_id")
        severity = request_data.get("severity")
        pr_url = request_data.get("pr_url")
        pr_number = request_data.get("pr_number")
        pr_title = request_data.get("pr_title")
        fix_description = request_data.get("fix_description")
        additional_data = request_data.get("additional_data")

        # Validate workspace_id if provided
        if workspace_id:
            validation = validate_workspace_id(workspace_id)
            if not validation["valid"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": f"Invalid workspace_id: {validation['error']}"
                            },
                        }
                    ),
                    400,
                )

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Determine status based on PR information
        status = "pr_created" if pr_url else "pending"
        pr_created_at = datetime.now(timezone.utc) if pr_url else None

        # Create fix request record
        fix_request = FixRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            repo_type=repo_type,
            repo_identifier=repo_identifier,
            branch_name=branch_name,
            finding_id=finding_id,
            file_path=file_path,
            line_start=line_start,
            cwe_id=cwe_id,
            severity=severity,
            pr_url=pr_url,
            pr_number=pr_number,
            pr_title=pr_title,
            status=status,
            fix_description=fix_description,
            pr_created_at=pr_created_at,
            additional_data=additional_data,
        )

        db_session.add(fix_request)
        db_session.commit()

        logger.info(
            f"Created fix request {fix_request.id} for finding {finding_id} in {repo_identifier}"
        )

        return jsonify({"success": True, "data": fix_request.to_dict()}), 201

    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Error creating fix request: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/fix-requests/<int:fix_request_id>", methods=["PATCH"])
def update_fix_request(fix_request_id):
    """
    Update a fix request status (for webhook updates).

    Expected payload:
    {
        "status": "pr_merged",  // pending, pr_created, pr_merged, pr_closed, failed
        "pr_url": "https://github.com/owner/repo/pull/123",  // optional
        "pr_number": "123",  // optional
        "pr_title": "Fix: SQL injection",  // optional
        "error": "Error message if failed",  // optional
        "metadata": {}  // optional additional data
    }
    """
    engine = None
    db_session = None

    try:
        request_data = request.get_json()
        if not request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Create database session

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        engine = create_api_engine()
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get the fix request
        fix_request = db_session.query(FixRequest).filter_by(id=fix_request_id).first()

        if not fix_request:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": f"Fix request {fix_request_id} not found"},
                    }
                ),
                404,
            )

        # Update fields if provided
        if "status" in request_data:
            new_status = request_data["status"]
            valid_statuses = [
                "pending",
                "pr_created",
                "pr_merged",
                "pr_closed",
                "failed",
            ]
            if new_status not in valid_statuses:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": f"Invalid status. Must be one of: {', '.join(valid_statuses)}"
                            },
                        }
                    ),
                    400,
                )

            fix_request.status = new_status

            # Update timestamp fields based on status
            if new_status == "pr_created" and not fix_request.pr_created_at:
                fix_request.pr_created_at = datetime.now(timezone.utc)
            elif new_status == "pr_merged":
                fix_request.pr_merged_at = datetime.now(timezone.utc)
            elif new_status == "pr_closed":
                fix_request.pr_closed_at = datetime.now(timezone.utc)

        if "pr_url" in request_data:
            fix_request.pr_url = request_data["pr_url"]

        if "pr_number" in request_data:
            fix_request.pr_number = request_data["pr_number"]

        if "pr_title" in request_data:
            fix_request.pr_title = request_data["pr_title"]

        if "error" in request_data:
            fix_request.error = request_data["error"]

        if "additional_data" in request_data:
            # Merge with existing additional_data if present
            if fix_request.additional_data:
                fix_request.additional_data = {
                    **fix_request.additional_data,
                    **request_data["additional_data"],
                }
            else:
                fix_request.additional_data = request_data["additional_data"]

        fix_request.updated_at = datetime.now(timezone.utc)

        db_session.commit()

        logger.info(
            f"Updated fix request {fix_request_id} to status: {fix_request.status}"
        )

        return jsonify({"success": True, "data": fix_request.to_dict()}), 200

    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Error updating fix request: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/fix-requests", methods=["GET"])
def get_fix_requests():
    """
    Get fix requests with optional filtering.

    Query parameters:
    - user_id: Filter by user (required)
    - workspace_id: Filter by workspace (optional)
    - repo_identifier: Filter by repository (optional)
    - status: Filter by status (optional)
    - finding_id: Filter by specific finding (optional)
    """
    engine = None
    db_session = None

    try:
        user_id = request.args.get("user_id")
        if not user_id:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": "user_id query parameter is required"},
                    }
                ),
                400,
            )

        workspace_id = request.args.get("workspace_id")
        repo_identifier = request.args.get("repo_identifier")
        status = request.args.get("status")
        finding_id = request.args.get("finding_id")

        # Validate workspace_id if provided
        if workspace_id:
            validation = validate_workspace_id(workspace_id)
            if not validation["valid"]:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": f"Invalid workspace_id: {validation['error']}"
                            },
                        }
                    ),
                    400,
                )

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Build query
        query = db_session.query(FixRequest).filter_by(user_id=user_id)

        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)

        if repo_identifier:
            query = query.filter_by(repo_identifier=repo_identifier)

        if status:
            query = query.filter_by(status=status)

        if finding_id:
            query = query.filter_by(finding_id=finding_id)

        # Order by most recent first
        fix_requests = query.order_by(desc(FixRequest.created_at)).all()

        # Convert to dict
        fix_requests_data = [fr.to_dict() for fr in fix_requests]

        # Calculate statistics
        total_count = len(fix_requests_data)
        status_counts = {}
        for fr in fix_requests_data:
            status_counts[fr["status"]] = status_counts.get(fr["status"], 0) + 1

        logger.info(f"Retrieved {total_count} fix requests for user {user_id}")

        return (
            jsonify(
                {
                    "success": True,
                    "data": {
                        "fix_requests": fix_requests_data,
                        "total_count": total_count,
                        "status_counts": status_counts,
                        "filters_applied": {
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                            "repo_identifier": repo_identifier,
                            "status": status,
                            "finding_id": finding_id,
                        },
                    },
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error getting fix requests: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/fix-requests/<int:fix_request_id>", methods=["GET"])
def get_fix_request(fix_request_id):
    """Get a specific fix request by ID"""
    engine = None
    db_session = None

    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        fix_request = db_session.query(FixRequest).filter_by(id=fix_request_id).first()

        if not fix_request:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": f"Fix request {fix_request_id} not found"},
                    }
                ),
                404,
            )

        return jsonify({"success": True, "data": fix_request.to_dict()}), 200

    except Exception as e:
        logger.error(f"Error getting fix request: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@api.route("/pr/webhook", methods=["POST"])
def handle_pr_webhook():
    """
    Unified webhook endpoint for GitHub, GitLab, and Azure DevOps PR/MR updates.
    Updates the fix_requests table with PR status changes.
    """
    import hmac
    import hashlib

    def verify_github_signature(payload_body, signature_header):
        """Verify GitHub webhook signature using HMAC SHA256"""
        secret = os.getenv("GITHUB_WEBHOOK_SECRET")
        if not secret:
            logger.warning(
                "GITHUB_WEBHOOK_SECRET not set - skipping signature verification"
            )
            return True

        if not signature_header:
            return False

        hash_object = hmac.new(
            secret.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256
        )
        expected_signature = "sha256=" + hash_object.hexdigest()

        # Timing-safe comparison
        return hmac.compare_digest(expected_signature, signature_header)

    def verify_gitlab_token(token_header):
        """Verify GitLab webhook token"""
        secret = os.getenv("GITLAB_WEBHOOK_TOKEN")
        if not secret:
            logger.warning("GITLAB_WEBHOOK_TOKEN not set - skipping token verification")
            return True

        return token_header == secret

    def verify_azure_auth(auth_header):
        """Verify Azure DevOps webhook basic authentication"""
        username = os.getenv("AZURE_WEBHOOK_USERNAME", "webhook")
        password = os.getenv("AZURE_WEBHOOK_PASSWORD")

        if not password:
            logger.warning(
                "AZURE_WEBHOOK_PASSWORD not set - skipping auth verification"
            )
            return True

        if not auth_header or not auth_header.startswith("Basic "):
            return False

        try:
            base64_credentials = auth_header[6:]  # Remove "Basic " prefix
            credentials = base64.b64decode(base64_credentials).decode("utf-8")
            provided_username, provided_password = credentials.split(":", 1)

            return provided_username == username and provided_password == password
        except Exception as e:
            logger.error(f"Error verifying Azure auth: {str(e)}")
            return False

    engine = None
    db_session = None

    try:
        # Get raw request body for signature verification
        raw_body = request.get_data()

        # Detect webhook source from headers
        github_event = request.headers.get("x-github-event")
        gitlab_event = request.headers.get("x-gitlab-event")
        azure_event_type = request.headers.get("x-vss-activityid")  # Azure DevOps
        sns_message_type = request.headers.get(
            "x-amz-sns-message-type"
        )  # AWS SNS/CodeCommit

        webhook_source = None

        # Determine source and verify authentication
        if github_event:
            webhook_source = "github"
            signature = request.headers.get("x-hub-signature-256")
            if not verify_github_signature(raw_body, signature):
                logger.error("Invalid GitHub webhook signature")
                return jsonify({"success": False, "error": "Invalid signature"}), 401

        elif gitlab_event:
            webhook_source = "gitlab"
            token = request.headers.get("x-gitlab-token")
            if not verify_gitlab_token(token):
                logger.error("Invalid GitLab webhook token")
                return jsonify({"success": False, "error": "Invalid token"}), 401

        elif azure_event_type:
            webhook_source = "azure_devops"
            auth_header = request.headers.get("authorization")
            if not verify_azure_auth(auth_header):
                logger.error("Invalid Azure DevOps webhook authentication")
                return jsonify({"success": False, "error": "Unauthorized"}), 401

        elif sns_message_type:
            # AWS SNS (CodeCommit)
            webhook_source = "codecommit"

            # SNS sends data as text/plain, not application/json - parse manually
            import json

            payload = json.loads(raw_body.decode("utf-8"))

            logger.info(f"Received SNS message type: {sns_message_type}")

            # Handle subscription confirmation (one-time setup)
            if sns_message_type == "SubscriptionConfirmation":
                subscribe_url = payload.get("SubscribeURL")
                topic_arn = payload.get("TopicArn", "unknown")

                logger.info(f"SNS Subscription Confirmation for topic: {topic_arn}")

                if subscribe_url:
                    logger.info(f"Confirming SNS subscription by visiting URL...")
                    import urllib.request

                    try:
                        with urllib.request.urlopen(
                            subscribe_url, timeout=30
                        ) as response:
                            response_code = response.getcode()
                            logger.info(
                                f"SNS subscription confirmed! Response code: {response_code}"
                            )
                            return (
                                jsonify(
                                    {
                                        "success": True,
                                        "message": "Subscription confirmed",
                                        "topicArn": topic_arn,
                                    }
                                ),
                                200,
                            )
                    except Exception as confirm_error:
                        logger.error(
                            f"Failed to confirm SNS subscription: {str(confirm_error)}",
                            exc_info=True,
                        )
                        return (
                            jsonify(
                                {
                                    "success": False,
                                    "error": f"Failed to confirm subscription: {str(confirm_error)}",
                                }
                            ),
                            500,
                        )
                else:
                    logger.error("No SubscribeURL in confirmation message")
                    return (
                        jsonify({"success": False, "error": "Missing SubscribeURL"}),
                        400,
                    )

            # Handle notification messages (actual PR events)
            elif sns_message_type == "Notification":
                # SNS wraps the actual event in a "Message" field as JSON string
                message_str = payload.get("Message", "{}")
                message = json.loads(message_str)

                detail_type = message.get("detailType")
                logger.info(f"Received CodeCommit notification: {detail_type}")

                # Only process PR state changes
                if detail_type != "CodeCommit Pull Request State Change":
                    logger.info(f"Ignoring non-PR CodeCommit event: {detail_type}")
                    return (
                        jsonify({"success": True, "message": "Event acknowledged"}),
                        200,
                    )

                # Extract PR details and continue to unified processing below
                detail = message.get("detail", {})
                payload = {
                    "codecommit_detail": detail,
                    "region": message.get("region", "us-east-1"),
                }

            else:
                logger.warning(f"Unknown SNS message type: {sns_message_type}")
                return (
                    jsonify({"success": True, "message": "Message acknowledged"}),
                    200,
                )

        else:
            logger.error("Unknown webhook source")
            return jsonify({"success": False, "error": "Unknown webhook source"}), 400

        # Parse JSON payload (for non-CodeCommit sources)
        if webhook_source != "codecommit":
            payload = request.get_json()

        logger.info(f"Received {webhook_source} webhook")

        # Extract PR information based on source
        pr_number = None
        pr_status = None
        pr_url = None
        pr_merged = False
        pr_closed = False
        pr_reopened = False

        if webhook_source == "github":
            pr_data = payload.get("pull_request", {})
            pr_number = str(pr_data.get("number"))
            pr_status = pr_data.get("state")  # open, closed
            pr_url = pr_data.get("html_url")
            pr_merged = pr_data.get("merged", False)

            # Determine if closed (merged or just closed) or reopened
            if pr_status == "closed":
                pr_closed = True
            elif pr_status == "open":
                # Check if this is a reopen action
                action = payload.get("action")
                if action == "reopened":
                    pr_reopened = True

            logger.info(
                f"GitHub PR #{pr_number}: status={pr_status}, merged={pr_merged}, reopened={pr_reopened}, url={pr_url}"
            )

        elif webhook_source == "gitlab":
            obj_attrs = payload.get("object_attributes", {})
            pr_number = str(obj_attrs.get("iid"))
            pr_status = obj_attrs.get(
                "state"
            )  # opened, closed, merged, locked, reopened
            pr_url = obj_attrs.get("url")
            action = obj_attrs.get("action")  # open, close, reopen, update, merge

            # GitLab has explicit merged state
            if pr_status == "merged":
                pr_merged = True
                pr_closed = True
            elif pr_status == "closed":
                pr_closed = True
            elif pr_status == "opened" or action == "reopen":
                # Check if this is a reopen action
                if action == "reopen":
                    pr_reopened = True

            logger.info(
                f"GitLab MR !{pr_number}: status={pr_status}, action={action}, reopened={pr_reopened}, url={pr_url}"
            )

        elif webhook_source == "azure_devops":
            resource = payload.get("resource", {})
            pr_number = str(resource.get("pullRequestId"))
            pr_status = resource.get("status")  # active, abandoned, completed
            pr_url = resource.get("_links", {}).get("web", {}).get("href")

            # Azure DevOps uses "completed" for merged
            if pr_status == "completed":
                pr_merged = True
                pr_closed = True
            elif pr_status == "abandoned":
                pr_closed = True
            elif pr_status == "active":
                # If it was previously closed/abandoned and now active, it's been reactivated
                pr_reopened = True

            logger.info(
                f"Azure DevOps PR #{pr_number}: status={pr_status}, reopened={pr_reopened}, url={pr_url}"
            )

        elif webhook_source == "codecommit":
            # Extract from CodeCommit event structure
            detail = payload.get("codecommit_detail", {})
            region = payload.get("region", "us-east-1")

            pr_number = str(detail.get("pullRequestId", ""))
            pr_status = detail.get("pullRequestStatus", "")  # Open, Closed
            is_merged = detail.get("isMerged", "False") == "True"
            repo_names = detail.get("repositoryNames", [])
            repo_name = repo_names[0] if repo_names else ""

            # Construct PR URL
            pr_url = f"https://{region}.console.aws.amazon.com/codesuite/codecommit/repositories/{repo_name}/pull-requests/{pr_number}"

            # Map CodeCommit status to our standard flags
            if is_merged and pr_status == "Closed":
                pr_merged = True
                pr_closed = True
            elif pr_status == "Closed":
                pr_closed = True
            elif pr_status == "Open":
                # Could be reopened if it was previously closed
                pr_reopened = True  # Will check DB status below to confirm

            logger.info(
                f"CodeCommit PR #{pr_number}: status={pr_status}, merged={is_merged}, url={pr_url}"
            )

        # Only process if we have PR number
        if not pr_number:
            logger.warning(f"No PR number found in {webhook_source} webhook payload")
            return jsonify({"success": True, "message": "No PR number to process"}), 200

        # Update fix_requests table
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Find fix request by PR number and URL (more reliable than just number)
        fix_request = None
        if pr_url:
            fix_request = (
                db_session.query(FixRequest).filter(FixRequest.pr_url == pr_url).first()
            )

        # Fallback to searching by PR number and repo type
        if not fix_request and pr_number:
            fix_request = (
                db_session.query(FixRequest)
                .filter(
                    FixRequest.pr_number == pr_number,
                    FixRequest.repo_type == webhook_source,
                )
                .order_by(desc(FixRequest.created_at))
                .first()
            )

        if not fix_request:
            logger.warning(f"No fix request found for {webhook_source} PR #{pr_number}")
            return jsonify({"success": True, "message": "No matching fix request"}), 200

        # Update fix request status
        updated = False

        if pr_reopened and fix_request.status in ["pr_closed", "pr_merged"]:
            # PR was reopened - reset to pr_created status
            fix_request.status = "pr_created"
            fix_request.pr_closed_at = None  # Clear closed timestamp
            fix_request.pr_merged_at = None  # Clear merged timestamp if it was set
            updated = True
            logger.info(
                f"Updated fix request {fix_request.id} to pr_created (reopened)"
            )

        elif pr_merged and fix_request.status != "pr_merged":
            fix_request.status = "pr_merged"
            fix_request.pr_merged_at = datetime.now(timezone.utc)
            updated = True
            logger.info(f"Updated fix request {fix_request.id} to pr_merged")

        elif pr_closed and not pr_merged and fix_request.status != "pr_closed":
            fix_request.status = "pr_closed"
            fix_request.pr_closed_at = datetime.now(timezone.utc)
            updated = True
            logger.info(f"Updated fix request {fix_request.id} to pr_closed")

        # Update URL if it changed
        if pr_url and fix_request.pr_url != pr_url:
            fix_request.pr_url = pr_url
            updated = True

        if updated:
            fix_request.updated_at = datetime.now(timezone.utc)
            db_session.commit()
            logger.info(
                f"Successfully updated fix request {fix_request.id} from {webhook_source} webhook"
            )
        else:
            logger.info(f"No updates needed for fix request {fix_request.id}")

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Webhook processed successfully",
                    "fix_request_id": fix_request.id,
                    "updated": updated,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error processing PR webhook: {str(e)}", exc_info=True)
        return jsonify({"success": False, "error": "Internal server error"}), 500

    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()
