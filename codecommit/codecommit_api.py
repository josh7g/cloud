from flask import Blueprint, jsonify, request
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc
from models import RepositoryScanResult, IgnoredFinding, FixRequest
import asyncio
import time
import logging
import os
from datetime import datetime, timezone
from .codecommit_scanner import scan_codecommit_repo
from db_utils import create_db_engine
from ignore_utils import add_ignore_status_to_findings, normalize_file_path
from fix_utils import add_fix_status_to_findings
from utils import extract_clean_file_path, get_repository_identifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def create_api_engine():
    """Create database engine for API routes"""
    return create_db_engine()


codecommit_bp = Blueprint("codecommit", __name__, url_prefix="/api/v1/codecommit")


@codecommit_bp.route("/validate-credentials", methods=["POST"])
def validate_codecommit_credentials():
    """
    Validate AWS CodeCommit credentials and repository access.

    Args (in request body):
        repo_name (str): Name of the CodeCommit repository
        region (str): AWS region where the repository is hosted
        aws_access_key_id (str): AWS access key ID
        aws_secret_access_key (str): AWS secret access key

    Returns:
        JSON response with validation status and repository details
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Validate required parameters
        required_params = [
            "repo_name",
            "region",
            "aws_access_key_id",
            "aws_secret_access_key",
        ]
        missing_params = [param for param in required_params if param not in data]

        if missing_params:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f"Missing required parameters: {', '.join(missing_params)}",
                            "code": "INVALID_PARAMETERS",
                        },
                    }
                ),
                400,
            )

        repo_name = data["repo_name"]
        region = data["region"]
        aws_access_key_id = data["aws_access_key_id"]
        aws_secret_access_key = data["aws_secret_access_key"]

        logger.info(f"Validating CodeCommit credentials for repository: {repo_name}")

        # Import the scanner class to use its validation method
        from .codecommit_scanner import AWSCodeCommitScanner
        from .utils import ScanConfig

        # Create scanner instance with provided credentials
        scanner = AWSCodeCommitScanner(
            config=ScanConfig(),
            repo_name=repo_name,
            region=region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
        )

        # Validate credentials using the scanner's method
        validation_result = scanner.validate_credentials()

        if validation_result["success"]:
            logger.info(
                f"Successfully validated access to repository: {repo_name} in region: {region}"
            )
            return (
                jsonify(
                    {
                        "success": True,
                        "message": validation_result["message"],
                        "repository": validation_result["details"],
                        "languages": validation_result.get("languages", []),
                    }
                ),
                200,
            )
        else:
            logger.warning(f"Validation failed for repository: {repo_name}")
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": validation_result["message"],
                            "code": "VALIDATION_FAILED",
                        },
                    }
                ),
                400,
            )

    except ValueError as e:
        # Handle repository not found, invalid name, etc.
        logger.error(f"Validation error: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": str(e),
                        "code": "VALIDATION_ERROR",
                    },
                }
            ),
            404,
        )

    except PermissionError as e:
        # Handle access denied errors
        logger.error(f"Permission error: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": str(e),
                        "code": "ACCESS_DENIED",
                    },
                }
            ),
            403,
        )

    except Exception as e:
        # Handle unexpected errors
        logger.error(f"Unexpected validation error: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": "Failed to validate credentials",
                        "code": "INTERNAL_ERROR",
                        "details": str(e),
                    },
                }
            ),
            500,
        )


@codecommit_bp.route("/scan", methods=["POST"])
def trigger_codecommit_scan():
    """
    Trigger a security scan for an AWS CodeCommit repository.

    Args (in request body):
        repo_name (str): Name of the CodeCommit repository
        region (str): AWS region where the repository is hosted
        aws_access_key_id (str): AWS access key ID
        aws_secret_access_key (str): AWS secret access key
        branch (str, optional): Branch to scan (default: "main")
        user_id (str): ID of the user requesting the scan
        workspace_id (str): Workspace ID for organization
    """
    from app import socketio

    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Validate required parameters
        required_base_params = ["repo_name", "region", "user_id", "workspace_id"]
        missing_base = [param for param in required_base_params if param not in data]

        if missing_base:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f"Missing required parameters: {', '.join(missing_base)}",
                            "code": "INVALID_PARAMETERS",
                        },
                    }
                ),
                400,
            )

        # Check for authentication credentials (IAM only)
        has_iam_creds = "aws_access_key_id" in data and "aws_secret_access_key" in data

        if not has_iam_creds:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "aws_access_key_id and aws_secret_access_key must be provided",
                            "code": "INVALID_PARAMETERS",
                        },
                    }
                ),
                400,
            )

        user_id = data["user_id"]
        repo_name = data["repo_name"]
        region = data["region"]
        branch = data.get("branch", "main")
        workspace_id = data.get("workspace_id")

        # Get IAM credentials
        aws_access_key_id = data.get("aws_access_key_id")
        aws_secret_access_key = data.get("aws_secret_access_key")

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        repo_identifier = get_repository_identifier(
            "codecommit", region=region, repo=repo_name
        )

        # Create analysis record
        codecommit_analysis = RepositoryScanResult(
            repo_type="codecommit",
            user_id=user_id,
            workspace_id=workspace_id,
            repo_identifier=repo_identifier,
            branch_name=branch,
            status="queued",
        )
        db_session.add(codecommit_analysis)
        db_session.commit()
        logger.info(
            f"Created CodeCommit analysis record with ID: {codecommit_analysis.id}"
        )

        # Clear both progress AND completion cache for this repo
        from progress_tracking import get_redis_client

        redis_client = get_redis_client()

        # Define keys
        completion_key = f"scan_complete:{user_id}:{region}/{repo_name}"
        progress_key = f"scan_progress:{user_id}:{region}/{repo_name}"

        # Delete cached data
        redis_client.delete(completion_key)
        redis_client.delete(progress_key)
        logger.info(f"Cleared previous CodeCommit scan data for {repo_name}")

        # Send a reset message to all subscribers
        reset_data = {
            "s": "reset",
            "p": 0,
            "o": 0,
            "t": int(time.time()),
            "id": f"scan_{int(time.time())}",
        }

        room = f"scan_{user_id}_{region}/{repo_name}"
        socketio.emit("progress_update", reset_data, room=room)
        logger.info(f"Sent CodeCommit reset signal to room {room}")

        # Initialize progress tracking
        from progress_tracking import clear_scan_progress, update_scan_progress

        clear_scan_progress(user_id, f"{region}/{repo_name}")
        update_scan_progress(user_id, f"{region}/{repo_name}", "initializing", 5)

        def run_scan_in_background():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                result = loop.run_until_complete(
                    scan_codecommit_repo(
                        repo_name=repo_name,
                        region=region,
                        branch=branch,
                        user_id=user_id,
                        db_session=db_session,
                        codecommit_analysis_record=codecommit_analysis,
                        aws_access_key_id=aws_access_key_id,
                        aws_secret_access_key=aws_secret_access_key,
                        multi_scan=True,
                    )
                )

                logger.info(
                    f"CodeCommit scan completed for {region}/{repo_name}: {result.get('success')}"
                )

            except Exception as e:
                logger.error(f"Background scan error: {str(e)}")
                if codecommit_analysis:
                    codecommit_analysis.status = "failed"
                    codecommit_analysis.error = str(e)
                    db_session.commit()
            finally:
                db_session.close()
                if engine:
                    engine.dispose()

        from threading import Thread

        thread = Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Scan queued successfully",
                    "scan_id": codecommit_analysis.id,
                    "status": "queued",
                    "repository": repo_name,
                    "region": region,
                    "branch": branch,
                }
            ),
            202,
        )

    except Exception as e:
        logger.error(f"Scan initialization error: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": "Internal server error",
                        "code": "SCAN_ERROR",
                        "details": str(e),
                    },
                }
            ),
            400,
        )


@codecommit_bp.route("/files", methods=["POST"])
def get_codecommit_file():
    """
    Fetch file content from AWS CodeCommit using POST with all parameters in request body.

    Args (in request body):
        repo_name (str): Name of the CodeCommit repository
        region (str): AWS region where the repository is hosted
        file_name (str): Path to the file in the repository
        aws_access_key_id (str): AWS access key ID
        aws_secret_access_key (str): AWS secret access key
        branch (str, optional): Branch name (default: "main")
        user_id (str): ID of the user requesting the file

    Returns:
        JSON response with file content or error details
    """
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Validate required parameters
        required_params = [
            "repo",  # repo name
            "owner",  # aws region
            "file_name",
            "aws_access_key_id",
            "aws_secret_access_key",
            "user_id",
        ]
        missing_params = [param for param in required_params if param not in data]

        if missing_params:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f"Missing required parameters: {', '.join(missing_params)}",
                            "code": "INVALID_PARAMETERS",
                        },
                    }
                ),
                400,
            )

        repo_name = data["repo"]
        region = data["owner"]
        file_name = data["file_name"]
        aws_access_key_id = data["aws_access_key_id"]
        aws_secret_access_key = data["aws_secret_access_key"]
        branch = data.get("branch", "main")
        user_id = data["user_id"]

        logger.info(f"Fetching file: {file_name} from CodeCommit repo: {repo_name}")

        # Import the helper function
        from .codecommit_scanner import get_codecommit_file_content
        from urllib.parse import unquote

        # Create event loop to run async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            result = loop.run_until_complete(
                get_codecommit_file_content(
                    repo_name=repo_name,
                    region=region,
                    file_path=extract_clean_file_path(file_name),
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                    branch=branch,
                )
            )

            if not result.get("success"):
                error_info = result.get("error", {})
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": error_info.get("message", "Unknown error"),
                                "code": error_info.get("code", "UNKNOWN_ERROR"),
                                "details": error_info.get(
                                    "details",
                                    "An error occurred while fetching the file",
                                ),
                            },
                        }
                    ),
                    404 if error_info.get("code") == "FILE_NOT_FOUND" else 500,
                )

            # Return successful response
            metadata = result.get("metadata", {})
            return jsonify(
                {
                    "success": True,
                    "data": {
                        "file": result.get("content"),
                        "user_id": user_id,
                        "version": metadata.get("commit_id", "latest"),
                        "reponame": f"{region}/{repo_name}",
                        "filename": unquote(file_name),
                        "metadata": {
                            "commit_id": metadata.get("commit_id"),
                            "file_size": metadata.get("file_size"),
                            "blob_id": metadata.get("blob_id"),
                            "branch": branch,
                        },
                    },
                }
            )

        finally:
            loop.close()

    except Exception as e:
        logger.error(f"CodeCommit file fetch error: {str(e)}")
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


@codecommit_bp.route("/analysis/<region>/<repo>/result", methods=["GET"])
def get_codecommit_analysis_findings(region: str, repo: str):
    engine = None
    db_session = None

    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("limit", 30))))
        severity = request.args.get("severity", "").upper()
        category = request.args.get("category", "")
        file_path = request.args.get("file", "")
        user_id = request.args.get("user_id")
        workspace_id = request.args.get("workspace_id")

        logger.info(f"Filtering analysis results by workspace_id: {workspace_id}")

        # ideally all repo types use one endpoint and the scan is done by a unique repo_identifier
        query = db_session.query(RepositoryScanResult).filter_by(
            repo_identifier=get_repository_identifier(
                "codecommit", region=region, repo=repo
            ),
            workspace_id=workspace_id,
            status="completed",
        )

        result = query.order_by(desc(RepositoryScanResult.timestamp)).first()

        if not result:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f"No analysis found for workspace {workspace_id}",
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

        # add ignore status to findings
        repo_name = f"{region}/{repo}"
        repo_identifier = get_repository_identifier(
            "codecommit", region=region, repo=repo
        )
        if user_id and findings:
            findings = add_ignore_status_to_findings(
                user_id, repo_name, findings, workspace_id, "codecommit"
            )
            # Add fix status to findings
            findings = add_fix_status_to_findings(
                user_id,
                repo_identifier,
                findings,
                workspace_id,
                "codecommit",
                db_session,
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
            normalized_filter_path = normalize_file_path(file_path)
            findings = [
                f
                for f in findings
                if normalized_filter_path in normalize_file_path(f.get("file", ""))
            ]

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
            for idx, finding in enumerate(findings)
        ]

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

        # Calculate adjusted severity counts based on ignore status
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
                severity_level = finding.get("severity", "INFO").upper()

                if severity_level == "ERROR":
                    severity_level = "HIGH"
                elif severity_level == "WARNING":
                    severity_level = "MEDIUM"
                elif severity_level == "INFO":
                    severity_level = "LOW"

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
            "severity_counts": complete_severity_counts,  # NOW ADJUSTED FOR IGNORES
            "skipped_files": stats.get("scan_stats", {}).get("skipped_files", 0),
            "total_findings": total_findings
            - (
                ignore_stats.get("total_ignored", 0) if user_id else 0
            ),  # ADJUSTED TOTAL
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
                    "repository": {"name": repo_name, "region": region},
                    "metadata": {
                        "analysis_id": result.id,
                        "duration_seconds": metadata.get("scan_duration_seconds", 0),
                        "status": result.status,
                        "timestamp": result.timestamp.isoformat(),
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "actual_workspace_id": result.workspace_id,
                        "ignore_support": bool(user_id),
                        "workspace_filtering": bool(workspace_id),
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
        logger.error(f"Error getting AWS Codecommit findings: {str(e)}")
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


@codecommit_bp.route("/scan/<region>/<repo>", methods=["DELETE"])
def delete_codecommit_scan_results(region: str, repo: str):
    """Delete CodeCommit scan results for a specific repository"""
    engine = None
    db_session = None
    try:
        repo_name = f"{region}/{repo}"
        logger.info(f"[CodeCommit] Starting delete request for repository: {repo_name}")

        # Get user_id from query parameter or request body
        user_id = request.args.get("user_id") or (request.get_json() or {}).get(
            "user_id"
        )

        workspace_id = request.args.get("workspace_id") or (
            request.get_json() or {}
        ).get("workspace_id")

        logger.info(
            f"[CodeCommit] Delete request - region: {region}, repo: {repo}, user_id: {user_id}"
        )

        if not user_id and not workspace_id:
            logger.warning(
                f"[CodeCommit] Delete request failed - missing workspace_id and user_id for repo: {repo_name}"
            )
            return (
                jsonify(
                    {"success": False, "error": {"message": "user_id is required"}}
                ),
                400,
            )

        logger.info(f"[CodeCommit] Creating database connection for delete operation")
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        # Get all analyses for this repository
        repo_identifier = get_repository_identifier(
            "codecommit", region=region, repo=repo
        )

        logger.info(
            f"[CodeCommit] Querying analyses for repository: {repo_identifier}, user_id: {user_id}"
        )

        query = db_session.query(RepositoryScanResult)

        if workspace_id:
            analyses = query.filter(
                RepositoryScanResult.repo_identifier == repo_identifier,
                RepositoryScanResult.workspace_id == workspace_id,
            ).all()

        elif user_id:
            analyses = query.filter(
                RepositoryScanResult.repo_identifier == repo_identifier,
                RepositoryScanResult.user_id == user_id,
            ).all()

        logger.info(
            f"[CodeCommit] Found {len(analyses)} analyses to delete for repository: {repo_name}"
        )

        # Even if no analyses, continue to remove any ignore records for this repo
        if not analyses:
            logger.info(
                f"[CodeCommit] No analyses found for repository: {repo_name}, user_id: {user_id}"
            )
        else:
            # Log details about analyses being deleted
            for i, analysis in enumerate(analyses):
                logger.info(
                    f"[CodeCommit] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                    f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                    f"Workspace ID: {analysis.workspace_id}"
                )

            # Delete all analyses
            logger.info(f"[CodeCommit] Starting deletion of {len(analyses)} analyses")
            for analysis in analyses:
                db_session.delete(analysis)
                logger.debug(f"[CodeCommit] Marked analysis {analysis.id} for deletion")

            logger.info(f"[CodeCommit] Committing deletion transaction")
            db_session.commit()
            logger.info(
                f"[CodeCommit] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
            )

        # Delete associated ignore records for this repo and scope
        logger.info(
            f"[CodeCommit] Removing ignore records for repo: {repo_identifier}, user_id: {user_id}, workspace_id: {workspace_id}"
        )
        ignore_query = (
            db_session.query(IgnoredFinding)
            .filter(IgnoredFinding.repo_name == repo_identifier)
            .filter(IgnoredFinding.repo_type == "codecommit")
        )
        if workspace_id:
            ignore_query = ignore_query.filter(
                IgnoredFinding.workspace_id == workspace_id
            )
        elif user_id:
            ignore_query = ignore_query.filter(IgnoredFinding.user_id == user_id)

        ignore_records = ignore_query.all()
        logger.info(
            f"[CodeCommit] Found {len(ignore_records)} ignore records to delete for repo: {repo_identifier}"
        )
        for record in ignore_records:
            db_session.delete(record)
        db_session.commit()
        logger.info(
            f"[CodeCommit] Successfully deleted {len(ignore_records)} ignore records for repository: {repo_identifier}"
        )

        # Log details about analyses being deleted
        for i, analysis in enumerate(analyses):
            logger.info(
                f"[CodeCommit] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                f"Workspace ID: {analysis.workspace_id}"
            )

        # Delete all analyses
        logger.info(f"[CodeCommit] Starting deletion of {len(analyses)} analyses")
        for analysis in analyses:
            db_session.delete(analysis)
            logger.debug(f"[CodeCommit] Marked analysis {analysis.id} for deletion")

        logger.info(f"[CodeCommit] Committing deletion transaction")
        db_session.commit()
        logger.info(
            f"[CodeCommit] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
        )

        return jsonify("DONE")

    except Exception as e:
        logger.error(
            f"[CodeCommit] Error deleting scan results for repository {repo_name}: {str(e)}",
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
            logger.debug(f"[CodeCommit] Closing database session")
            db_session.close()
        if engine:
            logger.debug(f"[CodeCommit] Disposing database engine")
            engine.dispose()


@codecommit_bp.route("/users/severity-counts", methods=["POST"])
def get_codecommit_user_severity_counts():
    """Get severity counts for all CodeCommit repositories for a user"""
    engine = None
    db_session = None
    try:
        request_data = request.get_json()
        if not request_data or "user_id" not in request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "user_id is required"}}
                ),
                400,
            )

        user_id = request_data["user_id"]
        workspace_id = request_data.get("workspace_id")
        include_ignored = request_data.get("include_ignored", False)
        logger.info(
            f"Processing CodeCommit severity counts for user_id: {user_id}, include_ignored: {include_ignored}"
        )

        # Create engine
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        query = db_session.query(RepositoryScanResult).filter(
            RepositoryScanResult.repo_type == "codecommit",
            RepositoryScanResult.status == "completed",
            RepositoryScanResult.results.isnot(None),
        )

        if workspace_id:
            query = query.filter(RepositoryScanResult.workspace_id == workspace_id)
            logger.info(f"Filtering by workspace_id: {workspace_id}")
        else:
            query = query.filter(RepositoryScanResult.user_id == user_id)

        # Get all completed analyses
        all_analyses = query.order_by(RepositoryScanResult.timestamp.desc()).all()
        logger.info(
            f"Found {len(all_analyses)} total CodeCommit analyses after workspace filtering"
        )

        # Get latest analysis per repository
        latest_analyses = {}
        for analysis in all_analyses:
            repo_name = analysis.repo_identifier
            if repo_name not in latest_analyses:
                latest_analyses[repo_name] = analysis

        if not latest_analyses:
            # Return empty successful response instead of 404
            empty_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            return jsonify(
                {
                    "success": True,
                    "data": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "total_findings": 0,
                        "total_ignored_findings": 0,
                        "total_repositories": 0,
                        "severity_counts": empty_counts,
                        "ignored_severity_counts": empty_counts,
                        "repositories": {},
                        "metadata": {
                            "last_scan": None,
                            "scans_analyzed": 0,
                            "include_ignored": include_ignored,
                            "ignore_support": True,
                            "workspace_id": bool(workspace_id),
                            "platform": "codecommit",
                        },
                    },
                }
            )

        repository_data = {}
        total_severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        total_ignored_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        total_findings = 0
        total_ignored_findings = 0
        latest_scan_time = None

        for repo_name, analysis in latest_analyses.items():
            results = analysis.results or {}

            # Get findings and add ignore status
            findings = results.get("findings", [])
            if findings:
                findings = add_ignore_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "codecommit"
                )

            # Calculate severity counts
            repo_severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            repo_ignored_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}

            repo_total_findings = 0
            repo_ignored_findings = 0

            for finding in findings:
                severity = finding.get("severity", "INFO")
                is_ignored = finding.get("ignored", False)

                if is_ignored:
                    repo_ignored_counts[severity] += 1
                    total_ignored_counts[severity] += 1
                    repo_ignored_findings += 1
                    total_ignored_findings += 1

                    if include_ignored:
                        repo_severity_counts[severity] += 1
                        total_severity_counts[severity] += 1
                        repo_total_findings += 1
                        total_findings += 1
                else:
                    repo_severity_counts[severity] += 1
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
                "severity_counts": repo_severity_counts,
                "ignored_counts": repo_ignored_counts,
                "total_findings": repo_total_findings,
                "total_ignored": repo_ignored_findings,
            }

        return jsonify(
            {
                "success": True,
                "data": {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "total_findings": total_findings,
                    "total_ignored_findings": total_ignored_findings,
                    "total_repositories": len(repository_data),
                    "severity_counts": total_severity_counts,
                    "ignored_severity_counts": total_ignored_counts,
                    "repositories": repository_data,
                    "metadata": {
                        "last_scan": (
                            latest_scan_time.isoformat() if latest_scan_time else None
                        ),
                        "scans_analyzed": len(repository_data),
                        "include_ignored": include_ignored,
                        "ignore_support": True,
                        "workspace_id": bool(workspace_id),
                        "platform": "codecommit",
                    },
                },
            }
        )

    except Exception as e:
        logger.error(f"Error getting CodeCommit severity counts: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@codecommit_bp.route("/users/<user_id>/top-vulnerabilities", methods=["GET"])
def get_codecommit_top_vulnerabilities(user_id):
    """Get top vulnerabilities across all CodeCommit repositories for a user"""
    engine = None
    db_session = None
    try:
        from collections import defaultdict

        # Get query parameters
        include_ignored = request.args.get("include_ignored", "true").lower() == "true"
        workspace_id = request.args.get("workspace_id")

        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        query = db_session.query(RepositoryScanResult).filter(
            RepositoryScanResult.repo_type == "codecommit",
            RepositoryScanResult.status == "completed",
            RepositoryScanResult.results.isnot(None),
        )

        if workspace_id:
            query = query.filter(RepositoryScanResult.workspace_id == workspace_id)
            logger.info(
                f"Filtering top vulnerabilities by workspace_id: {workspace_id}"
            )
        else:
            query = query.filter(RepositoryScanResult.user_id == user_id)

        analyses = query.order_by(RepositoryScanResult.timestamp.desc()).all()
        logger.info(
            f"Found {len(analyses)} CodeCommit analyses after workspace filtering"
        )

        if not analyses:
            # Return empty successful response instead of 404
            return jsonify(
                {
                    "success": True,
                    "data": {
                        "metadata": {
                            "user_id": user_id,
                            "workspace_id": workspace_id,
                            "total_vulnerabilities": 0,
                            "total_ignored_vulnerabilities": 0,
                            "total_repositories": 0,
                            "total_workspaces": 0,
                            "severity_breakdown": {},
                            "ignored_severity_breakdown": {},
                            "category_breakdown": {},
                            "ignored_category_breakdown": {},
                            "repository_breakdown": {},
                            "workspace_breakdown": {},
                            "last_scan": None,
                            "repository": None,
                            "include_ignored": include_ignored,
                            "ignore_support": True,
                            "workspace_filtering": bool(workspace_id),
                            "platform": "codecommit",
                        },
                        "vulnerabilities": [],
                    },
                }
            )

        # Track statistics with ignore awareness
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        repo_counts = defaultdict(int)
        workspace_counts = defaultdict(int)
        ignored_severity_counts = defaultdict(int)
        ignored_category_counts = defaultdict(int)
        unique_vulns = {}
        total_ignored_vulnerabilities = 0

        for analysis in analyses:
            findings = analysis.results.get("findings", [])
            repo_name = analysis.repo_identifier
            analysis_workspace_id = analysis.workspace_id

            # Add ignore status to findings
            if findings:
                findings = add_ignore_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "codecommit"
                )
                # Add fix status to findings
                findings = add_fix_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "codecommit"
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
                            "id": vuln_id,
                            "title": finding.get("title", "Unknown"),
                            "severity": severity,
                            "category": category,
                            "description": finding.get("description", ""),
                            "cwe": finding.get("cwe", []),
                            "owasp": finding.get("owasp", []),
                            "occurrences": 1,
                            "repositories": [repo_name],
                            "workspaces": (
                                [analysis_workspace_id] if analysis_workspace_id else []
                            ),
                            "ignored": is_ignored,
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
                        if analysis_workspace_id:
                            workspace_counts[analysis_workspace_id] += 1
                    else:
                        unique_vulns[vuln_id]["occurrences"] += 1
                        if repo_name not in unique_vulns[vuln_id]["repositories"]:
                            unique_vulns[vuln_id]["repositories"].append(repo_name)
                            repo_counts[repo_name] += 1
                        if (
                            analysis_workspace_id
                            and analysis_workspace_id
                            not in unique_vulns[vuln_id]["workspaces"]
                        ):
                            unique_vulns[vuln_id]["workspaces"].append(
                                analysis_workspace_id
                            )
                            workspace_counts[analysis_workspace_id] += 1

        return jsonify(
            {
                "success": True,
                "data": {
                    "metadata": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "total_vulnerabilities": len(unique_vulns),
                        "total_ignored_vulnerabilities": total_ignored_vulnerabilities,
                        "total_repositories": len(repo_counts),
                        "total_workspaces": len(workspace_counts),
                        "severity_breakdown": dict(severity_counts),
                        "ignored_severity_breakdown": dict(ignored_severity_counts),
                        "category_breakdown": dict(category_counts),
                        "ignored_category_breakdown": dict(ignored_category_counts),
                        "repository_breakdown": dict(repo_counts),
                        "workspace_breakdown": dict(workspace_counts),
                        "last_scan": (
                            analyses[0].timestamp.isoformat() if analyses else None
                        ),
                        "repository": None,
                        "include_ignored": include_ignored,
                        "ignore_support": True,
                        "workspace_filtering": bool(workspace_id),
                        "platform": "codecommit",
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


@codecommit_bp.route("/analysis/<region>/<repo>/reranked", methods=["GET"])
def get_codecommit_reranked_findings(region: str, repo: str):
    """Get reranked findings for CodeCommit repositories"""
    engine = None
    session = None
    try:
        # Create engine
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        # Get query parameters
        user_id = request.args.get("user_id")
        workspace_id = request.args.get("workspace_id")
        logger.info(f"CodeCommit Reranked request: {region}/{repo}, user_id={user_id}")

        repo_identifier = get_repository_identifier(
            "codecommit", region=region, repo=repo
        )

        query = session.query(RepositoryScanResult).filter_by(
            repo_type="codecommit",
            status="completed",
            repo_identifier=repo_identifier,
        )

        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)

        # Get latest analysis result
        result = query.order_by(desc(RepositoryScanResult.timestamp)).first()

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

        logger.info(f"CodeCommit Reranked data type: {type(reranked_data)}")

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
            f"Found CodeCommit findings to process: {len(findings_to_process) if findings_to_process else 0}"
        )

        # Add ignore status if user_id is provided and we have findings
        if user_id and findings_to_process:
            repo_name = repo_identifier
            logger.info(
                f"Adding ignore status for {len(findings_to_process)} CodeCommit findings"
            )

            # Process findings with ignore status
            processed_findings = add_ignore_status_to_findings(
                user_id, repo_name, findings_to_process, workspace_id, "codecommit"
            )

            # Add fix status to findings
            logger.info(
                f"Adding fix status for {len(processed_findings)} CodeCommit findings"
            )
            processed_findings = add_fix_status_to_findings(
                user_id,
                repo_identifier,
                processed_findings,
                workspace_id,
                "codecommit",
                session,
            )

            # Count ignored findings
            ignored_count = sum(
                1 for f in processed_findings if f.get("ignored", False)
            )
            logger.info(
                f"Processed CodeCommit findings: {len(processed_findings)}, ignored: {ignored_count}"
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
                        # If no suitable key found, add as 'findings'
                        reranked_data["findings"] = processed_findings

                # Update metadata
                if "metadata" not in reranked_data:
                    reranked_data["metadata"] = {}
                reranked_data["metadata"]["ignore_support"] = True
                reranked_data["metadata"]["user_id"] = user_id
                reranked_data["metadata"]["platform"] = "codecommit"

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
                    "metadata": {
                        "ignore_support": True,
                        "user_id": user_id,
                        "platform": "codecommit",
                    },
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
            f"Final CodeCommit response structure: {list(reranked_data.keys()) if isinstance(reranked_data, dict) else type(reranked_data)}"
        )
        return jsonify(reranked_data)

    except Exception as e:
        logger.error(
            f"Error getting CodeCommit reranked findings: {str(e)}", exc_info=True
        )
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


@codecommit_bp.route("/get-branches", methods=["POST"])
def get_codecommit_repository_branches():
    """Get all branches for an AWS CodeCommit repository"""

    async def get_branches_async():
        # Get data from POST request body
        request_data = request.get_json()
        if not request_data:
            return (
                {"success": False, "error": {"message": "Request body is required"}},
                400,
            )

        # Get required parameters from request body
        repo_name = request_data.get("repo_name")
        region = request_data.get("region")
        aws_access_key_id = request_data.get("aws_access_key_id")
        aws_secret_access_key = request_data.get("aws_secret_access_key")

        # Validate required parameters
        required_params = {
            "repo_name": repo_name,
            "region": region,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
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

        try:
            # Create boto3 client for CodeCommit
            import boto3

            codecommit_client = boto3.client(
                "codecommit",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )

            # Get repository metadata to find default branch
            repo_metadata = codecommit_client.get_repository(repositoryName=repo_name)
            default_branch = repo_metadata.get("repositoryMetadata", {}).get(
                "defaultBranch", "main"
            )

            # Get all branches
            branches_response = codecommit_client.list_branches(
                repositoryName=repo_name
            )
            branch_names = branches_response.get("branches", [])

            # Filter out branches that start with 'rezliant-fix' prefix
            branch_names = [b for b in branch_names if not b.startswith("rezliant-fix")]

            # Check if 'rezliant' branch exists, if not create it from default branch
            if "rezliant" not in branch_names:
                logger.info(
                    f"'rezliant' branch not found, creating it from {default_branch}"
                )

                try:
                    # Get the latest commit ID from default branch
                    default_branch_response = codecommit_client.get_branch(
                        repositoryName=repo_name, branchName=default_branch
                    )
                    commit_id = default_branch_response["branch"]["commitId"]

                    # Create the rezliant branch
                    codecommit_client.create_branch(
                        repositoryName=repo_name,
                        branchName="rezliant",
                        commitId=commit_id,
                    )

                    logger.info(f"Successfully created 'rezliant' branch")
                    branch_names.append("rezliant")
                except Exception as create_error:
                    logger.warning(
                        f"Failed to create 'rezliant' branch: {str(create_error)}"
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
                    "name": branch_name,
                    "isDefault": branch_name == default_branch,
                }
                for branch_name in branch_names
            ]

            # Sort branches by priority
            branches.sort(
                key=lambda b: (
                    get_branch_priority(b["name"], default_branch),
                    b["name"],
                )
            )

            logger.info(
                f"Retrieved {len(branches)} branches for CodeCommit repo: {repo_name}"
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

        except Exception as e:
            logger.error(f"Error fetching CodeCommit branches: {str(e)}")
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


@codecommit_bp.route("/create-pr", methods=["POST"])
def create_codecommit_pull_request():
    """Create a pull request with the fixed file content for AWS CodeCommit"""

    def ensure_webhook_exists(
        repo_name, region, aws_access_key_id, aws_secret_access_key
    ):
        """
        Checks if an EventBridge notification rule exists for PR events and creates one if it doesn't.
        Returns a tuple of (webhook_enabled: bool, webhook_url: str or None, error_message: str or None)
        """
        try:
            import boto3
            import json

            # Get webhook base URL from environment variable
            webhook_base_url = os.getenv("WEBHOOK_BASE_URL")
            if not webhook_base_url:
                logger.info(
                    "WEBHOOK_BASE_URL environment variable not set, skipping webhook creation"
                )
                return (False, None, "WEBHOOK_BASE_URL not configured")

            webhook_url = f"{webhook_base_url}/api/v1/pr/webhook"

            # Get webhook credentials for basic auth
            webhook_username = os.getenv("CODECOMMIT_WEBHOOK_USERNAME")
            webhook_password = os.getenv("CODECOMMIT_WEBHOOK_PASSWORD")

            if not webhook_username:
                logger.info(
                    "CODECOMMIT_WEBHOOK_USERNAME not set, skipping webhook creation for security"
                )
                return (False, None, "CODECOMMIT_WEBHOOK_USERNAME not configured")

            if not webhook_password:
                logger.info(
                    "CODECOMMIT_WEBHOOK_PASSWORD not set, skipping webhook creation for security"
                )
                return (False, None, "CODECOMMIT_WEBHOOK_PASSWORD not configured")

            # Create boto3 clients
            codecommit_client = boto3.client(
                "codecommit",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )

            events_client = boto3.client(
                "events",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )

            sns_client = boto3.client(
                "sns",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )

            # Get repository ARN
            repo_metadata = codecommit_client.get_repository(repositoryName=repo_name)
            repo_arn = repo_metadata["repositoryMetadata"]["Arn"]
            account_id = repo_arn.split(":")[4]

            # Define notification rule name
            notification_rule_name = f"rezliant-pr-events-{repo_name}"

            # Check if notification rule already exists
            notification_rule_exists = False
            try:
                codestar_client = boto3.client(
                    "codestar-notifications",
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key,
                )

                # List notification rules for this repository
                list_response = codestar_client.list_notification_rules()
                existing_rules = list_response.get("NotificationRules", [])

                # Check if our rule already exists
                for rule in existing_rules:
                    rule_details = codestar_client.describe_notification_rule(
                        Arn=rule["Arn"]
                    )
                    if rule_details.get(
                        "Resource"
                    ) == repo_arn and notification_rule_name in rule_details.get(
                        "Name", ""
                    ):
                        logger.info(
                            f"Notification rule already exists for repository {repo_name}"
                        )
                        notification_rule_exists = True
                        break

            except Exception as check_error:
                logger.warning(
                    f"Could not check existing notification rules: {str(check_error)}"
                )

            # Create SNS topic for webhook
            topic_name = f"rezliant-codecommit-pr-events-{repo_name}"
            try:
                topic_response = sns_client.create_topic(Name=topic_name)
                topic_arn = topic_response["TopicArn"]
                logger.info(f"Created SNS topic: {topic_arn}")

                # Set access policy to allow CodeStar Notifications to publish
                policy = {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Sid": "CodeStarNotification_publish",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "codestar-notifications.amazonaws.com"
                            },
                            "Action": "SNS:Publish",
                            "Resource": topic_arn,
                        }
                    ],
                }

                sns_client.set_topic_attributes(
                    TopicArn=topic_arn,
                    AttributeName="Policy",
                    AttributeValue=json.dumps(policy),
                )
                logger.info(f"Set SNS topic policy to allow CodeStar Notifications")

                # Check existing subscriptions to see if webhook URL already exists
                subscriptions = sns_client.list_subscriptions_by_topic(
                    TopicArn=topic_arn
                )
                existing_webhook_subscription = None
                webhook_subscription_exists = False

                for sub in subscriptions.get("Subscriptions", []):
                    if sub["Protocol"] == "https":
                        if sub["Endpoint"] == webhook_url:
                            webhook_subscription_exists = True
                            existing_webhook_subscription = sub
                            logger.info(
                                f"Webhook subscription already exists with correct URL: {webhook_url}"
                            )
                            break

                # Only create a new subscription if the current webhook URL doesn't exist
                if not webhook_subscription_exists:
                    logger.info(
                        f"Creating new webhook subscription for URL: {webhook_url}"
                    )
                    subscription_response = sns_client.subscribe(
                        TopicArn=topic_arn,
                        Protocol="https",
                        Endpoint=webhook_url,
                        ReturnSubscriptionArn=True,
                    )
                    subscription_arn = subscription_response["SubscriptionArn"]
                    logger.info(f"Created SNS subscription: {subscription_arn}")

                    # Set subscription attributes for authentication
                    if webhook_username and webhook_password:
                        # Note: SNS doesn't directly support basic auth, but we can use attributes
                        # The webhook endpoint will need to validate the SNS signature instead
                        logger.info(
                            "SNS subscription created (auth handled via SNS signature)"
                        )
                else:
                    logger.info("Using existing webhook subscription")

            except sns_client.exceptions.TopicLimitExceededException:
                # Topic might already exist, try to get it
                topics = sns_client.list_topics()
                topic_arn = None
                for topic in topics.get("Topics", []):
                    if topic_name in topic["TopicArn"]:
                        topic_arn = topic["TopicArn"]
                        break
                if not topic_arn:
                    raise

                # Update policy on existing topic
                logger.info(f"Topic already exists: {topic_arn}, updating policy")
                policy = {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Sid": "CodeStarNotification_publish",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "codestar-notifications.amazonaws.com"
                            },
                            "Action": "SNS:Publish",
                            "Resource": topic_arn,
                        }
                    ],
                }

                sns_client.set_topic_attributes(
                    TopicArn=topic_arn,
                    AttributeName="Policy",
                    AttributeValue=json.dumps(policy),
                )
                logger.info(f"Updated SNS topic policy to allow CodeStar Notifications")

                # Check existing subscriptions to see if webhook URL already exists
                subscriptions = sns_client.list_subscriptions_by_topic(
                    TopicArn=topic_arn
                )
                existing_webhook_subscription = None
                webhook_subscription_exists = False

                for sub in subscriptions.get("Subscriptions", []):
                    if sub["Protocol"] == "https":
                        if sub["Endpoint"] == webhook_url:
                            webhook_subscription_exists = True
                            existing_webhook_subscription = sub
                            logger.info(
                                f"Webhook subscription already exists with correct URL: {webhook_url}"
                            )
                            break

                # Only create a new subscription if the current webhook URL doesn't exist
                if not webhook_subscription_exists:
                    logger.info(
                        f"Creating new webhook subscription for existing topic with URL: {webhook_url}"
                    )
                    subscription_response = sns_client.subscribe(
                        TopicArn=topic_arn,
                        Protocol="https",
                        Endpoint=webhook_url,
                        ReturnSubscriptionArn=True,
                    )
                    subscription_arn = subscription_response["SubscriptionArn"]
                    logger.info(f"Created SNS subscription: {subscription_arn}")
                else:
                    logger.info("Using existing webhook subscription on existing topic")

            # Create notification rule using AWS CodeStar Notifications (only if it doesn't exist)
            if not notification_rule_exists:
                try:
                    notification_response = codestar_client.create_notification_rule(
                        Name=notification_rule_name,
                        EventTypeIds=[
                            "codecommit-repository-pull-request-status-changed",
                            "codecommit-repository-pull-request-merged",
                        ],
                        Resource=repo_arn,
                        Targets=[
                            {
                                "TargetType": "SNS",
                                "TargetAddress": topic_arn,
                            }
                        ],
                        DetailType="FULL",
                        Status="ENABLED",
                    )

                    logger.info(
                        f"Notification rule created successfully: {notification_response['Arn']}"
                    )

                except Exception as notification_error:
                    logger.warning(
                        f"Failed to create notification rule: {str(notification_error)}"
                    )
                    return (
                        False,
                        None,
                        f"Failed to create notification rule: {str(notification_error)}",
                    )
            else:
                logger.info(f"Notification rule already exists, skipping creation")

            # Return success after ensuring webhook subscription exists
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
        repo_name = request_data.get("repo_name")
        region = request_data.get("region")
        base_branch = request_data.get("base_branch")
        temp_file_path = request_data.get("file_path")
        aws_access_key_id = request_data.get("aws_access_key_id")
        aws_secret_access_key = request_data.get("aws_secret_access_key")
        file_content = request_data.get("file_content")

        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")
        finding_id = request_data.get("finding_id")
        line_number = request_data.get("line_number")
        cwe_id = request_data.get("cwe_id")
        severity = request_data.get("severity")

        file_path = extract_clean_file_path(temp_file_path)

        # Optional parameters with defaults
        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_branch_name = f"rezliant-fix/{file_path.replace('/', '-')}-{timestamp}"
        new_branch = request_data.get("new_branch", default_branch_name)
        commit_message = request_data.get(
            "commit_message", f"Fix vulnerability in {file_path}"
        )
        pr_title = request_data.get(
            "pr_title", f"Fix: Security vulnerability in {file_path}"
        )
        pr_description = request_data.get(
            "pr_body", f"This PR fixes a security vulnerability in {file_path}"
        )

        # Validate required parameters
        required_params = {
            "repo_name": repo_name,
            "region": region,
            "file_path": file_path,
            "file_content": file_content,
            "aws_access_key_id": aws_access_key_id,
            "aws_secret_access_key": aws_secret_access_key,
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

        try:
            import boto3

            # Create boto3 client for CodeCommit
            codecommit_client = boto3.client(
                "codecommit",
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )

            # Step 1: Get repository metadata and default branch if base_branch not provided
            repo_metadata = codecommit_client.get_repository(repositoryName=repo_name)
            default_branch = repo_metadata.get("repositoryMetadata", {}).get(
                "defaultBranch", "main"
            )

            # If base_branch is provided, validate it exists; otherwise use default
            if base_branch:
                try:
                    codecommit_client.get_branch(
                        repositoryName=repo_name, branchName=base_branch
                    )
                except:
                    logger.warning(
                        f"Base branch '{base_branch}' not found, using default branch '{default_branch}'"
                    )
                    base_branch = default_branch
            else:
                base_branch = default_branch

            logger.info(f"Using base branch: {base_branch}")

            # Step 2: Get the reference to the base branch
            base_branch_info = codecommit_client.get_branch(
                repositoryName=repo_name, branchName=base_branch
            )
            base_commit_id = base_branch_info["branch"]["commitId"]
            logger.info(f"Base branch commit ID: {base_commit_id}")

            # Step 3: Create a new branch from the base branch
            try:
                codecommit_client.create_branch(
                    repositoryName=repo_name,
                    branchName=new_branch,
                    commitId=base_commit_id,
                )
                logger.info(f"Created new branch: {new_branch}")
            except Exception as branch_error:
                # Branch might already exist
                if "already exists" in str(branch_error).lower():
                    logger.warning(
                        f"Branch '{new_branch}' already exists, will update it"
                    )
                else:
                    return (
                        {
                            "success": False,
                            "error": {
                                "message": f"Failed to create new branch: {str(branch_error)}"
                            },
                        },
                        500,
                    )

            # Step 4: Get the latest commit ID for the new branch
            new_branch_info = codecommit_client.get_branch(
                repositoryName=repo_name, branchName=new_branch
            )
            parent_commit_id = new_branch_info["branch"]["commitId"]
            logger.info(f"New branch commit ID: {parent_commit_id}")

            # Step 5: Create a commit with the file change
            put_file_response = codecommit_client.put_file(
                repositoryName=repo_name,
                branchName=new_branch,
                fileContent=file_content.encode("utf-8"),
                filePath=file_path,
                parentCommitId=parent_commit_id,
                commitMessage=commit_message,
                name="Rezliant Security Bot",
                email="security@rezliant.com",
            )

            logger.info(f"File committed successfully to branch {new_branch}")

            # Step 6: Create a pull request
            pr_response = codecommit_client.create_pull_request(
                title=pr_title,
                description=pr_description,
                targets=[
                    {
                        "repositoryName": repo_name,
                        "sourceReference": new_branch,
                        "destinationReference": base_branch,
                    }
                ],
            )

            pr_data = pr_response["pullRequest"]
            pr_id = pr_data["pullRequestId"]
            pr_number = str(pr_id)

            # Construct PR URL
            pr_url = f"https://{region}.console.aws.amazon.com/codesuite/codecommit/repositories/{repo_name}/pull-requests/{pr_id}"

            logger.info(f"Pull request created: {pr_url}")

            # Ensure webhook exists for PR status events
            webhook_enabled = False
            webhook_url_result = None
            webhook_error = None

            try:
                logger.info("Checking/creating webhook for CodeCommit PR events")
                webhook_enabled, webhook_url_result, webhook_error = (
                    ensure_webhook_exists(
                        repo_name, region, aws_access_key_id, aws_secret_access_key
                    )
                )

                if webhook_enabled:
                    logger.info(
                        f"Webhook successfully configured for repository {repo_name}"
                    )
                else:
                    logger.warning(
                        f"Webhook not configured for repository {repo_name}: {webhook_error}"
                    )
            except Exception as webhook_exc:
                logger.error(
                    f"Error setting up webhook: {str(webhook_exc)}", exc_info=True
                )
                webhook_error = str(webhook_exc)

            # Create fix request record if tracking parameters were provided
            if user_id and finding_id:
                try:
                    # Create database session for fix request
                    fix_engine = create_api_engine()
                    FixSession = sessionmaker(bind=fix_engine)
                    fix_session = FixSession()

                    try:
                        # Build repo identifier (CodeCommit format)
                        repo_identifier = f"https://git-codecommit.{region}.amazonaws.com/v1/repos/{repo_name}"

                        # Create fix request with separate fields
                        fix_request = FixRequest(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            repo_type="codecommit",
                            repo_identifier=repo_identifier,
                            branch_name=base_branch or "main",
                            finding_id=finding_id,
                            file_path=file_path,
                            line_start=line_number,  # Use line_number from request
                            cwe_id=cwe_id,
                            severity=severity,
                            pr_url=pr_url,
                            pr_number=pr_number,
                            pr_title=pr_data.get("title"),
                            status="pr_created",
                            fix_description=f"Automated fix for {file_path}",
                            pr_created_at=datetime.now(timezone.utc),
                            webhook_url=webhook_url_result,
                        )

                        fix_session.add(fix_request)
                        fix_session.commit()

                        logger.info(
                            f"Created fix request {fix_request.id} for finding {finding_id} with webhook_url={webhook_url_result}"
                        )
                    finally:
                        fix_session.close()
                        fix_engine.dispose()
                except Exception as fix_err:
                    logger.error(
                        f"Failed to create fix request: {str(fix_err)}", exc_info=True
                    )
                    # Don't fail the PR creation if fix request fails

            return (
                {
                    "success": True,
                    "data": {
                        "pullRequest": {
                            "id": pr_id,
                            "url": pr_url,
                            "title": pr_data.get("title"),
                            "branch": new_branch,
                            "baseBranch": base_branch,
                        },
                        "webhook": {
                            "enabled": webhook_enabled,
                            "url": webhook_url_result,
                            "error": webhook_error,
                        },
                    },
                },
                200,
            )

        except Exception as e:
            logger.error(f"Error creating CodeCommit pull request: {str(e)}")
            import traceback

            logger.error(traceback.format_exc())
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
