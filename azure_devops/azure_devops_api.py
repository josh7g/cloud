from flask import Blueprint, jsonify, request
from .utils import (
    logger,
    ScanAzureDevopsRepoModel,
    GetAzureDevopsFileModel,
    stringify_pydantic_error,
    create_api_engine,
    get_api_error_format_dict,
    create_secure_client_session,
    validate_workspace_id,
    get_latest_commit_sha,
    get_changed_files_between_commits,
    create_auth_header,
)
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc
from models import AzureDevOpsAnalysisResult, IgnoredFinding
from collections import defaultdict
import asyncio
from datetime import datetime, timezone
from .azure_devops_scanner import (
    scan_azure_devops_repo,
    get_full_file_content_with_details,
)
from ignore_utils import (
    add_ignore_status_to_findings,
    create_azure_devops_ignore_record,
    remove_azure_devops_ignore_record,
    normalize_file_path,
)
from fix_utils import add_fix_status_to_findings
from urllib.parse import unquote
from utils import extract_clean_file_path, get_repository_identifier
import json
import os

azure_devops_bp = Blueprint("azure_devops", __name__, url_prefix="/api/v1/azure-devops")


@azure_devops_bp.route("/scan", methods=["POST"])
def trigger_azure_devops_repository_scan():
    """
    Trigger a semgrep scan for an Azure Devops repo with incremental scanning support.

    INCREMENTAL SCANNING:
    1. NEW SCAN: If no previous analysis exists → Create new analysis record + Full scan of all files
    2. NO CHANGES: If same commit SHA as last scan → Skip scan with incremental progress updates, keep existing findings
    3. FILES CHANGED: If different commit SHA → Reuse existing analysis record + Incremental scan of changed files + merge with existing findings

    DATABASE RECORD HANDLING:
    - Creates new AzureDevOpsAnalysisResult record only for new scans (no previous analysis)
    - Reuses existing record for skip scenarios and incremental scans
    - Updates existing record with merged findings for incremental scans
    - Tracks commit SHA for future incremental scans

    Args:
        PAT (str, optional): Personal Access Token for authentication
        access_token (str, optional): OAuth access token for authentication
        organization_name (str): The Azure Devops organization where the repo is located
        project (str): The Azure Devops project where the repo is location
        repo (str): The name of the repo
        user_id (str): The id of the logged in user

    Note: Either PAT or access_token must be provided, but not both.
    """
    from app import socketio
    import time

    try:
        data = ScanAzureDevopsRepoModel(**request.json).model_dump()
        user_id = data["user_id"]
        repo = data["repo"]
        owner = data["organization_name"]
        project = data["project"]
        workspace_id = data["workspace_id"]
        repo_name = f"{owner}/{repo}"
        PAT = data.get("PAT")
        access_token = data.get("access_token")
        files_to_scan = None
        previous_sha = None
        latest_sha = None
        branch_name = None

        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Look up the last completed analysis for this repo/branch/workspace
        last_scan = (
            db_session.query(AzureDevOpsAnalysisResult)
            .filter(
                AzureDevOpsAnalysisResult.organization_name == owner,
                AzureDevOpsAnalysisResult.project_name == project,
                AzureDevOpsAnalysisResult.repository_name == repo,
                AzureDevOpsAnalysisResult.status == "completed",
                AzureDevOpsAnalysisResult.workspace_id == workspace_id,
            )
            .order_by(desc(AzureDevOpsAnalysisResult.timestamp))
            .first()
        )

        previous_sha = None
        previous_findings = []
        branch_name = None

        if last_scan:
            previous_sha = last_scan.results.get("metadata", {}).get(
                "scanned_commit_sha"
            ) or getattr(last_scan, "scanned_commit_sha", None)
            branch_name = last_scan.results.get("metadata", {}).get("branch_name")
            if last_scan.results and "findings" in last_scan.results:
                previous_findings = last_scan.results["findings"]
            logger.info(
                f"Previous scan found for {repo_name}, commit SHA: {previous_sha}"
            )

        # Get the latest commit SHA (use API)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        latest_sha = loop.run_until_complete(
            get_latest_commit_sha(
                owner,
                project,
                repo,
                PAT=PAT,
                access_token=access_token,
                branch_name=branch_name,
            )
        )

        # Determine scan strategy based on commit comparison
        scan_strategy = "full"  # Default to full scan
        files_to_scan = None

        if not previous_sha:
            # Scenario 1: New scan (no previous analysis)
            scan_strategy = "full"
            logger.critical(
                f"*** URGENT: New Azure DevOps scan for {repo_name} - no previous analysis found"
            )
            logger.debug(
                f"Azure DevOps new scan details: org={owner}, project={project}, repo={repo}"
            )
        elif previous_sha == latest_sha:
            # Scenario 2: No changes (same commit SHA) - skip scan
            scan_strategy = "skip"
            logger.critical(
                f"*** URGENT: No new commits detected for Azure DevOps {repo_name} at {latest_sha}, skipping scan"
            )
            logger.debug(
                f"Azure DevOps skip scan details: previous_sha={previous_sha}, latest_sha={latest_sha}"
            )
        else:
            # Scenario 3: Files changed - incremental scan
            scan_strategy = "incremental"
            logger.critical(
                f"*** URGENT: Azure DevOps incremental scan triggered for {repo_name} - commits differ"
            )
            logger.debug(
                f"Azure DevOps incremental scan details: previous_sha={previous_sha}, latest_sha={latest_sha}"
            )
            try:
                files_to_scan = loop.run_until_complete(
                    get_changed_files_between_commits(
                        owner,
                        project,
                        repo,
                        previous_sha,
                        latest_sha,
                        PAT=PAT,
                        access_token=access_token,
                    )
                )
                if not files_to_scan:
                    logger.warning(
                        "No changed files detected by Azure DevOps API, falling back to full scan"
                    )
                    scan_strategy = "full"
                    files_to_scan = None
                else:
                    logger.critical(
                        f"*** URGENT: Found {len(files_to_scan)} changed files for Azure DevOps incremental scan"
                    )
                    logger.debug(
                        f"Azure DevOps changed files: {files_to_scan[:10]}{'...' if len(files_to_scan) > 10 else ''}"
                    )
            except Exception as e:
                logger.warning(
                    f"Could not get changed files from Azure DevOps API: {e} - falling back to full scan"
                )
                scan_strategy = "full"
                files_to_scan = None

        loop.close()

        # Create or get analysis record
        if scan_strategy == "skip":
            azure_analysis = last_scan
            logger.critical(
                f"*** URGENT: Azure DevOps skip scan reusing existing record ID: {azure_analysis.id}"
            )
            logger.debug(
                f"Azure DevOps skip record details: status={azure_analysis.status}, timestamp={azure_analysis.timestamp}"
            )
        elif scan_strategy == "incremental" and last_scan:
            azure_analysis = last_scan
            logger.critical(
                f"*** URGENT: Azure DevOps incremental scan reusing existing record ID: {azure_analysis.id}"
            )
            logger.debug(
                f"Azure DevOps incremental record details: status={azure_analysis.status}, previous_sha={previous_sha}"
            )
        else:
            azure_analysis = AzureDevOpsAnalysisResult(
                organization_name=owner,
                project_name=project,
                repository_name=repo,
                user_id=user_id,
                workspace_id=workspace_id,
                status="pending",
                timestamp=datetime.utcnow(),
            )
            db_session.add(azure_analysis)
            db_session.commit()
            logger.critical(
                f"*** URGENT: Azure DevOps new scan created record ID: {azure_analysis.id}"
            )
            logger.debug(
                f"Azure DevOps new record details: org={owner}, project={project}, repo={repo}, workspace={workspace_id}"
            )

        # Clear both progress AND completion cache for this repo (like GitHub does)
        from progress_tracking import get_redis_client

        redis_client = get_redis_client()

        # Define keys
        completion_key = f"scan_complete:{user_id}:{repo_name}"
        progress_key = f"scan_progress:{user_id}:{repo_name}"

        # Delete cached data
        redis_client.delete(completion_key)
        redis_client.delete(progress_key)
        logger.info(f"Cleared previous Azure DevOps scan data for {repo_name}")

        # Send a reset message to all subscribers (like GitHub does)
        reset_data = {
            "s": "reset",
            "p": 0,
            "o": 0,
            "t": int(time.time()),
            "id": f"scan_{int(time.time())}",
        }

        room = f"scan_{user_id}_{repo_name}"
        socketio.emit("progress_update", reset_data, room=room)
        logger.info(f"Sent Azure DevOps reset signal to room {room}")
        print(f"🔄 Sent reset signal to WebSocket room: {room}")

        from progress_tracking import update_scan_progress

        # Initialize progress tracking (like GitHub does)
        from progress_tracking import clear_scan_progress

        clear_scan_progress(user_id, repo_name)
        update_scan_progress(user_id, repo_name, "initializing", 5)

        def run_scan_in_background():
            try:
                # no changes detected
                if scan_strategy == "skip":
                    logger.critical(
                        f"*** URGENT: Azure DevOps skip scan starting for {repo_name} - no new commits detected"
                    )
                    logger.debug(
                        f"Azure DevOps skip scan details: latest_sha={latest_sha}, record_id={azure_analysis.id}"
                    )

                    update_scan_progress(user_id, repo_name, "checking_changes", 20)
                    logger.debug(f"Azure DevOps skip progress: 20% - checking changes")
                    time.sleep(0.5)

                    update_scan_progress(user_id, repo_name, "no_changes_detected", 50)
                    logger.debug(
                        f"Azure DevOps skip progress: 50% - no changes detected"
                    )
                    time.sleep(0.5)

                    update_scan_progress(user_id, repo_name, "updating_metadata", 80)
                    logger.debug(f"Azure DevOps skip progress: 80% - updating metadata")
                    time.sleep(0.5)

                    azure_analysis.status = "completed"
                    azure_analysis.results = (
                        last_scan.results
                        if last_scan
                        else {"findings": [], "stats": {}, "metadata": {}}
                    )
                    azure_analysis.rerank = last_scan.rerank if last_scan else []
                    azure_analysis.scanned_commit_sha = latest_sha
                    db_session.commit()

                    update_scan_progress(user_id, repo_name, "completed", 100)
                    logger.critical(
                        f"*** URGENT: Azure DevOps skip scan completed for {repo_name} - no changes detected"
                    )
                    logger.debug(
                        f"Azure DevOps skip completion: record_id={azure_analysis.id}, commit_sha={latest_sha}"
                    )
                    return

                azure_analysis.status = "in_progress"
                db_session.commit()
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                scan_result = loop.run_until_complete(
                    scan_azure_devops_repo(
                        PAT,
                        access_token,
                        owner,
                        project,
                        repo,
                        user_id,
                        db_session,
                        azure_analysis,
                        multi_scan=True,
                        files_to_scan=files_to_scan,
                        previous_findings=previous_findings,
                        current_commit_sha=latest_sha,
                    )
                )

                # After scan, save the `latest_sha` in db for this result
                if scan_result and scan_result.get("success"):
                    if hasattr(azure_analysis, "scanned_commit_sha"):
                        azure_analysis.scanned_commit_sha = latest_sha
                    if "metadata" not in scan_result["data"]:
                        scan_result["data"]["metadata"] = {}
                    scan_result["data"]["metadata"]["scanned_commit_sha"] = latest_sha
                    scan_result["data"]["metadata"]["branch_name"] = branch_name
                    scan_result["data"]["metadata"]["scan_strategy"] = scan_strategy
                    azure_analysis.results = scan_result["data"]
                    db_session.commit()
                    logger.critical(
                        f"*** URGENT: Azure DevOps {scan_strategy} scan completed successfully for {repo_name}"
                    )
                    logger.debug(
                        f"Azure DevOps scan completion: record_id={azure_analysis.id}, commit_sha={latest_sha}, strategy={scan_strategy}"
                    )
                loop.close()
            except Exception as e:
                logger.error(f"Background scan error: {str(e)}")
                azure_analysis.status = "error"
                azure_analysis.error = str(e)
                update_scan_progress(user_id, repo_name, "error", 100)
                db_session.commit()

        from threading import Thread

        thread = Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Scan queued successfully",
                    "scan_id": azure_analysis.id,
                    "status": "queued",
                    "repository": repo_name,
                }
            ),
            202,
        )
    except ValidationError as error:
        return (
            jsonify(
                get_api_error_format_dict(
                    f"Validation error: {stringify_pydantic_error(error)}",
                    "INVALID_PARAMETERS",
                )
            ),
            400,
        )
    except Exception as e:
        logger.error(f"Scan initialization error: {str(e)}")
        return (
            jsonify(get_api_error_format_dict(str(e), "SCAN_ERROR")),
            400,
        )


@azure_devops_bp.route("/files", methods=["POST"])
def get_azure_devops_file():
    """Fetch file content from Azure DevOps using POST with all parameters in request body"""

    try:
        if not request.get_json():
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        data = GetAzureDevopsFileModel(**request.get_json()).model_dump()

    except ValidationError as error:
        return (
            jsonify(
                get_api_error_format_dict(
                    f"Validation error: {stringify_pydantic_error(error)}",
                    "INVALID_PARAMETERS",
                )
            ),
            400,
        )

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:

            async def fetch_file_content():
                async with create_secure_client_session() as session:
                    result = await get_full_file_content_with_details(
                        session=session,
                        organization_name=data["organization_name"],
                        project_name=data["project"],
                        repo_name=data["repo"],
                        file_path=extract_clean_file_path(data["file_name"]),
                        PAT=data.get("PAT"),
                        access_token=data.get("access_token"),
                    )
                    return result

            result = loop.run_until_complete(fetch_file_content())

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

            return jsonify(
                {
                    "success": True,
                    "data": {
                        "file": result.get("content"),
                        "user_id": data["user_id"],
                        "version": "latest",  # Azure DevOps doesn't provide commit SHA in this context
                        "reponame": f"{data['organization_name']}/{data['project']}/{data['repo']}",
                        "filename": unquote(data["file_name"]),
                    },
                }
            )
        finally:
            loop.close()

    except Exception as e:
        logger.error(f"Azure DevOps API error: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@azure_devops_bp.route(
    "/analysis/<organization_name>/<project>/<repo>/result", methods=["GET"]
)
def get_azure_devops_analysis_findings(organization_name: str, project: str, repo: str):
    """Get Azure DevOps analysis findings with ignore status included and adjusted severity counts"""
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
        user_id = request.args.get("user_id")  # Add user_id parameter for ignore status
        workspace_id = request.args.get("workspace_id")  # NEW: Add workspace_id filter

        query = db_session.query(AzureDevOpsAnalysisResult).filter_by(
            organization_name=organization_name,
            project_name=project,
            repository_name=repo,
        )

        if workspace_id:
            query = query.filter_by(workspace_id=workspace_id)
            logger.info(f"Filtering analysis results by workspace_id: {workspace_id}")

        # Apply user filtering if provided (fallback for compatibility)
        if user_id and not workspace_id:
            query = query.filter_by(user_id=user_id)
            logger.info(
                f"Filtering analysis results by user_id: {user_id} (no workspace filter)"
            )
        # Get latest analysis result
        result = query.order_by(desc(AzureDevOpsAnalysisResult.timestamp)).first()

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

        repo_name = f"{organization_name}/{project}/{repo}"
        repo_identifier = get_repository_identifier(
            "azure_devops", org=organization_name, project=project, repo=repo
        )

        # Add ignore status to findings if user_id is provided
        if user_id and findings:
            findings = add_ignore_status_to_findings(
                user_id, repo_name, findings, workspace_id, "azure-devops"
            )
            # Add fix status to findings
            findings = add_fix_status_to_findings(
                user_id,
                repo_identifier,
                findings,
                workspace_id,
                "azure_devops",
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
                severity_level = finding.get("severity", "LOW").upper()

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
                    "repository": {
                        "name": repo_name,
                        "organization": organization_name,
                        "project": project,
                        "repo": repo,
                    },
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
        logger.error(f"Error getting Azure DevOps findings: {str(e)}")
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


@azure_devops_bp.route("/scan/<organization_name>/<project>/<repo>", methods=["DELETE"])
def delete_azure_devops_scan_results(organization_name: str, project: str, repo: str):
    """Delete Azure DevOps scan results for a specific repository"""
    engine = None
    db_session = None
    try:
        repo_name = f"{organization_name}/{project}/{repo}"
        logger.info(
            f"[Azure DevOps] Starting delete request for repository: {repo_name}"
        )

        # Get user_id from query parameter or request body
        user_id = request.args.get("user_id") or (request.get_json() or {}).get(
            "user_id"
        )

        logger.info(
            f"[Azure DevOps] Delete request - organization: {organization_name}, project: {project}, repo: {repo}, user_id: {user_id}"
        )

        if not user_id:
            logger.warning(
                f"[Azure DevOps] Delete request failed - missing user_id for repo: {repo_name}"
            )
            return (
                jsonify(
                    {"success": False, "error": {"message": "user_id is required"}}
                ),
                400,
            )

        # Create engine using the new function
        logger.info(f"[Azure DevOps] Creating database connection for delete operation")
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get all analyses for this repository
        logger.info(
            f"[Azure DevOps] Querying analyses for repository: {repo_name}, user_id: {user_id}"
        )
        analyses = (
            db_session.query(AzureDevOpsAnalysisResult)
            .filter(
                AzureDevOpsAnalysisResult.organization_name == organization_name,
                AzureDevOpsAnalysisResult.project_name == project,
                AzureDevOpsAnalysisResult.repository_name == repo,
                AzureDevOpsAnalysisResult.user_id == user_id,
            )
            .all()
        )

        logger.info(
            f"[Azure DevOps] Found {len(analyses)} analyses to delete for repository: {repo_name}"
        )

        # Even if no analyses, continue to remove any ignore records for this repo
        if not analyses:
            logger.info(
                f"[Azure DevOps] No analyses found for repository: {repo_name}, user_id: {user_id}"
            )
        else:
            # Log details about analyses being deleted
            for i, analysis in enumerate(analyses):
                logger.info(
                    f"[Azure DevOps] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                    f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                    f"Workspace ID: {analysis.workspace_id}"
                )

            # Delete all analyses
            logger.info(f"[Azure DevOps] Starting deletion of {len(analyses)} analyses")
            for analysis in analyses:
                db_session.delete(analysis)
                logger.debug(
                    f"[Azure DevOps] Marked analysis {analysis.id} for deletion"
                )

            logger.info(f"[Azure DevOps] Committing deletion transaction")
            db_session.commit()
            logger.info(
                f"[Azure DevOps] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
            )

        # Delete associated ignore records for this repo and user
        logger.info(
            f"[Azure DevOps] Removing ignore records for repo: {repo_name}, user_id: {user_id}"
        )
        ignore_query = (
            db_session.query(IgnoredFinding)
            .filter(IgnoredFinding.repo_name == repo_name)
            .filter(IgnoredFinding.user_id == user_id)
            .filter(IgnoredFinding.repo_type == "azure-devops")
        )
        ignore_records = ignore_query.all()
        logger.info(
            f"[Azure DevOps] Found {len(ignore_records)} ignore records to delete for repo: {repo_name}"
        )
        for record in ignore_records:
            db_session.delete(record)
        db_session.commit()
        logger.info(
            f"[Azure DevOps] Successfully deleted {len(ignore_records)} ignore records for repository: {repo_name}"
        )

        # Log details about analyses being deleted
        for i, analysis in enumerate(analyses):
            logger.info(
                f"[Azure DevOps] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                f"Workspace ID: {analysis.workspace_id}"
            )

        # Delete all analyses
        logger.info(f"[Azure DevOps] Starting deletion of {len(analyses)} analyses")
        for analysis in analyses:
            db_session.delete(analysis)
            logger.debug(f"[Azure DevOps] Marked analysis {analysis.id} for deletion")

        logger.info(f"[Azure DevOps] Committing deletion transaction")
        db_session.commit()
        logger.info(
            f"[Azure DevOps] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
        )

        return jsonify("DONE")

    except Exception as e:
        logger.error(
            f"[Azure DevOps] Error deleting scan results for repository {repo_name}: {str(e)}",
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
            logger.debug(f"[Azure DevOps] Closing database session")
            db_session.close()
        if engine:
            logger.debug(f"[Azure DevOps] Disposing database engine")
            engine.dispose()


@azure_devops_bp.route("/users/severity-counts", methods=["POST"])
def get_azure_devops_user_severity_counts():
    """Get severity counts for all Azure DevOps repositories for a user"""
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
        workspace_id = request_data.get("workspace_id")  # NEW: Accept workspace_id
        # Changed default to False - by default, don't include ignored findings in counts
        include_ignored = request_data.get("include_ignored", False)
        logger.info(
            f"Processing Azure DevOps severity counts for user_id: {user_id}, include_ignored: {include_ignored}"
        )

        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        print(workspace_id)
        print(request_data)
        print("\n\n\n\n")
        query = db_session.query(AzureDevOpsAnalysisResult).filter(
            AzureDevOpsAnalysisResult.status == "completed",
            AzureDevOpsAnalysisResult.results.isnot(None),
        )

        if workspace_id:
            query = query.filter(AzureDevOpsAnalysisResult.workspace_id == workspace_id)
            logger.info(f"Filtering by workspace_id: {workspace_id}")
        else:
            query = query.filter(AzureDevOpsAnalysisResult.user_id == user_id)

        # Get all completed analyses
        all_analyses = query.order_by(AzureDevOpsAnalysisResult.timestamp.desc()).all()
        logger.info(
            f"Found {len(all_analyses)} total Azure DevOps analyses after workspace filtering"
        )

        # Get latest analysis per repository
        latest_analyses = {}
        for analysis in all_analyses:
            repo_name = f"{analysis.organization_name}/{analysis.project_name}/{analysis.repository_name}"
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
                            "platform": "azure_devops",
                        },
                    },
                }
            )

        repository_data = {}
        # These counts represent ACTIVE findings only (unless include_ignored=True)
        total_severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        # Separate tracking for ignored findings (always tracked for transparency)
        total_ignored_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        total_findings = 0  # Active findings count
        total_ignored_findings = 0  # Always tracked separately
        latest_scan_time = None

        for repo_name, analysis in latest_analyses.items():
            results = analysis.results or {}

            # Get findings and add ignore status
            findings = results.get("findings", [])
            if findings:
                findings = add_ignore_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "azure-devops"
                )

            # Calculate severity counts
            repo_severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            repo_ignored_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}

            repo_total_findings = 0  # Active findings for this repo
            repo_ignored_findings = 0  # Ignored findings for this repo

            for finding in findings:
                severity = finding.get("severity", "INFO")
                is_ignored = finding.get("ignored", False)

                if is_ignored:
                    # Always track ignored findings separately
                    repo_ignored_counts[severity] += 1
                    total_ignored_counts[severity] += 1
                    repo_ignored_findings += 1
                    total_ignored_findings += 1

                    # Only include in main counts if explicitly requested
                    if include_ignored:
                        repo_severity_counts[severity] += 1
                        total_severity_counts[severity] += 1
                        repo_total_findings += 1
                        total_findings += 1
                else:
                    # Always count active findings
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
                "organization": analysis.organization_name,
                "project": analysis.project_name,
                "repo": analysis.repository_name,
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
                    "workspace_id": workspace_id,
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
                        "workspace_id": bool(workspace_id),
                        "platform": "azure_devops",
                    },
                },
            }
        )

    except Exception as e:
        logger.error(f"Error getting Azure DevOps severity counts: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@azure_devops_bp.route("/users/<user_id>/top-vulnerabilities", methods=["GET"])
def get_azure_devops_top_vulnerabilities(user_id):
    """Get top vulnerabilities across all Azure DevOps repositories for a user"""
    engine = None
    db_session = None
    try:
        # Get query parameters
        include_ignored = request.args.get("include_ignored", "true").lower() == "true"
        workspace_id = request.args.get("workspace_id")

        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        query = db_session.query(AzureDevOpsAnalysisResult).filter(
            AzureDevOpsAnalysisResult.status == "completed",
            AzureDevOpsAnalysisResult.results.isnot(None),
        )
        if workspace_id:
            query = query.filter(AzureDevOpsAnalysisResult.workspace_id == workspace_id)
            logger.info(
                f"Filtering top vulnerabilities by workspace_id: {workspace_id}"
            )
        else:
            query.filter(AzureDevOpsAnalysisResult.user_id == user_id)

        analyses = query.order_by(AzureDevOpsAnalysisResult.timestamp.desc()).all()
        logger.info(
            f"Found {len(analyses)} Azure DevOps analyses after workspace filtering"
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
                            "platform": "azure_devops",
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
            repo_name = analysis.repository_name
            analysis_workspace_id = analysis.workspace_id

            # Add ignore status to findings
            if findings:
                findings = add_ignore_status_to_findings(
                    user_id, repo_name, findings, workspace_id, "azure-devops"
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
                                "name": analysis.repository_name,
                                "organization": analysis.organization_name,
                                "project": analysis.project_name,
                                "full_name": f"{analysis.organization_name}/{analysis.project_name}/{repo_name}",
                                "analyzed_at": analysis.timestamp.isoformat(),
                                "workspace_id": analysis_workspace_id,
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
                        if analysis_workspace_id:
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
                        "platform": "azure_devops",
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


@azure_devops_bp.route(
    "/analysis/<organization_name>/<project>/<repo>/reranked", methods=["GET"]
)
def get_azure_devops_reranked_findings(organization_name: str, project: str, repo: str):
    """Get reranked findings for Azure DevOps repositories"""
    engine = None
    session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        # Get query parameters
        user_id = request.args.get("user_id")
        workspace_id = request.args.get("workspace_id")
        logger.info(
            f"Azure DevOps Reranked request: {organization_name}/{project}/{repo}, user_id={user_id}"
        )

        query = session.query(AzureDevOpsAnalysisResult).filter_by(
            status="completed",
            organization_name=organization_name,
            project_name=project,
            repository_name=repo,
            workspace_id=workspace_id,
        )

        # Get latest analysis result
        result = query.order_by(desc(AzureDevOpsAnalysisResult.timestamp)).first()

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

        logger.info(f"Azure DevOps Reranked data type: {type(reranked_data)}")

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
            f"Found Azure DevOps findings to process: {len(findings_to_process) if findings_to_process else 0}"
        )

        # Add ignore status if user_id is provided and we have findings
        if user_id and findings_to_process:
            repo_name = f"{organization_name}/{project}/{repo}"
            repo_identifier = get_repository_identifier(
                "azure_devops", org=organization_name, project=project, repo=repo
            )
            logger.info(
                f"Adding ignore status for {len(findings_to_process)} Azure DevOps findings"
            )

            # Process findings with ignore status
            processed_findings = add_ignore_status_to_findings(
                user_id, repo_name, findings_to_process, workspace_id, "azure-devops"
            )

            # Add fix status to findings
            logger.info(
                f"Adding fix status for {len(processed_findings)} Azure DevOps findings"
            )
            processed_findings = add_fix_status_to_findings(
                user_id,
                repo_identifier,
                processed_findings,
                workspace_id,
                "azure_devops",
                session,
            )

            # Count ignored findings
            ignored_count = sum(
                1 for f in processed_findings if f.get("ignored", False)
            )
            logger.info(
                f"Processed Azure DevOps findings: {len(processed_findings)}, ignored: {ignored_count}"
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
                reranked_data["metadata"]["platform"] = "azure_devops"

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
                        "platform": "azure_devops",
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
            f"Final Azure DevOps response structure: {list(reranked_data.keys()) if isinstance(reranked_data, dict) else type(reranked_data)}"
        )
        return jsonify(reranked_data)

    except Exception as e:
        logger.error(
            f"Error getting Azure DevOps reranked findings: {str(e)}", exc_info=True
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


@azure_devops_bp.route("/ignore-finding", methods=["POST"])
def azure_devops_ignore_finding():
    """Ignore finding for Azure DevOps repositories"""
    try:
        request_data = request.get_json()
        if not request_data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        user_id = request_data.get("user_id")
        repo_name = request_data.get("repo_name")
        workspace_id = request_data.get("workspace_id")
        ignore_type = request_data.get("ignore_type")

        if not all([user_id, repo_name, ignore_type]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "user id, repo_name and ignore type are required"
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
                repo_exists = (
                    db_session.query(AzureDevOpsAnalysisResult)
                    .filter(
                        # AzureDevOpsAnalysisResult.user_id == user_id, it might have been created by different user but in same workspace
                        AzureDevOpsAnalysisResult.repository_name == repo_name,
                        AzureDevOpsAnalysisResult.workspace_id == workspace_id,
                    )
                    .first()
                )

                if not repo_exists:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": {
                                    "message": f"Repository {repo_name} not found in workspace {workspace_id} for user {user_id}"
                                },
                            }
                        ),
                        404,
                    )
            finally:
                db_session.close()

        # Create ignore record using Azure DevOps specific function
        result = create_azure_devops_ignore_record(user_id, repo_name, request_data)

        if result["success"]:
            # Return the FULL result including metadata
            return (
                jsonify(
                    {
                        **result,
                        "workspace_id": workspace_id,
                        "workspace_validated": bool(workspace_id),
                    }
                ),
                201,
            )
        else:
            status_code = 409 if "already ignored" in result["message"] else 400
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
        logger.error(f"Error in Azure DevOps ignore_finding endpoint: {str(e)}")
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@azure_devops_bp.route("/ignore-finding", methods=["DELETE"])
def azure_devops_unignore_finding():
    """Remove ignore status from an Azure DevOps finding/file/rule"""
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
        user_id = request_data.get("user_id")
        repo_name = request_data.get("repo_name")

        if not all([user_id, repo_name]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": "user_id and repo_name are required"},
                    }
                ),
                400,
            )

        # Remove ignore record using Azure DevOps specific function
        result = remove_azure_devops_ignore_record(user_id, repo_name, request_data)

        if result["success"]:
            return jsonify({"success": True, "message": result["message"]}), 200
        else:
            return (
                jsonify({"success": False, "error": {"message": result["message"]}}),
                404,
            )

    except Exception as e:
        logger.error(f"Error in Azure DevOps unignore_finding endpoint: {str(e)}")
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@azure_devops_bp.route("/ignores/<user_id>", methods=["GET"])
def get_azure_devops_user_ignore_list(user_id: str):
    """Get all ignore records for Azure DevOps repositories for a user"""
    engine = None
    db_session = None
    try:
        repo_name = request.args.get("repo_name")
        workspace_id = request.args.get("workspace_id")  # NEW: Add workspace_id filter

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

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get ignore records, filtering for Azure DevOps repos if repo_name contains org/project/repo pattern
        query = db_session.query(IgnoredFinding).filter_by(user_id=user_id)
        if repo_name:
            query = query.filter_by(repo_name=repo_name)
        else:
            # Filter for Azure DevOps repos (they have org/project/repo format with 3 parts)
            query = query.filter(IgnoredFinding.repo_name.like("%/%/%"))

        ignore_records = query.order_by(IgnoredFinding.ignored_at.desc()).all()

        # NEW: Filter ignore records by workspace if specified
        if workspace_id:
            # Get repositories that belong to the specified workspace
            workspace_repos_query = (
                db_session.query(AzureDevOpsAnalysisResult.repository_name)
                .filter(
                    AzureDevOpsAnalysisResult.user_id == user_id,
                    AzureDevOpsAnalysisResult.workspace_id == workspace_id,
                )
                .distinct()
            )

            workspace_repo_names = [
                row.repository_name for row in workspace_repos_query.all()
            ]

            # Filter ignore records to only include repos from the specified workspace
            ignore_records = [
                record
                for record in ignore_records
                if record.repo_name in workspace_repo_names
            ]

            logger.info(
                f"Filtered ignore records by workspace {workspace_id}: {len(ignore_records)} records from {len(workspace_repo_names)} repos"
            )

        # Convert to dictionaries and enhance with metadata
        enhanced_ignores = []

        # Get analysis data for metadata extraction (group by repo for efficiency)
        repo_analyses = {}

        for record in ignore_records:
            record_repo = record.repo_name

            # Get analysis data for this repo if we haven't already
            if record_repo not in repo_analyses:
                try:
                    # Parse Azure DevOps repo name (org/project/repo)
                    parts = record_repo.split("/")
                    if len(parts) == 3:
                        org, proj, repo = parts
                        analysis = (
                            db_session.query(AzureDevOpsAnalysisResult)
                            .filter_by(
                                organization_name=org,
                                project_name=proj,
                                repository_name=repo,
                            )
                            .order_by(desc(AzureDevOpsAnalysisResult.timestamp))
                            .first()
                        )

                        repo_analyses[record_repo] = (
                            analysis.results.get("findings", [])
                            if (analysis and analysis.results)
                            else []
                        )
                    else:
                        repo_analyses[record_repo] = []
                except Exception as e:
                    logger.warning(
                        f"Could not get Azure DevOps analysis for repo {record_repo}: {str(e)}"
                    )
                    repo_analyses[record_repo] = []

            # Extract metadata for this ignore record
            severity = None
            cwe = []
            owasp = []
            category = None
            message = None

            findings = repo_analyses[record_repo]
            if findings:
                # Find matching finding
                normalized_record_path = (
                    normalize_file_path(record.file_path) if record.file_path else None
                )

                for finding in findings:
                    finding_file = normalize_file_path(finding.get("file", ""))

                    # Match based on ignore type
                    match_found = False

                    if record.ignore_type == "finding":
                        # Exact match: rule + file + code snippet
                        if (
                            finding.get("id") == record.finding_id
                            and finding_file == normalized_record_path
                            and finding.get("code_snippet", "") == record.code_snippet
                        ):
                            match_found = True
                    elif record.ignore_type == "rule_in_file":
                        # Rule in specific file
                        if (
                            finding.get("id") == record.finding_id
                            and finding_file == normalized_record_path
                        ):
                            match_found = True
                    elif record.ignore_type == "file":
                        # Any finding in this file
                        if finding_file == normalized_record_path:
                            match_found = True
                    elif record.ignore_type == "rule_in_repo":
                        # This rule anywhere in repo
                        if finding.get("id") == record.finding_id:
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
                "id": record.id,
                "user_id": record.user_id,
                "repo_name": record.repo_name,
                "ignore_type": record.ignore_type,
                "finding_id": record.finding_id,
                "file_path": record.file_path,
                "code_snippet": record.code_snippet,
                "reason": record.reason,
                "ignored_at": (
                    record.ignored_at.isoformat() if record.ignored_at else None
                ),
                "ignored_by": record.ignored_by,
                # Enhanced metadata
                "severity": severity,
                "cwe": cwe if cwe else [],
                "owasp": owasp if owasp else [],
                "category": category,
                "message": message,
                "platform": "azure_devops",
            }

            enhanced_ignores.append(enhanced_ignore)

        return (
            jsonify(
                {
                    "success": True,
                    "data": {
                        "user_id": user_id,
                        "repo_name": repo_name,
                        "ignores": enhanced_ignores,
                        "total_count": len(enhanced_ignores),
                        "metadata_support": True,
                        "platform": "azure_devops",
                    },
                }
            ),
            200,
        )

    except Exception as e:
        logger.error(f"Error getting enhanced Azure DevOps user ignores: {str(e)}")
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@azure_devops_bp.route("/get-branches", methods=["POST"])
def get_azure_devops_repository_branches():
    """Get all branches for an Azure DevOps repository"""

    async def get_branches_async():
        # Get data from POST request body
        request_data = request.get_json()
        if not request_data:
            return (
                {"success": False, "error": {"message": "Request body is required"}},
                400,
            )

        # Get required parameters from request body
        organization_name = request_data.get("organization_name")
        project_name = request_data.get("project")
        repo_name = request_data.get("repo_name")
        PAT = request_data.get("PAT")
        access_token = request_data.get("access_token")

        # Validate required parameters
        required_params = {
            "organization_name": organization_name,
            "project": project_name,
            "repo_name": repo_name,
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

        # Validate authentication
        if not PAT and not access_token:
            return (
                {
                    "success": False,
                    "error": {"message": "Either PAT or access_token must be provided"},
                },
                400,
            )

        # Azure DevOps API base URL
        from urllib.parse import quote

        api_base = f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/git/repositories/{quote(repo_name)}"

        try:
            async with create_secure_client_session(timeout=30) as session:
                # Create authorization header
                auth_header = create_auth_header(PAT=PAT, access_token=access_token)
                headers = {
                    **auth_header,
                    "Content-Type": "application/json",
                }

                # Get repository to find default branch
                repo_url = f"{api_base}?api-version=7.1"
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
                    default_branch = repo_data.get("defaultBranch", "refs/heads/main")
                    # Remove 'refs/heads/' prefix if present
                    if default_branch.startswith("refs/heads/"):
                        default_branch = default_branch[len("refs/heads/") :]

                # Get all branches (refs)
                refs_url = f"{api_base}/refs?filter=heads/&api-version=7.1"
                async with session.get(refs_url, headers=headers) as response:
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

                    refs_data = await response.json()
                    branches_data = refs_data.get("value", [])

                    # Extract branch names
                    branch_names = []
                    for ref in branches_data:
                        ref_name = ref.get("name", "")
                        if ref_name.startswith("refs/heads/"):
                            branch_name = ref_name[len("refs/heads/") :]
                            branch_names.append(branch_name)

                    # Check if 'rezliant' branch exists, if not create it from default branch
                    if "rezliant" not in branch_names:
                        logger.info(
                            f"'rezliant' branch not found, creating it from {default_branch}"
                        )

                        # Get the SHA of the default branch
                        default_ref_url = f"{api_base}/refs?filter=heads/{quote(default_branch)}&api-version=7.1"
                        async with session.get(
                            default_ref_url, headers=headers
                        ) as ref_response:
                            if ref_response.status == 200:
                                ref_data = await ref_response.json()
                                refs_list = ref_data.get("value", [])
                                if refs_list:
                                    default_branch_sha = refs_list[0]["objectId"]

                                    # Create the rezliant branch
                                    create_ref_url = f"{api_base}/refs?api-version=7.1"
                                    create_ref_payload = [
                                        {
                                            "name": "refs/heads/rezliant",
                                            "oldObjectId": "0000000000000000000000000000000000000000",
                                            "newObjectId": default_branch_sha,
                                        }
                                    ]
                                    async with session.post(
                                        create_ref_url,
                                        headers=headers,
                                        json=create_ref_payload,
                                    ) as create_response:
                                        if create_response.status == 200:
                                            logger.info(
                                                f"Successfully created 'rezliant' branch"
                                            )
                                            branch_names.append("rezliant")
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
                        f"Retrieved {len(branches)} branches for {organization_name}/{project_name}/{repo_name}"
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
            logger.error(f"Error fetching Azure DevOps branches: {str(e)}")
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


@azure_devops_bp.route("/create-pr", methods=["POST"])
def create_azure_devops_pull_request():
    """Create a pull request with the fixed file content for Azure DevOps"""

    async def ensure_webhook_exists(
        session, organization_name, project_id, repo_id, headers
    ):
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

            # Get webhook credentials for basic auth
            webhook_username = os.getenv("AZURE_WEBHOOK_USERNAME")
            webhook_password = os.getenv("AZURE_WEBHOOK_PASSWORD")

            if not webhook_username:
                logger.info(
                    "AZURE_WEBHOOK_USERNAME not set, skipping webhook creation for security"
                )
                return (False, None, "AZURE_WEBHOOK_USERNAME not configured")

            if not webhook_password:
                logger.info(
                    "AZURE_WEBHOOK_PASSWORD not set, skipping webhook creation for security"
                )
                return (False, None, "AZURE_WEBHOOK_PASSWORD not configured")

            # List all service hook subscriptions
            list_webhooks_url = f"https://dev.azure.com/{organization_name}/_apis/hooks/subscriptions?api-version=7.1"
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

                hooks_data = await response.json()
                hooks = hooks_data.get("value", [])

            # Check if a webhook already exists for this URL AND is configured for this specific repository
            # We need to verify URL, event type, project, and repository all match
            existing_hook = None
            for hook in hooks:
                hook_url = hook.get("consumerInputs", {}).get("url")
                hook_event = hook.get("eventType")
                hook_repo_id = hook.get("publisherInputs", {}).get("repository")
                hook_project_id = hook.get("publisherInputs", {}).get("projectId")

                # Webhook must match URL, event type, and be configured for this specific repository
                if (
                    hook_url == webhook_url
                    and hook_event == "git.pullrequest.updated"
                    and hook_repo_id == repo_id
                    and hook_project_id == project_id
                ):
                    existing_hook = hook
                    break

            if existing_hook:
                logger.info(
                    f"Webhook already exists for {webhook_url} with PR events for repository {repo_id} in project {project_id}"
                )
                return (True, webhook_url, None)

            # Create a new webhook (service hook subscription) with authentication
            logger.info(f"Creating webhook for {webhook_url}")

            webhook_config = {
                "url": webhook_url,
            }

            # Add basic auth credentials if password is available
            if webhook_password:
                webhook_config["basicAuthUsername"] = webhook_username
                webhook_config["basicAuthPassword"] = webhook_password
                logger.info("Webhook will be created with basic authentication")

            create_webhook_payload = {
                "publisherId": "tfs",
                "eventType": "git.pullrequest.updated",
                "resourceVersion": "1.0",
                "consumerId": "webHooks",
                "consumerActionId": "httpRequest",
                "publisherInputs": {
                    "projectId": project_id,
                    "repository": repo_id,
                },
                "consumerInputs": webhook_config,
            }

            create_webhooks_url = f"https://dev.azure.com/{organization_name}/_apis/hooks/subscriptions?api-version=7.1"
            async with session.post(
                create_webhooks_url, headers=headers, json=create_webhook_payload
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
        organization_name = request_data.get("organization_name")
        project_name = request_data.get("project")
        repo_name = request_data.get("repo_name")
        base_branch = request_data.get("base_branch")
        temp_file_path = request_data.get("file_path")
        file_path = extract_clean_file_path(temp_file_path)
        PAT = request_data.get("PAT")
        access_token = request_data.get("access_token")
        file_content = request_data.get("file_content")

        # Get optional tracking parameters for fix_requests
        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")
        finding_id = request_data.get(
            "finding_id"
        )  # Should be in format: id-filepath-linestart
        line_number = request_data.get("line_number")
        cwe_id = request_data.get("cwe_id")
        severity = request_data.get("severity")

        # Optional parameters with defaults
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_branch_name = f"fix/{file_path.replace('/', '-')}-{timestamp}"
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
            "organization_name": organization_name,
            "project": project_name,
            "repo_name": repo_name,
            "file_path": file_path,
            "file_content": file_content,
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

        # Validate authentication
        if not PAT and not access_token:
            return (
                {
                    "success": False,
                    "error": {"message": "Either PAT or access_token must be provided"},
                },
                400,
            )

        # Azure DevOps API base URL
        from urllib.parse import quote
        import base64

        api_base = f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/git/repositories/{quote(repo_name)}"

        try:
            async with create_secure_client_session(timeout=60) as session:
                # Create authorization header
                auth_header = create_auth_header(PAT=PAT, access_token=access_token)
                headers = {
                    **auth_header,
                    "Content-Type": "application/json",
                }

                # Step 1: Get repository info and default branch if base_branch not provided
                repo_url = f"{api_base}?api-version=7.1"
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
                    repo_id = repo_data.get("id")
                    default_branch_ref = repo_data.get(
                        "defaultBranch", "refs/heads/main"
                    )

                    # Remove 'refs/heads/' prefix if present
                    default_branch = default_branch_ref
                    if default_branch.startswith("refs/heads/"):
                        default_branch = default_branch[len("refs/heads/") :]

                # If base_branch is provided, validate it exists; otherwise use default
                if base_branch:
                    branch_check_url = f"{api_base}/refs?filter=heads/{quote(base_branch)}&api-version=7.1"
                    async with session.get(
                        branch_check_url, headers=headers
                    ) as response:
                        if response.status == 200:
                            ref_data = await response.json()
                            refs_list = ref_data.get("value", [])
                            if not refs_list:
                                logger.warning(
                                    f"Base branch '{base_branch}' not found, using default branch '{default_branch}'"
                                )
                                base_branch = default_branch
                        else:
                            logger.warning(
                                f"Failed to verify base branch, using default branch '{default_branch}'"
                            )
                            base_branch = default_branch
                else:
                    base_branch = default_branch

                logger.info(f"Using base branch: {base_branch}")

                # Step 2: Get the reference to the base branch
                ref_url = (
                    f"{api_base}/refs?filter=heads/{quote(base_branch)}&api-version=7.1"
                )
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
                    refs_list = ref_data.get("value", [])
                    if not refs_list:
                        return (
                            {
                                "success": False,
                                "error": {
                                    "message": f"Base branch '{base_branch}' not found"
                                },
                            },
                            404,
                        )

                    base_sha = refs_list[0]["objectId"]
                    logger.info(f"Base branch SHA: {base_sha}")

                # Step 3: Create a new branch from the base branch
                create_ref_url = f"{api_base}/refs?api-version=7.1"
                create_ref_payload = [
                    {
                        "name": f"refs/heads/{new_branch}",
                        "oldObjectId": "0000000000000000000000000000000000000000",
                        "newObjectId": base_sha,
                    }
                ]

                async with session.post(
                    create_ref_url, headers=headers, json=create_ref_payload
                ) as response:
                    if response.status not in [200]:
                        # Check if branch already exists
                        error_text = await response.text()
                        if (
                            "already exists" in error_text.lower()
                            or "TF401028" in error_text
                        ):
                            logger.warning(
                                f"Branch '{new_branch}' already exists, will update it"
                            )
                        else:
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
                                        "message": f"Failed to create new branch: {error_message}"
                                    },
                                },
                                response.status,
                            )
                    else:
                        logger.info(f"Created new branch: {new_branch}")

                # Step 4: Create a push with the file change
                # Azure DevOps uses a different approach - we create a push with commits
                push_url = f"{api_base}/pushes?api-version=7.1"

                # Encode file content in base64
                encoded_content = base64.b64encode(file_content.encode("utf-8")).decode(
                    "utf-8"
                )

                push_payload = {
                    "refUpdates": [
                        {
                            "name": f"refs/heads/{new_branch}",
                            "oldObjectId": base_sha,
                        }
                    ],
                    "commits": [
                        {
                            "comment": commit_message,
                            "changes": [
                                {
                                    "changeType": "edit",
                                    "item": {"path": f"/{file_path}"},
                                    "newContent": {
                                        "content": encoded_content,
                                        "contentType": "base64encoded",
                                    },
                                }
                            ],
                        }
                    ],
                }

                async with session.post(
                    push_url, headers=headers, json=push_payload
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
                                    "message": f"Failed to push file changes: {error_message}"
                                },
                            },
                            response.status,
                        )

                    logger.info(f"File pushed successfully to branch {new_branch}")

                # Step 5: Create a pull request
                create_pr_url = f"{api_base}/pullrequests?api-version=7.1"
                create_pr_payload = {
                    "sourceRefName": f"refs/heads/{new_branch}",
                    "targetRefName": f"refs/heads/{base_branch}",
                    "title": pr_title,
                    "description": pr_description,
                }

                async with session.post(
                    create_pr_url, headers=headers, json=create_pr_payload
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
                                    "message": f"Failed to create pull request: {error_message}"
                                },
                            },
                            response.status,
                        )

                    pr_data = await response.json()
                    pr_id = pr_data.get("pullRequestId")
                    pr_number = str(pr_id)

                    # Construct PR URL
                    pr_url = f"https://dev.azure.com/{organization_name}/{project_name}/_git/{repo_name}/pullrequest/{pr_id}"

                    logger.info(f"Pull request created: {pr_url}")

                    # Step 6: Attempt to create webhook for PR updates (non-blocking)
                    webhook_enabled = False
                    webhook_url_result = None
                    webhook_error = None

                    try:
                        # Get project and repo IDs for webhook creation
                        project_id = repo_data.get("project", {}).get("id")
                        repo_id = repo_data.get("id")

                        if project_id and repo_id:
                            webhook_enabled, webhook_url_result, webhook_error = (
                                await ensure_webhook_exists(
                                    session,
                                    organization_name,
                                    project_id,
                                    repo_id,
                                    headers,
                                )
                            )
                            if not webhook_enabled:
                                logger.warning(
                                    f"Webhook creation skipped or failed: {webhook_error}. "
                                    "PR will not have live updates."
                                )
                        else:
                            logger.warning(
                                "Could not retrieve project/repo IDs for webhook creation"
                            )
                            webhook_error = "Missing project or repo ID"
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
                            from azure_devops.utils import create_api_engine
                            from models import FixRequest
                            from sqlalchemy.orm import sessionmaker

                            fix_engine = create_api_engine()
                            FixSession = sessionmaker(bind=fix_engine)
                            fix_session = FixSession()

                            try:
                                # Build repo identifier (Azure DevOps format)
                                repo_identifier = f"https://dev.azure.com/{organization_name}/{project_name}/_git/{repo_name}"

                                # Create fix request with separate fields
                                fix_request = FixRequest(
                                    user_id=user_id,
                                    workspace_id=workspace_id,
                                    repo_type="azure_devops",
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
                                    "liveUpdates": webhook_enabled,
                                },
                            },
                        },
                        200,
                    )

        except Exception as e:
            logger.error(f"Error creating Azure DevOps pull request: {str(e)}")
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
