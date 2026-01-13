from flask import Blueprint, jsonify, request
from sqlalchemy import desc
from sqlalchemy.orm import sessionmaker
from models import db, GitLabAnalysisResult
from collections import defaultdict
import os
import logging
import json
import traceback
import asyncio
from datetime import datetime, timezone
from threading import Thread
import requests
import uuid
from db_utils import create_db_engine
from progress_tracking import update_scan_progress, clear_scan_progress
from gitlab_scanner import scan_gitlab_repository_handler
from ignore_utils import (
    add_ignore_status_to_findings,
    create_ignore_record,
    remove_ignore_record,
    get_user_ignores,
    normalize_file_path,
)
from fix_utils import add_fix_status_to_findings, get_finding_key
from utils import get_repository_identifier
from models import IgnoredFinding


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


def create_api_engine():
    """Create database engine for API routes"""
    return create_db_engine()


# Create Blueprint
gitlab_bp = Blueprint("gitlab", __name__, url_prefix="/api/v1/gitlab")

# =====================================================
# UTILITY FUNCTIONS
# =====================================================


def extract_project_info_from_url(project_url):
    """Extract project information from GitLab URL"""
    if "gitlab.com/" not in project_url:
        raise ValueError("Invalid GitLab project URL")

    project_path = project_url.split("gitlab.com/")[-1].rstrip("/")
    repository_name = project_path.split("/")[-1]

    return {
        "project_path": project_path,
        "repository_name": repository_name,
        "gitlab_instance_url": "https://gitlab.com",
    }


def get_gitlab_project_details(project_path, access_token):
    """Get project details from GitLab API"""
    headers = {"Authorization": f"Bearer {access_token}"}
    encoded_path = requests.utils.quote(project_path, safe="")
    project_url = f"https://gitlab.com/api/v4/projects/{encoded_path}"

    response = requests.get(project_url, headers=headers)
    if response.status_code != 200:
        raise Exception(f"Project not found or inaccessible: {response.text}")

    return response.json()


def parse_workspace_param(workspace_param):
    """Parse workspace parameter - can be UUID string or generate new one"""
    if not workspace_param:
        return uuid.uuid4()

    try:
        # Try to parse as UUID
        return uuid.UUID(workspace_param)
    except (ValueError, TypeError):
        # If not a valid UUID, generate a new one
        return uuid.uuid4()


def rerank_findings(findings, user_id, project_url, project_id, analysis, db_session):
    """Helper function to rerank findings through AI"""
    try:
        if not findings:
            logger.info("No findings to rerank")
            analysis.status = "completed"
            analysis.results = {"findings": [], "summary": {}, "metadata": {}}
            analysis.rerank = []
            db_session.commit()
            return

        logger.info(f"Preparing to rerank {len(findings)} findings")

        # Prepare data for LLM
        llm_data = {
            "findings": [
                {
                    "ID": finding.get("ID", idx + 1),
                    "file": finding.get("file", ""),
                    "code_snippet": finding.get("code_snippet", ""),
                    "message": finding.get("message", ""),
                    "severity": finding.get("severity", ""),
                }
                for idx, finding in enumerate(findings)
            ],
            "metadata": {
                "repository": (
                    project_url.split("gitlab.com/")[-1]
                    if "gitlab.com/" in project_url
                    else project_url
                ),
                "project_url": project_url,
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
                "scan_id": analysis.id if analysis else None,
            },
        }

        # Call LLM reranking service
        AI_RERANK_URL = os.getenv("RERANK_API_URL")
        reordered_findings = findings  # Default to original order

        if AI_RERANK_URL:
            try:
                headers = {"Content-Type": "application/json"}
                response = requests.post(
                    AI_RERANK_URL, headers=headers, json=llm_data, timeout=60
                )

                if response.status_code == 200:
                    response_data = response.json()
                    reranked_ids = extract_ids_from_llm_response(
                        response_data, findings
                    )

                    if reranked_ids:
                        findings_map = {
                            finding.get("ID", idx + 1): finding
                            for idx, finding in enumerate(findings)
                        }
                        reordered_findings = [
                            findings_map[rank_id]
                            for rank_id in reranked_ids
                            if rank_id in findings_map
                        ]

                        if not reordered_findings:
                            reordered_findings = findings

            except Exception as e:
                logger.error(f"Error calling LLM service: {str(e)}")

        # Calculate statistics
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        for finding in findings:
            severity = finding.get("severity", "INFO")
            category = finding.get("category", "unknown")
            severity_counts[severity] += 1
            category_counts[category] += 1

        summary = {
            "total_findings": len(findings),
            "severity_counts": dict(severity_counts),
            "category_counts": dict(category_counts),
            "files_scanned": len(set(f.get("file", "") for f in findings)),
            "files_with_findings": len(set(f.get("file", "") for f in findings)),
        }

        results_data = {
            "findings": findings,
            "summary": summary,
            "metadata": {
                "scan_duration_seconds": 0,
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": user_id,
                "project_url": project_url,
                "project_id": project_id,
                "reranking": "completed",
            },
        }

        # Save to database
        try:
            fresh_analysis = db_session.query(GitLabAnalysisResult).get(analysis.id)
            if fresh_analysis:
                fresh_analysis.status = "completed"
                fresh_analysis.results = results_data
                fresh_analysis.rerank = reordered_findings
                db_session.commit()
                logger.info(
                    f"Successfully committed reranked findings to database for analysis {fresh_analysis.id}"
                )
        except Exception as db_e:
            logger.error(f"Database error when saving reranked findings: {str(db_e)}")
            db_session.rollback()

    except Exception as e:
        logger.error(f"Error in rerank_findings: {str(e)}")
        try:
            merged_analysis = db_session.merge(analysis)
            merged_analysis.status = "completed"
            merged_analysis.results = {
                "findings": findings,
                "summary": {"total_findings": len(findings)},
                "metadata": {
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": str(e),
                },
            }
            merged_analysis.rerank = findings
            db_session.commit()
        except Exception as fallback_e:
            logger.error(f"Critical failure in reranking fallback: {str(fallback_e)}")
            db_session.rollback()


def extract_ids_from_llm_response(response_data, original_findings=None):
    """Extract IDs from LLM response with fallback"""
    try:
        if isinstance(response_data, dict) and "llm_response" in response_data:
            response = response_data["llm_response"]
            if isinstance(response, list) and response:
                return response
        elif isinstance(response_data, list) and response_data:
            return response_data

        # Fallback to original order
        return list(range(1, len(original_findings) + 1)) if original_findings else None

    except Exception as e:
        logger.error(f"Error extracting IDs from LLM response: {str(e)}")
        return list(range(1, len(original_findings) + 1)) if original_findings else None


# =====================================================
# API ENDPOINTS
# =====================================================


@gitlab_bp.route("/user/info", methods=["POST"])
def get_user_info():
    """Get GitLab user info using Personal Access Token"""
    try:
        data = request.get_json()
        if not data or not data.get("access_token"):
            return (
                jsonify(
                    {"success": False, "error": {"message": "access_token is required"}}
                ),
                400,
            )

        headers = {"Authorization": f"Bearer {data['access_token']}"}
        response = requests.get("https://gitlab.com/api/v4/user", headers=headers)

        if response.status_code == 200:
            user_data = response.json()
            return jsonify(
                {
                    "success": True,
                    "data": {
                        "id": str(user_data["id"]),
                        "username": user_data["username"],
                        "name": user_data["name"],
                        "email": user_data["email"],
                        "avatar_url": user_data.get("avatar_url", ""),
                        "web_url": user_data.get("web_url", ""),
                    },
                }
            )

        return (
            jsonify({"success": False, "error": {"message": "Invalid access token"}}),
            response.status_code,
        )

    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@gitlab_bp.route("/repositories", methods=["POST"])
def list_repositories():
    """List repositories accessible to the authenticated user"""
    try:
        data = request.get_json()
        if not data or not data.get("access_token"):
            return (
                jsonify(
                    {"success": False, "error": {"message": "access_token is required"}}
                ),
                400,
            )

        headers = {"Authorization": f"Bearer {data['access_token']}"}
        response = requests.get(
            "https://gitlab.com/api/v4/projects",
            headers=headers,
            params={"membership": True, "min_access_level": 30},
        )

        if response.status_code == 200:
            repositories = response.json()
            formatted_repos = [
                {
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["path_with_namespace"],
                    "url": repo["web_url"],
                    "description": repo["description"],
                    "default_branch": repo["default_branch"],
                    "visibility": repo["visibility"],
                    "created_at": repo["created_at"],
                    "last_activity_at": repo["last_activity_at"],
                }
                for repo in repositories
            ]

            return jsonify({"success": True, "data": formatted_repos})

        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": f"Failed to fetch repositories: {response.text}"
                    },
                }
            ),
            response.status_code,
        )

    except Exception as e:
        logger.error(f"Error fetching repositories: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@gitlab_bp.route("/scan", methods=["POST"])
def trigger_scan():
    """Trigger a security scan for a GitLab repository"""
    db_session = None
    analysis = None

    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Required parameters

        # Sanitize input data
        data = sanitize_request_data(data)
        access_token = data.get("access_token")
        access_token = data.get("access_token")
        project_url = data.get("project_url")
        user_id = data.get("user_id")
        workspace = data.get("workspace")

        if not all([access_token, project_url, user_id]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "access_token, project_url, and user_id are required"
                        },
                    }
                ),
                400,
            )

        # Extract project information
        try:
            project_info = extract_project_info_from_url(project_url)
            project_data = get_gitlab_project_details(
                project_info["project_path"], access_token
            )
        except Exception as e:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f"Failed to fetch project details: {str(e)}"
                        },
                    }
                ),
                400,
            )

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # REUSING EXISTING ANALYSIS RECORD IF AVAILABLE (same repo/workspace)
        existing_query = db_session.query(GitLabAnalysisResult).filter(
            GitLabAnalysisResult.project_path == project_info["project_path"],
            GitLabAnalysisResult.project_id == str(project_data["id"]),
        )
        if workspace:
            existing_query = existing_query.filter(
                GitLabAnalysisResult.workspace == workspace
            )
        analysis = existing_query.order_by(desc(GitLabAnalysisResult.timestamp)).first()

        if analysis:
            analysis.status = "queued"
            analysis.project_id = str(project_data["id"])  # ensure project id fresh
            analysis.timestamp = datetime.utcnow()
            db_session.commit()
            logger.info(
                f"Reusing GitLab analysis record ID: {analysis.id} for {project_info['project_path']} (workspace={workspace})"
            )
        else:
            analysis = GitLabAnalysisResult(
                user_id=user_id,
                repository_name=project_info["repository_name"],
                project_id=str(project_data["id"]),
                project_path=project_info["project_path"],
                gitlab_instance_url=project_info["gitlab_instance_url"],
                workspace=workspace,
                branch_name=project_data.get("default_branch", "main"),
                status="queued",
            )
            db_session.add(analysis)
            db_session.commit()
            logger.info(f"Created analysis record with ID: {analysis.id}")

        # Initialize progress tracking
        clear_scan_progress(user_id, str(project_data["id"]))
        update_scan_progress(
            user_id, str(project_data["id"]), "initializing", 0, None, "gitlab"
        )

        # Start scan in background thread
        def run_scan_in_background():
            try:
                analysis.status = "in_progress"
                db_session.commit()

                # Run scan
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(
                    scan_gitlab_repository_handler(
                        project_id=str(project_data["id"]),
                        project_url=project_url,
                        access_token=access_token,
                        user_id=user_id,
                        db_session=db_session,
                        analysis_record=analysis,
                    )
                )
                loop.close()

                # Handle reranking
                if results.get("success"):
                    findings = results["data"].get("findings", [])
                    for idx, finding in enumerate(findings, 1):
                        if "ID" not in finding:
                            finding["ID"] = idx

                    rerank_findings(
                        findings,
                        user_id,
                        project_url,
                        str(project_data["id"]),
                        analysis,
                        db_session,
                    )

            except Exception as e:
                logger.error(f"Background scan error: {str(e)}")
                analysis.status = "error"
                analysis.error = str(e)
                update_scan_progress(user_id, str(project_data["id"]), "error", 0)
                db_session.commit()

        # Start the background thread
        thread = Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()

        return (
            jsonify(
                {
                    "success": True,
                    "message": "GitLab scan queued successfully",
                    "scan_id": analysis.id,
                    "status": "queued",
                    "user_id": user_id,
                    "project_id": project_data["id"],
                    "repository_name": project_info["repository_name"],
                    "project_path": project_info["project_path"],
                    "workspace": str(workspace),
                }
            ),
            202,
        )

    except Exception as e:
        logger.error(f"GitLab scan initialization error: {str(e)}")
        if analysis and db_session:
            try:
                analysis.status = "error"
                analysis.error = str(e)
                db_session.commit()
            except Exception as commit_error:
                logger.error(f"Failed to update analysis status: {str(commit_error)}")
                db_session.rollback()
        return jsonify({"success": False, "error": {"message": str(e)}}), 500
    finally:
        if db_session:
            db_session.close()


@gitlab_bp.route("/analysis/<repo_name>/result", methods=["GET"])
def get_analysis_findings(repo_name):
    """Get analysis findings with ignore status included and adjusted severity counts"""
    engine = None
    db_session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get query parameters
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("limit", 30))))
        severity = request.args.get("severity", "").upper()
        category = request.args.get("category", "")
        file_path = request.args.get("file", "")
        user_id = request.args.get("user_id")
        workspace_param = request.args.get("workspace_id")

        # Build query - use repository_name for lookup
        query = db_session.query(GitLabAnalysisResult).filter_by(
            repository_name=repo_name
        )

        if workspace_param:
            query = query.filter(GitLabAnalysisResult.workspace == workspace_param)

        if user_id and not workspace_param:
            query = query.filter_by(user_id=user_id)

        # Get latest analysis result
        result = query.order_by(desc(GitLabAnalysisResult.timestamp)).first()

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

        # Extract results dynamically
        results = result.results or {}
        stats = results.get("summary", {})
        metadata = results.get("metadata", {})
        findings = results.get("findings", [])

        # Get repository identifier for fix status
        repo_identifier = f"https://gitlab.com/{result.project_path}"

        # Add ignore status to findings if user_id is provided
        if user_id and findings:
            findings = add_ignore_status_to_findings(
                user_id, repo_name, findings, workspace_param, "gitlab"
            )
            # Add fix status to findings
            findings = add_fix_status_to_findings(
                user_id,
                repo_identifier,
                findings,
                workspace_param,
                "gitlab",
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
            # Apply normalization to file filter as well
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

        # Calculate adjusted severity counts based on ignore status
        original_severity_counts = stats.get("severity_counts", {})
        complete_severity_counts = {
            "CRITICAL": int(original_severity_counts.get("CRITICAL", 0) or 0),
            "HIGH": int(original_severity_counts.get("ERROR", 0) or 0),
            "MEDIUM": int(original_severity_counts.get("WARNING", 0) or 0),
            "LOW": int(original_severity_counts.get("INFO", 0) or 0),
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

            complete_severity_counts = adjusted_severity_counts

            ignore_stats["ignored_severity_counts"] = ignored_severity_counts

        summary = {
            "category_counts": stats.get("category_counts", {}),
            "files_scanned": stats.get("files_scanned", 0),
            "files_with_findings": stats.get("files_with_findings", 0),
            "partially_scanned": 0,
            "severity_counts": complete_severity_counts,
            "skipped_files": stats.get("skipped_files", 0),
            "total_findings": total_findings
            - (ignore_stats.get("total_ignored", 0) if user_id else 0),
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
                        "project_id": result.project_id,
                        "project_path": result.project_path,
                        "gitlab_instance_url": result.gitlab_instance_url,
                        "branch_name": result.branch_name,
                    },
                    "metadata": {
                        "analysis_id": result.id,
                        "duration_seconds": metadata.get("scan_duration_seconds", 0),
                        "status": result.status,
                        "timestamp": result.timestamp.isoformat(),
                        "workspace": str(result.workspace),
                        "user_id": user_id,
                        "ignore_support": bool(user_id),
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


@gitlab_bp.route("/analysis/<repo_name>/reranked", methods=["GET"])
def get_reranked_findings(repo_name):
    """Get reranked findings for a GitLab repository"""
    engine = None
    session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        # Get query parameters
        user_id = request.args.get("user_id")
        workspace_param = request.args.get("workspace_id")
        logger.info(f"Reranked request: {repo_name}, user_id={user_id}")

        # Build query - use repository_name for lookup
        query = session.query(GitLabAnalysisResult).filter_by(repository_name=repo_name)

        if workspace_param:
            query = query.filter(GitLabAnalysisResult.workspace == workspace_param)

        if user_id and not workspace_param:
            try:

                query = query.filter(GitLabAnalysisResult.workspace == workspace_param)
            except ValueError:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": {
                                "message": "Invalid workspace UUID format",
                                "code": "INVALID_WORKSPACE",
                            },
                        }
                    ),
                    400,
                )

        # Get latest analysis result
        result = query.order_by(desc(GitLabAnalysisResult.timestamp)).first()

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

        # Get repository identifier for fix status
        repo_identifier = f"https://gitlab.com/{result.project_path}"

        # Add ignore status if user_id is provided and we have findings
        if user_id and findings_to_process:
            logger.info(f"Adding ignore status for {len(findings_to_process)} findings")

            # Process findings with ignore status
            processed_findings = add_ignore_status_to_findings(
                user_id, repo_name, findings_to_process, workspace_param, "gitlab"
            )

            # Add fix status to findings
            logger.info(f"Adding fix status for {len(processed_findings)} findings")
            processed_findings = add_fix_status_to_findings(
                user_id,
                repo_identifier,
                processed_findings,
                workspace_param,
                "gitlab",
                session,
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


@gitlab_bp.route("/users/<user_id>/scans", methods=["GET"])
def get_user_scans(user_id):
    """Get all scans for a specific user"""
    try:
        workspace_param = request.args.get("workspace_id")

        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        session = Session()

        try:
            query = session.query(GitLabAnalysisResult).filter_by(user_id=user_id)

            if workspace_param:
                try:

                    query = query.filter(
                        GitLabAnalysisResult.workspace == workspace_param
                    )
                except ValueError:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "error": {
                                    "message": "Invalid workspace UUID format",
                                    "code": "INVALID_WORKSPACE",
                                },
                            }
                        ),
                        400,
                    )

            scans = query.order_by(desc(GitLabAnalysisResult.timestamp)).all()

            scans_data = []
            total_findings = 0
            severity_counts = defaultdict(int)

            for scan in scans:
                scan_dict = scan.to_dict()
                # Convert UUID to string for JSON serialization
                if "workspace" in scan_dict and scan_dict["workspace"]:
                    scan_dict["workspace"] = str(scan_dict["workspace"])
                scans_data.append(scan_dict)

                if scan.results and "stats" in scan.results:
                    stats = scan.results["stats"]
                    scan_stats = stats.get("scan_stats", {})
                    total_findings += stats.get("total_findings", 0)

                    for severity, count in stats.get("severity_counts", {}).items():
                        severity_counts[severity] += count

            return jsonify(
                {
                    "success": True,
                    "data": {
                        "scans": scans_data,
                        "summary": {
                            "total_scans": len(scans_data),
                            "total_findings": total_findings,
                            "severity_counts": dict(severity_counts),
                        },
                    },
                }
            )

        finally:
            session.close()

    except Exception as e:
        logger.error(f"Error getting user scans: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@gitlab_bp.route("/files", methods=["POST"])
def get_vulnerable_file():
    """Fetch vulnerable file content from GitLab"""
    try:
        data = request.get_json()
        if not data:
            return (
                jsonify(
                    {"success": False, "error": {"message": "Request body is required"}}
                ),
                400,
            )

        # Sanitize input data
        data = sanitize_request_data(data)
        project_id = data.get("project_id")
        project_id = data.get("project_id")
        file_path = data.get("file_path")
        access_token = data.get("access_token")
        branch = data.get("branch", "main")

        required_params = {
            "project_id": project_id,
            "file_path": file_path,
            "access_token": access_token,
        }

        missing_params = [
            param for param, value in required_params.items() if not value
        ]
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

        headers = {"Authorization": f"Bearer {access_token}"}

        # URL encode the file path for GitLab API
        encoded_file_path = requests.utils.quote(file_path, safe="")

        # Get file content
        file_url = f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/{encoded_file_path}/raw"
        params = {"ref": branch}

        file_response = requests.get(file_url, headers=headers, params=params)
        if file_response.status_code != 200:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {"message": "File not found or inaccessible"},
                    }
                ),
                404,
            )

        return jsonify(
            {
                "success": True,
                "data": {
                    "file": file_response.text,
                    "project_id": project_id,
                    "file_path": file_path,
                    "branch": branch,
                },
            }
        )

    except Exception as e:
        logger.error(f"GitLab API error: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@gitlab_bp.route("/users/severity-counts", methods=["POST"])
def gitlab_user_severity_counts():
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
        include_ignored = request_data.get("include_ignored", False)
        workspace_param = request_data.get("workspace_id") or request.args.get(
            "workspace_id"
        )

        logger.info(
            f"[GitLab] Processing severity counts for user_id={user_id}, include_ignored={include_ignored}, workspace_param={workspace_param}"
        )
        from sqlalchemy.orm import sessionmaker

        engine = create_api_engine()
        engine.dispose()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        try:
            from models import GitLabAnalysisResult

            query = db_session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.status == "completed",
                GitLabAnalysisResult.results.isnot(None),
            )

            if workspace_param:
                query = query.filter(GitLabAnalysisResult.workspace == workspace_param)
                logger.info(
                    f"[GitLab] Filtering severity counts by workspace str={workspace_param}"
                )
            else:
                query = query.filter(GitLabAnalysisResult.user_id == user_id)
                logger.info(f"[GitLab] Filtering severity counts by user_id={user_id}")

            all_analyses = query.order_by(GitLabAnalysisResult.timestamp.desc()).all()
            logger.info(
                f"[GitLab] Found {len(all_analyses)} total analyses after workspace filtering for user {user_id}"
            )

            latest_analyses = {}
            for analysis in all_analyses:
                project_path = analysis.project_path
                if project_path not in latest_analyses:
                    latest_analyses[project_path] = analysis
            if not latest_analyses:
                # Return empty successful response instead of 404
                empty_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
                return (
                    jsonify(
                        {
                            "success": True,
                            "data": {
                                "user_id": user_id,
                                "total_findings": 0,
                                "total_ignored_findings": 0,
                                "total_projects": 0,
                                "severity_counts": empty_counts,
                                "ignored_severity_counts": empty_counts,
                                "projects": {},
                                "metadata": {
                                    "last_scan": None,
                                    "scans_analyzed": 0,
                                    "include_ignored": include_ignored,
                                    "ignore_support": True,
                                    "workspace_filtering": bool(workspace_param),
                                },
                            },
                        }
                    ),
                    200,
                )
            project_data = {}
            total_severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            total_ignored_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            total_findings = 0
            total_ignored_findings = 0
            latest_scan_time = None
            for project_path, analysis in latest_analyses.items():
                results = analysis.results or {}
                findings = results.get("findings", [])
                if findings:
                    findings = add_ignore_status_to_findings(
                        user_id, project_path, findings, workspace_param, "gitlab"
                    )
                project_severity_counts = {
                    "CRITICAL": 0,
                    "ERROR": 0,
                    "WARNING": 0,
                    "INFO": 0,
                }
                project_ignored_counts = {
                    "CRITICAL": 0,
                    "ERROR": 0,
                    "WARNING": 0,
                    "INFO": 0,
                }
                project_total_findings = 0
                project_ignored_findings = 0
                for finding in findings:
                    severity = finding.get("severity", "INFO")
                    is_ignored = finding.get("ignored", False)
                    if is_ignored:
                        project_ignored_counts[severity] += 1
                        total_ignored_counts[severity] += 1
                        project_ignored_findings += 1
                        total_ignored_findings += 1
                        if include_ignored:
                            project_severity_counts[severity] += 1
                            total_severity_counts[severity] += 1
                            project_total_findings += 1
                            total_findings += 1
                    else:
                        project_severity_counts[severity] += 1
                        total_severity_counts[severity] += 1
                        project_total_findings += 1
                        total_findings += 1
                current_scan_time = analysis.timestamp
                latest_scan_time = (
                    max(latest_scan_time, current_scan_time)
                    if latest_scan_time
                    else current_scan_time
                )
                project_data[project_path] = {
                    "project_path": project_path,
                    "severity_counts": project_severity_counts,
                    "ignored_counts": project_ignored_counts,
                    "total_findings": project_total_findings,
                    "total_ignored": project_ignored_findings,
                }
            logger.info(
                f"[GitLab] Severity counts ready for user={user_id}: projects={len(project_data)}, total_findings={total_findings}, total_ignored={total_ignored_findings}"
            )
            return (
                jsonify(
                    {
                        "success": True,
                        "data": {
                            "user_id": user_id,
                            "total_findings": total_findings,
                            "total_ignored_findings": total_ignored_findings,
                            "total_projects": len(project_data),
                            "severity_counts": total_severity_counts,
                            "ignored_severity_counts": total_ignored_counts,
                            "projects": project_data,
                            "metadata": {
                                "last_scan": (
                                    latest_scan_time.isoformat()
                                    if latest_scan_time
                                    else None
                                ),
                                "scans_analyzed": len(project_data),
                                "include_ignored": include_ignored,
                                "ignore_support": True,
                            },
                        },
                    }
                ),
                200,
            )
        finally:
            db_session.close()
            engine.dispose()
    except Exception as e:
        logger.error(f"Error getting severity counts (GitLab): {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@gitlab_bp.route("/users/<user_id>/top-vulnerabilities", methods=["GET"])
def gitlab_top_vulnerabilities(user_id):
    try:
        include_ignored = request.args.get("include_ignored", "true").lower() == "true"
        workspace_param = request.args.get("workspace_id") or request.args.get(
            "workspace"
        )
        logger.info(
            f"[GitLab] Computing top vulnerabilities for user_id={user_id}, include_ignored={include_ignored}, workspace_param={workspace_param}"
        )
        from sqlalchemy.orm import sessionmaker

        engine = create_api_engine()
        engine.dispose()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        try:
            from models import GitLabAnalysisResult

            query = db_session.query(GitLabAnalysisResult).filter(
                GitLabAnalysisResult.status == "completed",
                GitLabAnalysisResult.results.isnot(None),
            )

            if workspace_param:

                query = query.filter(GitLabAnalysisResult.workspace == workspace_param)
                logger.info(
                    f"[GitLab] Filtering top vulns by workspace str={workspace_param}"
                )
            else:
                query = query.filter(GitLabAnalysisResult.user_id == user_id)
                logger.info(f"[GitLab] Filtering top vulns by user_id={user_id}")

            analyses = query.order_by(GitLabAnalysisResult.timestamp.desc()).all()
            logger.info(
                f"[GitLab] Found {len(analyses)} analyses after workspace filtering"
            )

            if not analyses:
                # Return empty successful response instead of 404
                return (
                    jsonify(
                        {
                            "success": True,
                            "data": {
                                "metadata": {
                                    "user_id": user_id,
                                    "total_vulnerabilities": 0,
                                    "total_ignored_vulnerabilities": 0,
                                    "total_projects": 0,
                                    "severity_breakdown": {},
                                    "ignored_severity_breakdown": {},
                                    "category_breakdown": {},
                                    "ignored_category_breakdown": {},
                                    "project_breakdown": {},
                                    "last_scan": None,
                                    "project": None,
                                    "include_ignored": include_ignored,
                                    "ignore_support": True,
                                    "workspace_filtering": bool(workspace_param),
                                },
                                "vulnerabilities": [],
                            },
                        }
                    ),
                    200,
                )
            logger.info(
                f"[GitLab] Found {len(analyses)} analyses for top vulnerabilities (user={user_id})"
            )
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            project_counts = defaultdict(int)
            ignored_severity_counts = defaultdict(int)
            ignored_category_counts = defaultdict(int)
            unique_vulns = {}
            total_ignored_vulnerabilities = 0
            for analysis in analyses:
                findings = analysis.results.get("findings", [])
                project_path = analysis.project_path
                # Get repository identifier for fix status
                repo_identifier = f"https://gitlab.com/{project_path}"
                if findings:
                    findings = add_ignore_status_to_findings(
                        user_id, project_path, findings, workspace_param, "gitlab"
                    )
                    # Add fix status to findings
                    findings = add_fix_status_to_findings(
                        user_id,
                        repo_identifier,
                        findings,
                        workspace_param,
                        "gitlab",
                        db_session,
                    )
                for finding in findings:
                    vuln_id = finding.get("id")
                    is_ignored = finding.get("ignored", False)
                    severity = finding.get("severity")
                    category = finding.get("category")
                    if is_ignored:
                        ignored_severity_counts[severity] += 1
                        ignored_category_counts[category] += 1
                        total_ignored_vulnerabilities += 1
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
                                    "description": finding.get(
                                        "fix_recommendations", ""
                                    ),
                                    "references": finding.get("references", []),
                                },
                                "project": {
                                    "name": project_path.split("/")[-1],
                                    "full_path": project_path,
                                    "analyzed_at": analysis.timestamp.isoformat(),
                                },
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
                            project_counts[project_path] += 1
            logger.info(
                f"[GitLab] Top vulnerabilities computed for user={user_id}: unique={len(unique_vulns)}, ignored_total={total_ignored_vulnerabilities}, projects={len(project_counts)}"
            )
            return (
                jsonify(
                    {
                        "success": True,
                        "data": {
                            "metadata": {
                                "user_id": user_id,
                                "total_vulnerabilities": len(unique_vulns),
                                "total_ignored_vulnerabilities": total_ignored_vulnerabilities,
                                "total_projects": len(project_counts),
                                "severity_breakdown": dict(severity_counts),
                                "ignored_severity_breakdown": dict(
                                    ignored_severity_counts
                                ),
                                "category_breakdown": dict(category_counts),
                                "ignored_category_breakdown": dict(
                                    ignored_category_counts
                                ),
                                "project_breakdown": dict(project_counts),
                                "last_scan": (
                                    analyses[0].timestamp.isoformat()
                                    if analyses
                                    else None
                                ),
                                "project": None,
                                "include_ignored": include_ignored,
                                "ignore_support": True,
                            },
                            "vulnerabilities": list(unique_vulns.values()),
                        },
                    }
                ),
                200,
            )
        finally:
            db_session.close()
            engine.dispose()
    except Exception as e:
        logger.error(f"Error in gitlab_top_vulnerabilities: {str(e)}")
        return jsonify({"success": False, "error": {"message": str(e)}}), 500


@gitlab_bp.route("/ignore-finding", methods=["POST"])
def gitlab_ignore_finding():
    """
    Create ignore record for GitLab findings (same logic as GitHub, but repo_name=project_path)
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

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        user_id = request_data.get("user_id")
        user_id = request_data.get("user_id")
        project_path = request_data.get("project_path")  # Use project_path as repo_name
        ignore_type = request_data.get("ignore_type")
        reason = request_data.get("reason", "")
        logger.info(
            f"[GitLab] Creating ignore record user_id={user_id} project_path={project_path} type={ignore_type}"
        )

        if not all([user_id, project_path, ignore_type]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "user_id, project_path, and ignore_type are required"
                        },
                    }
                ),
                400,
            )

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

        if file_path:
            file_path = normalize_file_path(file_path)
        if cwe_id and not cwe_id.startswith("CWE-"):
            if ":" in cwe_id:
                cwe_id = cwe_id.split(":")[0].strip()
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

        # Prepare ignore data
        workspace_id = request_data.get("workspace_id")
        ignore_data = {
            "ignore_type": ignore_type,
            "finding_id": finding_id,
            "file_path": file_path,
            "code_snippet": code_snippet,
            "cwe_id": cwe_id,
            "reason": reason,
        }
        result = create_ignore_record(
            user_id, project_path, ignore_data, workspace_id, "gitlab"
        )
        if result["success"]:
            logger.info(
                f"[GitLab] Successfully created ignore record: type={ignore_type} project_path={project_path}"
            )
            return jsonify(result), 201
        else:
            status_code = 409 if "already ignored" in result["message"] else 400
            logger.warning(
                f"[GitLab] Failed to create ignore record: {result['message']}"
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": result["message"],
                            "existing_reason": result.get("existing_reason"),
                        },
                    }
                ),
                status_code,
            )
    except Exception as e:
        logger.error(f"Error in gitlab_ignore_finding: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@gitlab_bp.route("/ignore-finding", methods=["DELETE"])
def gitlab_unignore_finding():
    """
    Remove ignore status from a finding/file/rule/CWE for GitLab project
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

        # Sanitize input data
        request_data = sanitize_request_data(request_data)
        user_id = request_data.get("user_id")
        user_id = request_data.get("user_id")
        project_path = request_data.get("project_path")
        ignore_type = request_data.get("ignore_type")
        logger.info(
            f"[GitLab] Removing ignore record user_id={user_id} project_path={project_path} type={ignore_type}"
        )
        if not all([user_id, project_path, ignore_type]):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": "user_id, project_path, and ignore_type are required"
                        },
                    }
                ),
                400,
            )
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
        finding_id = request_data.get("finding_id")
        file_path = request_data.get("file_path")
        code_snippet = request_data.get("code_snippet")
        cwe_id = request_data.get("cwe_id")
        if file_path:
            file_path = normalize_file_path(file_path)
        if cwe_id and not cwe_id.startswith("CWE-"):
            if ":" in cwe_id:
                cwe_id = cwe_id.split(":")[0].strip()
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
        ignore_data = {
            "ignore_type": ignore_type,
            "finding_id": finding_id,
            "file_path": file_path,
            "code_snippet": code_snippet,
            "cwe_id": cwe_id,
        }
        result = remove_ignore_record(user_id, project_path, ignore_data)
        if result["success"]:
            logger.info(
                f"[GitLab] Successfully removed ignore record: type={ignore_type} project_path={project_path}"
            )
            return jsonify({"success": True, "message": result["message"]}), 200
        else:
            logger.warning(
                f"[GitLab] No ignore record found to remove: type={ignore_type} project_path={project_path}"
            )
            return (
                jsonify({"success": False, "error": {"message": result["message"]}}),
                404,
            )
    except Exception as e:
        logger.error(f"Error in gitlab_unignore_finding: {str(e)}", exc_info=True)
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@gitlab_bp.route("/ignores/<user_id>", methods=["GET"])
def gitlab_get_user_ignore_list(user_id):
    """
    Get all ignore records for a user (optionally filter by project_path)
    """
    try:
        project_path = request.args.get("project_path")
        workspace_param = request.args.get("workspace_id")
        logger.info(
            f"[GitLab] Fetching ignore list for user_id={user_id}, project_path={project_path}, workspace_id={workspace_param}"
        )
        ignore_records = get_user_ignores(
            user_id, project_path, workspace_param, "gitlab"
        )
        logger.info(
            f"[GitLab] Ignore list fetched: count={len(ignore_records)} for user_id={user_id}"
        )
        return (
            jsonify(
                {
                    "success": True,
                    "data": {
                        "user_id": user_id,
                        "project_path": project_path,
                        "ignores": ignore_records,
                        "total_count": len(ignore_records),
                    },
                }
            ),
            200,
        )
    except Exception as e:
        logger.error(f"Error getting user ignores (GitLab): {str(e)}")
        return (
            jsonify({"success": False, "error": {"message": "Internal server error"}}),
            500,
        )


@gitlab_bp.route("/scan/<repo_name>", methods=["DELETE"])
def delete_gitlab_scan_results(repo_name: str):
    """Delete GitLab scan results for a specific repository"""
    engine = None
    db_session = None
    try:
        logger.info(f"[GitLab] Starting delete request for repository: {repo_name}")

        # Get user_id from query parameter or request body
        user_id = request.args.get("user_id") or (request.get_json() or {}).get(
            "user_id"
        )

        logger.info(
            f"[GitLab] Delete request - repo_name: {repo_name}, user_id: {user_id}"
        )

        if not user_id:
            logger.warning(
                f"[GitLab] Delete request failed - missing user_id for repo: {repo_name}"
            )
            return (
                jsonify(
                    {"success": False, "error": {"message": "user_id is required"}}
                ),
                400,
            )

        # Create engine using the new function
        logger.info(f"[GitLab] Creating database connection for delete operation")
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Get all analyses for this repository
        logger.info(
            f"[GitLab] Querying analyses for repository: {repo_name}, user_id: {user_id}"
        )
        analyses = (
            db_session.query(GitLabAnalysisResult)
            .filter(
                GitLabAnalysisResult.repository_name == repo_name,
                GitLabAnalysisResult.user_id == user_id,
            )
            .all()
        )

        logger.info(
            f"[GitLab] Found {len(analyses)} analyses to delete for repository: {repo_name}"
        )

        # Even if no analyses, continue to remove any ignore records for this repo
        if not analyses:
            logger.info(
                f"[GitLab] No analyses found for repository: {repo_name}, user_id: {user_id}"
            )
        else:
            # Log details about analyses being deleted
            for i, analysis in enumerate(analyses):
                logger.info(
                    f"[GitLab] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                    f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                    f"Project ID: {analysis.project_id}"
                )

            # Delete all analyses
            logger.info(f"[GitLab] Starting deletion of {len(analyses)} analyses")
            for analysis in analyses:
                db_session.delete(analysis)
                logger.debug(f"[GitLab] Marked analysis {analysis.id} for deletion")

            logger.info(f"[GitLab] Committing deletion transaction")
            db_session.commit()
            logger.info(
                f"[GitLab] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
            )

        # Delete associated ignore records for this repo and user
        logger.info(
            f"[GitLab] Removing ignore records for repo: {repo_name}, user_id: {user_id}"
        )
        ignore_query = (
            db_session.query(IgnoredFinding)
            .filter(IgnoredFinding.repo_name == repo_name)
            .filter(IgnoredFinding.user_id == user_id)
            .filter(IgnoredFinding.repo_type == "gitlab")
        )
        ignore_records = ignore_query.all()
        logger.info(
            f"[GitLab] Found {len(ignore_records)} ignore records to delete for repo: {repo_name}"
        )
        for record in ignore_records:
            db_session.delete(record)
        db_session.commit()
        logger.info(
            f"[GitLab] Successfully deleted {len(ignore_records)} ignore records for repository: {repo_name}"
        )

        # Log details about analyses being deleted
        for i, analysis in enumerate(analyses):
            logger.info(
                f"[GitLab] Analysis {i+1}/{len(analyses)} - ID: {analysis.id}, "
                f"Status: {analysis.status}, Timestamp: {analysis.timestamp}, "
                f"Project ID: {analysis.project_id}"
            )

        # Delete all analyses
        logger.info(f"[GitLab] Starting deletion of {len(analyses)} analyses")
        for analysis in analyses:
            db_session.delete(analysis)
            logger.debug(f"[GitLab] Marked analysis {analysis.id} for deletion")

        logger.info(f"[GitLab] Committing deletion transaction")
        db_session.commit()
        logger.info(
            f"[GitLab] Successfully deleted {len(analyses)} analyses for repository: {repo_name}"
        )

        return jsonify("DONE")

    except Exception as e:
        logger.error(
            f"[GitLab] Error deleting scan results for repository {repo_name}: {str(e)}",
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
            logger.debug(f"[GitLab] Closing database session")
            db_session.close()
        if engine:
            logger.debug(f"[GitLab] Disposing database engine")
            engine.dispose()


@gitlab_bp.route("/get-branches", methods=["POST"])
def get_gitlab_repository_branches():
    """Get all branches for a GitLab repository"""

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
        project_path = request_data.get("project_path")
        project_path = request_data.get("project_path")
        access_token = request_data.get("access_token")

        # Validate required parameters
        if not project_path:
            return (
                {
                    "success": False,
                    "error": {"message": "project_path is required"},
                },
                400,
            )

        if not access_token:
            return (
                {
                    "success": False,
                    "error": {"message": "access_token is required"},
                },
                400,
            )

        # GitLab API base URL
        encoded_path = requests.utils.quote(project_path, safe="")
        api_base = f"https://gitlab.com/api/v4/projects/{encoded_path}"

        try:
            from utils import create_secure_client_session

            async with create_secure_client_session(timeout=30) as session:
                # Create authorization header
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                }

                # Get project to find default branch
                project_url = api_base
                async with session.get(project_url, headers=headers) as response:
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
                                    "message": f"Failed to access project: {error_message}"
                                },
                            },
                            response.status,
                        )

                    project_data = await response.json()
                    default_branch = project_data.get("default_branch", "main")
                    project_id = project_data.get("id")

                # Get all branches
                branches_url = f"{api_base}/repository/branches"
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

                    # Extract branch names
                    branch_names = [branch.get("name") for branch in branches_data]

                    # Check if 'rezliant' branch exists, if not create it from default branch
                    if "rezliant" not in branch_names:
                        logger.info(
                            f"'rezliant' branch not found, creating it from {default_branch}"
                        )

                        # Create the rezliant branch
                        create_branch_url = f"{api_base}/repository/branches"
                        create_branch_payload = {
                            "branch": "rezliant",
                            "ref": default_branch,
                        }
                        async with session.post(
                            create_branch_url,
                            headers=headers,
                            json=create_branch_payload,
                        ) as create_response:
                            if create_response.status in [200, 201]:
                                logger.info(f"Successfully created 'rezliant' branch")
                                branch_names.append("rezliant")
                            else:
                                error_text = await create_response.text()
                                logger.warning(
                                    f"Failed to create 'rezliant' branch: {error_text}"
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
                        f"Retrieved {len(branches)} branches for {project_path}"
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
            logger.error(f"Error fetching GitLab branches: {str(e)}")
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


@gitlab_bp.route("/create-pr", methods=["POST"])
def create_gitlab_merge_request():
    """Create a merge request (PR) with the fixed file content for GitLab"""

    async def ensure_webhook_exists(session, api_base, headers, project_id):
        """
        Checks if a webhook exists for the merge_request event and creates one if it doesn't.
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

            # Get webhook token for request verification
            webhook_token = os.getenv("GITLAB_WEBHOOK_TOKEN")
            if not webhook_token:
                logger.info(
                    "GITLAB_WEBHOOK_TOKEN not set, skipping webhook creation for security"
                )
                return (False, None, "GITLAB_WEBHOOK_TOKEN not configured")

            # List all project hooks (webhooks)
            list_webhooks_url = f"https://gitlab.com/api/v4/projects/{project_id}/hooks"
            async with session.get(list_webhooks_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.warning(
                        f"Failed to list webhooks (status {response.status}): {error_text}"
                    )
                    # If 403, likely insufficient permissions
                    if response.status == 403:
                        return (
                            False,
                            None,
                            "Insufficient permissions to manage webhooks (requires Maintainer/Owner role)",
                        )
                    return (
                        False,
                        None,
                        f"Failed to list webhooks: HTTP {response.status}",
                    )

                hooks = await response.json()

            # Check if a webhook already exists for this URL AND has merge_requests_events enabled
            # We need to verify both the URL matches and MR events are enabled
            existing_hook = None
            for hook in hooks:
                hook_url = hook.get("url")
                mr_events_enabled = hook.get("merge_requests_events", False)

                # Webhook must match URL and have merge request events enabled
                if hook_url == webhook_url and mr_events_enabled:
                    existing_hook = hook
                    break

            if existing_hook:
                logger.info(
                    f"Webhook already exists for {webhook_url} with merge_requests_events for project {project_id}"
                )
                return (True, webhook_url, None)

            # Create a new webhook with token verification
            logger.info(f"Creating webhook for {webhook_url}")

            webhook_config = {
                "url": webhook_url,
                "merge_requests_events": True,  # Only MR events
                "push_events": False,
                "issues_events": False,
                "wiki_page_events": False,
                "pipeline_events": False,
                "tag_push_events": False,
                "note_events": False,
                "enable_ssl_verification": True,
            }

            # Add token for request verification if available
            if webhook_token:
                webhook_config["token"] = webhook_token
                logger.info("Webhook will be created with token verification")

            async with session.post(
                list_webhooks_url, headers=headers, json=webhook_config
            ) as response:
                if response.status not in [200, 201]:
                    error_text = await response.text()
                    logger.warning(
                        f"Failed to create webhook (status {response.status}): {error_text}"
                    )
                    # If 403, likely insufficient permissions
                    if response.status == 403:
                        return (
                            False,
                            None,
                            "Insufficient permissions to create webhooks (requires Maintainer/Owner role)",
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

    async def create_mr_async():
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
        project_path = request_data.get("project_path")
        project_path = request_data.get("project_path")
        base_branch = request_data.get("base_branch")
        temp_file_path = request_data.get("file_path")
        access_token = request_data.get("access_token")
        file_content = request_data.get("file_content")

        user_id = request_data.get("user_id")
        workspace_id = request_data.get("workspace_id")
        finding_id = request_data.get(
            "finding_id"
        )  # Should be in format: id-filepath-linestart
        line_number = request_data.get("line_number")
        cwe_id = request_data.get("cwe_id")
        severity = request_data.get("severity")

        # Get explicit owner and repo if provided (preferred)
        owner = request_data.get("owner")
        repo = request_data.get("repo")

        # Import utility function
        from utils import extract_clean_file_path

        file_path = extract_clean_file_path(temp_file_path)

        # Optional parameters with defaults
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        default_branch_name = f"fix/{file_path.replace('/', '-')}-{timestamp}"
        new_branch = request_data.get("new_branch", default_branch_name)
        commit_message = request_data.get(
            "commit_message", f"Fix vulnerability in {file_path}"
        )
        mr_title = request_data.get(
            "pr_title", f"Fix: Security vulnerability in {file_path}"
        )
        mr_description = request_data.get(
            "pr_body", f"This MR fixes a security vulnerability in {file_path}"
        )

        # Validate required parameters
        required_params = {
            "project_path": project_path,
            "file_path": file_path,
            "file_content": file_content,
            "access_token": access_token,
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

        # GitLab API base URL
        encoded_path = requests.utils.quote(project_path, safe="")
        api_base = f"https://gitlab.com/api/v4/projects/{encoded_path}"

        try:
            from utils import create_secure_client_session
            import base64

            async with create_secure_client_session(timeout=60) as session:
                # Create authorization header
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                }

                # Step 1: Get project info and default branch if base_branch not provided
                project_url = api_base
                async with session.get(project_url, headers=headers) as response:
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
                                    "message": f"Failed to access project: {error_message}"
                                },
                            },
                            response.status,
                        )

                    project_data = await response.json()
                    project_id = project_data.get("id")
                    default_branch = project_data.get("default_branch", "main")
                    # Get the actual path_with_namespace (owner/repo format)
                    actual_project_path = project_data.get(
                        "path_with_namespace", project_path
                    )

                # If base_branch is provided, validate it exists; otherwise use default
                if base_branch:
                    branch_check_url = f"{api_base}/repository/branches/{base_branch}"
                    async with session.get(
                        branch_check_url, headers=headers
                    ) as response:
                        if response.status != 200:
                            logger.warning(
                                f"Base branch '{base_branch}' not found, using default branch '{default_branch}'"
                            )
                            base_branch = default_branch
                else:
                    base_branch = default_branch

                logger.info(f"Using base branch: {base_branch}")

                # Step 2: Create a new branch from the base branch
                create_branch_url = f"{api_base}/repository/branches"
                create_branch_payload = {
                    "branch": new_branch,
                    "ref": base_branch,
                }

                async with session.post(
                    create_branch_url, headers=headers, json=create_branch_payload
                ) as response:
                    if response.status not in [200, 201]:
                        # Check if branch already exists
                        error_text = await response.text()
                        if "Branch already exists" in error_text:
                            logger.warning(
                                f"Branch '{new_branch}' already exists, will use it"
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

                # Step 3: Commit the file change to the new branch
                # GitLab uses a different approach - we create/update a file directly
                commit_file_url = f"{api_base}/repository/files/{requests.utils.quote(file_path, safe='')}"

                # Check if file exists first
                file_exists = False
                async with session.get(
                    f"{commit_file_url}?ref={new_branch}", headers=headers
                ) as response:
                    file_exists = response.status == 200

                # Prepare commit payload
                commit_payload = {
                    "branch": new_branch,
                    "content": file_content,
                    "commit_message": commit_message,
                }

                # Use PUT for update, POST for create
                if file_exists:
                    async with session.put(
                        commit_file_url, headers=headers, json=commit_payload
                    ) as response:
                        if response.status not in [200, 201]:
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
                                        "message": f"Failed to update file: {error_message}"
                                    },
                                },
                                response.status,
                            )
                else:
                    async with session.post(
                        commit_file_url, headers=headers, json=commit_payload
                    ) as response:
                        if response.status not in [200, 201]:
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
                                        "message": f"Failed to create file: {error_message}"
                                    },
                                },
                                response.status,
                            )

                logger.info(f"File committed successfully to branch {new_branch}")

                # Step 4: Create a merge request
                create_mr_url = f"{api_base}/merge_requests"
                create_mr_payload = {
                    "source_branch": new_branch,
                    "target_branch": base_branch,
                    "title": mr_title,
                    "description": mr_description,
                }

                async with session.post(
                    create_mr_url, headers=headers, json=create_mr_payload
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
                                    "message": f"Failed to create merge request: {error_message}"
                                },
                            },
                            response.status,
                        )

                    mr_data = await response.json()
                    mr_url = mr_data.get("web_url")
                    mr_number = str(mr_data.get("iid"))

                    logger.info(
                        f"Successfully created merge request: {mr_url} from {new_branch} to {base_branch}"
                    )

                    # Step 5: Attempt to create webhook for MR updates (non-blocking)
                    webhook_enabled = False
                    webhook_url_result = None
                    webhook_error = None

                    try:
                        # Get project ID for webhook creation
                        project_id = project_data.get("id")

                        if project_id:
                            webhook_enabled, webhook_url_result, webhook_error = (
                                await ensure_webhook_exists(
                                    session, api_base, headers, project_id
                                )
                            )
                            if not webhook_enabled:
                                logger.warning(
                                    f"Webhook creation skipped or failed: {webhook_error}. "
                                    "MR will not have live updates."
                                )
                        else:
                            logger.warning(
                                "Could not retrieve project ID for webhook creation"
                            )
                            webhook_error = "Missing project ID"
                    except Exception as webhook_exc:
                        logger.warning(
                            f"Exception while creating webhook: {str(webhook_exc)}. "
                            "MR will not have live updates.",
                            exc_info=True,
                        )
                        webhook_error = f"Exception: {str(webhook_exc)}"

                    # Create fix request record if tracking parameters were provided
                    if user_id and finding_id:
                        try:
                            # Create database session for fix request
                            from api import create_api_engine
                            from models import FixRequest
                            from sqlalchemy.orm import sessionmaker
                            from utils import get_repository_identifier

                            fix_engine = create_api_engine()
                            FixSession = sessionmaker(bind=fix_engine)
                            fix_session = FixSession()

                            try:
                                # Build repo identifier using utility function
                                # Prefer explicit owner/repo from request, fallback to parsing path_with_namespace
                                repo_owner = owner
                                repo_name = repo

                                if not repo_owner or not repo_name:
                                    # Fallback: parse from actual_project_path (path_with_namespace)
                                    if "/" in actual_project_path:
                                        repo_owner, repo_name = (
                                            actual_project_path.rsplit("/", 1)
                                        )
                                    else:
                                        # Last fallback if path doesn't contain /
                                        logger.warning(
                                            f"Could not parse owner/repo from path: {actual_project_path}"
                                        )
                                        repo_owner = actual_project_path
                                        repo_name = actual_project_path

                                repo_identifier = get_repository_identifier(
                                    "gitlab", owner=repo_owner, repo=repo_name
                                )

                                # Create fix request with separate fields
                                fix_request = FixRequest(
                                    user_id=user_id,
                                    workspace_id=workspace_id,
                                    repo_type="gitlab",
                                    repo_identifier=repo_identifier,
                                    branch_name=base_branch or "main",
                                    finding_id=finding_id,
                                    file_path=file_path,
                                    line_start=line_number,  # Use line_number from request
                                    cwe_id=cwe_id,
                                    severity=severity,
                                    pr_url=mr_url,
                                    pr_number=mr_number,
                                    pr_title=mr_title,
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
                            # Don't fail the MR creation if fix request fails

                    return (
                        {
                            "success": True,
                            "data": {
                                "pullRequest": {
                                    "url": mr_url,
                                    "number": mr_number,
                                    "title": mr_title,
                                    "source_branch": new_branch,
                                    "target_branch": base_branch,
                                },
                                "webhook": {
                                    "enabled": webhook_enabled,
                                    "url": webhook_url_result,
                                    "error": webhook_error,
                                    "liveUpdates": webhook_enabled,
                                },
                            },
                        },
                        201,
                    )

        except Exception as e:
            logger.error(f"Error creating GitLab merge request: {str(e)}")
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
        result, status_code = asyncio.run(create_mr_async())
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error running async create merge request: {str(e)}")
        return (
            jsonify(
                {
                    "success": False,
                    "error": {"message": f"Internal server error: {str(e)}"},
                }
            ),
            500,
        )
