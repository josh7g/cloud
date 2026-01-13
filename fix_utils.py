"""
Utilities for managing fix request status on findings
"""

import logging
from typing import List, Dict, Optional
from models import FixRequest
from sqlalchemy.orm import Session
from datetime import datetime
from utils import extract_clean_file_path

logger = logging.getLogger(__name__)


def get_finding_key(finding_id: str, file_path: str, line_start: int) -> str:
    """
    Create a composite key for a finding, matching the frontend format.
    Format: {finding_id}-{file_path}-{line_start}

    Normalizes the file_path by removing temporary directory prefixes to match
    what's stored in the database.

    Args:
        finding_id: The rule ID (e.g., "javascript.express.security.sql-injection")
        file_path: Path to the file containing the finding
        line_start: Starting line number of the finding

    Returns:
        Composite string key in format "finding_id-file_path-line_start"
    """
    # Normalize file path to match database storage (removes temp prefixes)
    clean_path = extract_clean_file_path(file_path)
    return f"{finding_id}-{clean_path}-{line_start}"


def add_fix_status_to_findings(
    user_id: str,
    repo_identifier: str,
    findings: List[Dict],
    workspace_id: Optional[str] = None,
    repo_type: str = "github",
    db_session: Optional[Session] = None,
) -> List[Dict]:
    """
    Add fix request status to findings based on existing fix_requests records.

    Args:
        user_id: User ID
        repo_identifier: Repository identifier (e.g., "https://github.com/owner/repo" or "owner/repo")
        findings: List of finding dictionaries
        workspace_id: Optional workspace ID for filtering
        repo_type: Type of repository (github, gitlab, azure_devops, codecommit)
        db_session: Optional existing database session

    Returns:
        List of findings with fix_status fields added
    """
    if not findings or not user_id:
        return findings

    # Import here to avoid circular imports
    from api import create_api_engine
    from sqlalchemy.orm import sessionmaker

    should_close_session = db_session is None
    engine = None

    try:
        # Create session if not provided
        if db_session is None:
            engine = create_api_engine()
            Session = sessionmaker(bind=engine)
            db_session = Session()

        # Normalize repo_identifier to full URL format if needed
        if not repo_identifier.startswith("http"):
            # Assume it's in owner/repo format, convert based on repo_type
            if repo_type == "github":
                repo_identifier = f"https://github.com/{repo_identifier}"
            elif repo_type == "gitlab":
                repo_identifier = f"https://gitlab.com/{repo_identifier}"
            # Add more mappings as needed

        # Build query for fix requests
        query = db_session.query(FixRequest).filter(
            FixRequest.repo_identifier == repo_identifier,
            FixRequest.repo_type == repo_type,
        )

        # Add workspace filter if provided
        if workspace_id:
            query = query.filter(FixRequest.workspace_id == workspace_id)

        if not workspace_id and user_id:
            query = query.filter(FixRequest.user_id == user_id)

        # Get all fix requests for this repo
        fix_requests = query.all()

        if not fix_requests:
            # No fix requests found, add default status to all findings
            for finding in findings:
                finding["fix_status"] = None
                finding["pr_url"] = None
                finding["pr_number"] = None
                finding["pr_created_at"] = None
                finding["pr_merged_at"] = None
                finding["fix_error"] = None
                finding["webhook_enabled"] = None
                finding["webhook_url"] = None
            return findings

        # Create a lookup map: finding_key_string -> fix_request
        fix_map = {}
        for fix_req in fix_requests:
            # Build composite key matching frontend format
            key = get_finding_key(
                fix_req.finding_id, fix_req.file_path, fix_req.line_start or 0
            )
            fix_map[key] = fix_req

        logger.info(f"Found {len(fix_requests)} fix requests for {repo_identifier}")

        # Add fix status to each finding
        for finding in findings:
            # Extract components for this finding
            finding_id = finding.get("id", "")
            file_path = finding.get("file", "")
            line_start = finding.get("line_start", 0)

            # Create lookup key using the same function
            finding_key = get_finding_key(finding_id, file_path, line_start)

            # Look up fix request
            fix_req = fix_map.get(finding_key)

            if fix_req:
                # Add fix request information to finding
                finding["fix_status"] = fix_req.status
                finding["pr_url"] = fix_req.pr_url
                finding["pr_number"] = fix_req.pr_number
                finding["pr_title"] = fix_req.pr_title
                finding["pr_created_at"] = (
                    fix_req.pr_created_at.isoformat() if fix_req.pr_created_at else None
                )
                finding["pr_merged_at"] = (
                    fix_req.pr_merged_at.isoformat() if fix_req.pr_merged_at else None
                )
                finding["pr_closed_at"] = (
                    fix_req.pr_closed_at.isoformat() if fix_req.pr_closed_at else None
                )
                finding["fix_error"] = fix_req.error
                finding["fix_description"] = fix_req.fix_description
                finding["fix_request_id"] = fix_req.id
                # Webhook info - enabled derived from URL presence
                finding["webhook_enabled"] = bool(fix_req.webhook_url)
                finding["webhook_url"] = fix_req.webhook_url
            else:
                # No fix request found for this finding
                finding["fix_status"] = None
                finding["pr_url"] = None
                finding["pr_number"] = None
                finding["pr_created_at"] = None
                finding["pr_merged_at"] = None
                finding["fix_error"] = None
                finding["webhook_enabled"] = None
                finding["webhook_url"] = None

        logger.info(f"Added fix status to {len(findings)} findings")
        return findings

    except Exception as e:
        logger.error(f"Error adding fix status to findings: {str(e)}", exc_info=True)
        # Return findings unchanged if there's an error
        return findings

    finally:
        # Only close session if we created it
        if should_close_session and db_session:
            db_session.close()
        if engine:
            engine.dispose()


def get_fix_requests_for_repo(
    user_id: str,
    repo_identifier: str,
    workspace_id: Optional[str] = None,
    repo_type: str = "github",
    status: Optional[str] = None,
) -> List[Dict]:
    """
    Get all fix requests for a repository.

    Args:
        user_id: User ID
        repo_identifier: Repository identifier
        workspace_id: Optional workspace ID for filtering
        repo_type: Type of repository
        status: Optional status filter (pending, pr_created, pr_merged, pr_closed, failed)

    Returns:
        List of fix request dictionaries
    """
    from api import create_api_engine
    from sqlalchemy.orm import sessionmaker

    engine = None
    db_session = None

    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Build query
        query = db_session.query(FixRequest).filter(
            FixRequest.user_id == user_id,
            FixRequest.repo_identifier == repo_identifier,
            FixRequest.repo_type == repo_type,
        )

        if workspace_id:
            query = query.filter(FixRequest.workspace_id == workspace_id)

        if status:
            query = query.filter(FixRequest.status == status)

        fix_requests = query.order_by(FixRequest.created_at.desc()).all()

        return [fix_req.to_dict() for fix_req in fix_requests]

    except Exception as e:
        logger.error(f"Error getting fix requests: {str(e)}", exc_info=True)
        return []

    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()
