"""
Utilities for managing ignored findings across different ignore types
"""

import logging
from typing import List, Dict, Optional, Any
from models import db, IgnoredFinding
from sqlalchemy import and_

logger = logging.getLogger(__name__)


def normalize_file_path(file_path):
    """Extract the repository-relative path from a full file path"""
    if not file_path:
        return file_path

    # Handle temporary scanner directories
    if "/repo_" in file_path:
        # Find the repo directory and get everything after the timestamp
        parts = file_path.split("/repo_")[1]
        # Remove the timestamp part (format: repo_YYYYMMDD_HHMMSS_hash)
        if "/" in parts:
            # Skip the timestamp directory and get the actual repo path
            actual_path = "/" + "/".join(parts.split("/")[1:])
            return actual_path

    # Handle other temporary directory patterns
    if "/tmp/" in file_path and "/repo" in file_path:
        # Extract everything after the actual repo content starts
        # Look for common repo structure indicators
        repo_indicators = [
            "/BrokenAuth/",
            "/src/",
            "/app/",
            "/lib/",
            "/test/",
            "/tests/",
        ]
        for indicator in repo_indicators:
            if indicator in file_path:
                idx = file_path.find(indicator)
                return file_path[idx:]

    return file_path


def create_ignore_record(
    user_id, repo_name, ignore_data, workspace_id=None, repo_type=None
):
    """Create ignore record with metadata extraction and CWE support using dedicated cwe_id column"""
    from models import IgnoredFinding, AnalysisResult
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import desc
    from api import create_api_engine
    import logging
    from datetime import datetime

    logger = logging.getLogger(__name__)
    engine = None
    db_session = None

    try:
        # Validate ignore_type - now includes CWE types
        valid_ignore_types = [
            "finding",
            "rule_in_file",
            "file",
            "rule_in_repo",
            "cwe_in_file",
            "cwe_in_repo",
        ]
        ignore_type = ignore_data.get("ignore_type")

        if ignore_type not in valid_ignore_types:
            return {
                "success": False,
                "message": f'Invalid ignore_type. Must be one of: {", ".join(valid_ignore_types)}',
            }

        # Get basic ignore data
        finding_id = ignore_data.get("finding_id")
        file_path = ignore_data.get("file_path")
        code_snippet = ignore_data.get("code_snippet")
        reason = ignore_data.get("reason", "")
        cwe_id = ignore_data.get("cwe_id")  # New CWE parameter

        # Normalize file path if provided
        if file_path:
            file_path = normalize_file_path(file_path)

        # Validation based on ignore type
        if ignore_type == "finding":
            if not all([finding_id, file_path, code_snippet]):
                return {
                    "success": False,
                    "message": "finding_id, file_path, and code_snippet are required for finding ignore_type",
                }
        elif ignore_type == "rule_in_file":
            if not all([finding_id, file_path]):
                return {
                    "success": False,
                    "message": "finding_id and file_path are required for rule_in_file ignore_type",
                }
        elif ignore_type == "file":
            if not file_path:
                return {
                    "success": False,
                    "message": "file_path is required for file ignore_type",
                }
        elif ignore_type == "rule_in_repo":
            if not finding_id:
                return {
                    "success": False,
                    "message": "finding_id is required for rule_in_repo ignore_type",
                }
        elif ignore_type == "cwe_in_file":
            if not all([cwe_id, file_path]):
                return {
                    "success": False,
                    "message": "cwe_id and file_path are required for cwe_in_file ignore_type",
                }
        elif ignore_type == "cwe_in_repo":
            if not cwe_id:
                return {
                    "success": False,
                    "message": "cwe_id is required for cwe_in_repo ignore_type",
                }

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        severity = None
        cwe = []
        owasp = []
        category = None
        message = None

        try:
            # Get the latest analysis for this repo with workspace filtering
            query = db_session.query(AnalysisResult).filter_by(
                repository_name=repo_name
            )
            
            # Apply workspace filtering if provided
            if workspace_id:
                query = query.filter_by(workspace_id=workspace_id)
                logger.info(
                    f"Filtering analysis for metadata extraction by workspace_id: {workspace_id}"
                )
            elif user_id:
                # Fallback to user_id if no workspace_id
                query = query.filter_by(user_id=user_id)
                logger.info(
                    f"Filtering analysis for metadata extraction by user_id: {user_id}"
                )
            
            analysis = query.order_by(desc(AnalysisResult.timestamp)).first()

            if analysis and analysis.results:
                findings = analysis.results.get("findings", [])
                normalized_ignore_path = (
                    normalize_file_path(file_path) if file_path else None
                )

                logger.info(
                    f"Searching {len(findings)} findings for match - finding_id: {finding_id}, "
                    f"file: {normalized_ignore_path}, ignore_type: {ignore_type}"
                )

                # Normalize code snippet for comparison (strip whitespace)
                normalized_code_snippet = code_snippet.strip() if code_snippet else ""

                # Find the matching finding
                target_finding = None
                for finding in findings:
                    finding_file = normalize_file_path(finding.get("file", ""))
                    finding_cwes = finding.get("cwe", [])
                    finding_code_snippet = finding.get("code_snippet", "").strip()

                    # Match based on ignore type
                    if ignore_type == "finding":
                        # Exact match: rule + file + code snippet (with normalized whitespace)
                        if (
                            finding.get("id") == finding_id
                            and finding_file == normalized_ignore_path
                            and finding_code_snippet == normalized_code_snippet
                        ):
                            target_finding = finding
                            logger.info(
                                f"Found matching finding for metadata extraction: "
                                f"id={finding.get('id')}, file={finding_file}"
                            )
                            break
                    elif ignore_type == "rule_in_file":
                        # Rule in specific file
                        if (
                            finding.get("id") == finding_id
                            and finding_file == normalized_ignore_path
                        ):
                            target_finding = finding
                            logger.info(
                                f"Found matching rule_in_file finding: "
                                f"id={finding.get('id')}, file={finding_file}"
                            )
                            break
                    elif ignore_type == "file":
                        # Any finding in this file
                        if finding_file == normalized_ignore_path:
                            target_finding = finding
                            logger.info(
                                f"Found matching file finding: file={finding_file}"
                            )
                            break
                    elif ignore_type == "rule_in_repo":
                        # This rule anywhere in repo
                        if finding.get("id") == finding_id:
                            target_finding = finding
                            logger.info(
                                f"Found matching rule_in_repo finding: id={finding.get('id')}"
                            )
                            break
                    elif ignore_type == "cwe_in_file":
                        # CWE in specific file - normalize CWE IDs for comparison
                        finding_cwe_ids = []
                        for cwe_entry in finding_cwes:
                            if isinstance(cwe_entry, str):
                                # Extract CWE ID from entries like "CWE-269: Description"
                                cwe_id_from_entry = (
                                    cwe_entry.split(":")[0].strip()
                                    if ":" in cwe_entry
                                    else cwe_entry.strip()
                                )
                                finding_cwe_ids.append(cwe_id_from_entry)
                        
                        if (
                            cwe_id in finding_cwe_ids
                            and finding_file == normalized_ignore_path
                        ):
                            target_finding = finding
                            logger.info(
                                f"Found matching cwe_in_file finding: "
                                f"cwe_id={cwe_id}, file={finding_file}"
                            )
                            break
                    elif ignore_type == "cwe_in_repo":
                        # CWE anywhere in repo - normalize CWE IDs for comparison
                        finding_cwe_ids = []
                        for cwe_entry in finding_cwes:
                            if isinstance(cwe_entry, str):
                                # Extract CWE ID from entries like "CWE-269: Description"
                                cwe_id_from_entry = (
                                    cwe_entry.split(":")[0].strip()
                                    if ":" in cwe_entry
                                    else cwe_entry.strip()
                                )
                                finding_cwe_ids.append(cwe_id_from_entry)
                        
                        if cwe_id in finding_cwe_ids:
                            target_finding = finding
                            logger.info(
                                f"Found matching cwe_in_repo finding: cwe_id={cwe_id}"
                            )
                            break

                # Extract metadata from found finding
                if target_finding:
                    severity = target_finding.get("severity", "").upper()
                    cwe = target_finding.get("cwe", [])
                    owasp = target_finding.get("owasp", [])
                    category = target_finding.get("category", "")
                    message = target_finding.get("message", "")

                    logger.info(
                        f"Auto-extracted metadata: severity={severity}, cwe={len(cwe)} items, category={category}"
                    )
                else:
                    logger.warning(
                        f"Could not find matching finding for metadata extraction: "
                        f"finding_id={finding_id}, cwe_id={cwe_id}, "
                        f"file={normalized_ignore_path}, ignore_type={ignore_type}, "
                        f"workspace_id={workspace_id}, total_findings={len(findings)}"
                    )

        except Exception as e:
            logger.warning(f"Failed to auto-extract metadata: {str(e)}")
            # Continue without metadata - not a critical failure

        # Check if ignore already exists using raw SQL to avoid SQLAlchemy model issues
        if ignore_type == "finding":
            query_sql = """
                SELECT id FROM ignored_findings 
                WHERE user_id = :user_id AND repo_name = :repo_name 
                AND ignore_type = :ignore_type AND finding_id = :finding_id 
                AND file_path = :file_path AND code_snippet = :code_snippet
                AND (workspace_id = :workspace_id OR (:workspace_id IS NULL AND workspace_id IS NULL))
                AND (repo_type = :repo_type OR (:repo_type IS NULL AND repo_type IS NULL))
            """
            params = {
                "user_id": user_id,
                "repo_name": repo_name,
                "ignore_type": ignore_type,
                "finding_id": finding_id,
                "file_path": file_path,
                "code_snippet": code_snippet,
                "workspace_id": workspace_id,
                "repo_type": repo_type,
            }
        elif ignore_type == "rule_in_file":
            query_sql = """
                SELECT id FROM ignored_findings 
                WHERE user_id = :user_id AND repo_name = :repo_name 
                AND ignore_type = :ignore_type AND finding_id = :finding_id AND file_path = :file_path
                AND code_snippet = :code_snippet
                AND (workspace_id = :workspace_id OR (:workspace_id IS NULL AND workspace_id IS NULL))
                AND (repo_type = :repo_type OR (:repo_type IS NULL AND repo_type IS NULL))
            """
            params = {
                "user_id": user_id,
                "repo_name": repo_name,
                "ignore_type": ignore_type,
                "finding_id": finding_id,
                "file_path": file_path,
                "code_snippet": code_snippet,
                "workspace_id": workspace_id,
                "repo_type": repo_type,
            }
        elif ignore_type == "file":
            query_sql = """
                SELECT id FROM ignored_findings 
                WHERE user_id = :user_id AND repo_name = :repo_name 
                AND ignore_type = :ignore_type AND file_path = :file_path
                AND code_snippet = :code_snippet
                AND (workspace_id = :workspace_id OR (:workspace_id IS NULL AND workspace_id IS NULL))
                AND (repo_type = :repo_type OR (:repo_type IS NULL AND repo_type IS NULL))
            """
            params = {
                "user_id": user_id,
                "repo_name": repo_name,
                "ignore_type": ignore_type,
                "file_path": file_path,
                "code_snippet": code_snippet,
                "workspace_id": workspace_id,
                "repo_type": repo_type,
            }
        elif ignore_type == "rule_in_repo":
            query_sql = """
                SELECT id FROM ignored_findings 
                WHERE user_id = :user_id AND repo_name = :repo_name 
                AND ignore_type = :ignore_type AND finding_id = :finding_id
                AND code_snippet = :code_snippet
                AND (workspace_id = :workspace_id OR (:workspace_id IS NULL AND workspace_id IS NULL))
                AND (repo_type = :repo_type OR (:repo_type IS NULL AND repo_type IS NULL))
            """
            params = {
                "user_id": user_id,
                "repo_name": repo_name,
                "ignore_type": ignore_type,
                "finding_id": finding_id,
                "code_snippet": code_snippet,
                "workspace_id": workspace_id,
                "repo_type": repo_type,
            }
        elif ignore_type == "cwe_in_file":
            query_sql = """
                SELECT id FROM ignored_findings 
                WHERE user_id = :user_id AND repo_name = :repo_name 
                AND ignore_type = :ignore_type AND cwe_id = :cwe_id AND file_path = :file_path
                AND code_snippet = :code_snippet
                AND (workspace_id = :workspace_id OR (:workspace_id IS NULL AND workspace_id IS NULL))
                AND (repo_type = :repo_type OR (:repo_type IS NULL AND repo_type IS NULL))
            """
            params = {
                "user_id": user_id,
                "repo_name": repo_name,
                "ignore_type": ignore_type,
                "cwe_id": cwe_id,
                "file_path": file_path,
                "code_snippet": code_snippet,
                "workspace_id": workspace_id,
                "repo_type": repo_type,
            }
        elif ignore_type == "cwe_in_repo":
            query_sql = """
                SELECT id FROM ignored_findings 
                WHERE user_id = :user_id AND repo_name = :repo_name 
                AND ignore_type = :ignore_type AND cwe_id = :cwe_id
                AND code_snippet = :code_snippet
                AND (workspace_id = :workspace_id OR (:workspace_id IS NULL AND workspace_id IS NULL))
                AND (repo_type = :repo_type OR (:repo_type IS NULL AND repo_type IS NULL))
            """
            params = {
                "user_id": user_id,
                "repo_name": repo_name,
                "ignore_type": ignore_type,
                "cwe_id": cwe_id,
                "code_snippet": code_snippet,
                "workspace_id": workspace_id,
                "repo_type": repo_type,
            }

        from sqlalchemy import text

        existing_result = db_session.execute(text(query_sql), params).fetchone()

        if existing_result:
            return {
                "success": False,
                "message": f"This {ignore_type} is already ignored",
                "existing_reason": "Previously ignored",
                "existing_ignored_at": None,
            }

        # Create new ignore record using raw SQL to avoid SQLAlchemy model issues
        ignored_at = datetime.utcnow()

        insert_sql = """
            INSERT INTO ignored_findings 
            (user_id, repo_name, ignore_type, finding_id, file_path, code_snippet, cwe_id, reason, ignored_at, ignored_by, workspace_id, repo_type)
            VALUES (:user_id, :repo_name, :ignore_type, :finding_id, :file_path, :code_snippet, :cwe_id, :reason, :ignored_at, :ignored_by, :workspace_id, :repo_type)
            RETURNING id
        """

        insert_params = {
            "user_id": user_id,
            "repo_name": repo_name,
            "ignore_type": ignore_type,
            "finding_id": finding_id,
            "file_path": file_path,
            "code_snippet": code_snippet,
            "cwe_id": cwe_id if ignore_type.startswith("cwe_") else None,
            "reason": reason,
            "ignored_at": ignored_at,
            "ignored_by": user_id,
            "workspace_id": workspace_id,
            "repo_type": repo_type,
        }

        result = db_session.execute(text(insert_sql), insert_params)
        ignore_id = result.fetchone()[0]
        db_session.commit()

        logger.info(
            f"Created ignore record with extracted metadata: {ignore_type}, severity={severity}"
        )

        # update findings in the database to mark them as ignored
        try:
            update_findings_ignored_status(
                user_id=user_id,
                repo_name=repo_name,
                ignore_type=ignore_type,
                finding_id=finding_id,
                file_path=file_path,
                code_snippet=code_snippet,
                cwe_id=cwe_id,
                workspace_id=workspace_id,
                repo_type=repo_type,
                db_session=db_session,
            )
        except Exception as update_error:
            logger.warning(
                f"Failed to update findings ignored status in database: {str(update_error)}"
            )

        return {
            "success": True,
            "message": f"Successfully ignored {ignore_type}",
            "ignore_id": ignore_id,
            "metadata": {
                "severity": severity,
                "cwe": cwe if cwe else [],
                "category": category,
                "ignored_at": ignored_at.isoformat(),
                "cwe_id": cwe_id if ignore_type.startswith("cwe_") else None,
            },
        }

    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Error creating ignore record: {str(e)}")
        return {"success": False, "message": f"Database error: {str(e)}"}
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


def update_findings_ignored_status(
    user_id,
    repo_name,
    ignore_type,
    finding_id=None,
    file_path=None,
    code_snippet=None,
    cwe_id=None,
    workspace_id=None,
    repo_type=None,
    db_session=None,
):
    """
    Update the ignored field of findings in the database analysis results.
    This function marks findings as ignored in the JSONB results.findings array.
    """
    from models import (
        AnalysisResult,
        GitLabAnalysisResult,
        AzureDevOpsAnalysisResult,
        RepositoryScanResult,
    )
    from sqlalchemy import desc
    from utils import get_repository_identifier

    if not db_session:
        logger.warning("No database session provided, skipping finding update")
        return

    try:
        normalized_file_path = normalize_file_path(file_path) if file_path else None

        analysis = None

        if repo_type == "github" or repo_type == "git":
            query = db_session.query(AnalysisResult).filter_by(
                repository_name=repo_name
            )
            if workspace_id:
                query = query.filter_by(workspace_id=workspace_id)
                logger.info(
                    f"Filtering analysis for update by workspace_id: {workspace_id}"
                )
            elif user_id:
                # Fallback to user_id if no workspace_id
                query = query.filter_by(user_id=user_id)
                logger.info(
                    f"Filtering analysis for update by user_id: {user_id} (no workspace filter)"
                )
            analysis = query.order_by(desc(AnalysisResult.timestamp)).first()

        elif repo_type == "gitlab":
            query = db_session.query(GitLabAnalysisResult).filter_by(
                repository_name=repo_name
            )
            if workspace_id:
                query = query.filter_by(workspace=workspace_id)
                logger.info(
                    f"Filtering GitLab analysis for update by workspace_id: {workspace_id}"
                )
            elif user_id:
                # Fallback to user_id if no workspace_id
                query = query.filter_by(user_id=user_id)
                logger.info(
                    f"Filtering GitLab analysis for update by user_id: {user_id} (no workspace filter)"
                )
            analysis = query.order_by(desc(GitLabAnalysisResult.timestamp)).first()

        elif repo_type == "azure-devops" or repo_type == "azure_devops":
            parts = repo_name.split("/")
            if len(parts) >= 3:
                organization_name = parts[0]
                project_name = parts[1]
                repository_name = "/".join(parts[2:])
                query = (
                    db_session.query(AzureDevOpsAnalysisResult)
                    .filter_by(
                        organization_name=organization_name,
                        project_name=project_name,
                        repository_name=repository_name,
                    )
                )
                if workspace_id:
                    query = query.filter_by(workspace_id=workspace_id)
                    logger.info(
                        f"Filtering Azure DevOps analysis for update by workspace_id: {workspace_id}"
                    )
                elif user_id:
                    # Fallback to user_id if no workspace_id
                    query = query.filter_by(user_id=user_id)
                    logger.info(
                        f"Filtering Azure DevOps analysis for update by user_id: {user_id} (no workspace filter)"
                    )
                analysis = query.order_by(
                    desc(AzureDevOpsAnalysisResult.timestamp)
                ).first()

        elif repo_type == "codecommit":
            parts = repo_name.split("/")
            if len(parts) >= 2:
                region = parts[0]
                repo = "/".join(parts[1:])
                repo_identifier = get_repository_identifier(
                    "codecommit", region=region, repo=repo
                )
                query = db_session.query(RepositoryScanResult).filter_by(
                    repo_identifier=repo_identifier, repo_type="codecommit"
                )
                if workspace_id:
                    query = query.filter_by(workspace_id=workspace_id)
                    logger.info(
                        f"Filtering CodeCommit analysis for update by workspace_id: {workspace_id}"
                    )
                elif user_id:
                    # Fallback to user_id if no workspace_id
                    query = query.filter_by(user_id=user_id)
                    logger.info(
                        f"Filtering CodeCommit analysis for update by user_id: {user_id} (no workspace filter)"
                    )
                analysis = query.order_by(desc(RepositoryScanResult.timestamp)).first()

        if not analysis or not analysis.results:
            logger.warning(
                f"No analysis result found for repo_name={repo_name}, repo_type={repo_type}, "
                f"workspace_id={workspace_id}, user_id={user_id}"
            )
            return

        findings = analysis.results.get("findings", [])
        if not findings:
            logger.warning(f"No findings found in analysis result for {repo_name}")
            return

        # Normalize code snippet for comparison
        normalized_code_snippet = code_snippet.strip() if code_snippet else ""

        # Update findings based on ignore type
        updated_count = 0
        logger.info(
            f"Updating findings ignored status - ignore_type={ignore_type}, "
            f"finding_id={finding_id}, cwe_id={cwe_id}, file={normalized_file_path}, "
            f"total_findings={len(findings)}"
        )
        
        for finding in findings:
            finding_file = normalize_file_path(finding.get("file", ""))
            finding_cwes = finding.get("cwe", [])
            finding_code_snippet = finding.get("code_snippet", "").strip()

            should_mark_ignored = False

            # Match based on ignore type
            if ignore_type == "finding":
                # Exact match: rule + file + code snippet (with normalized whitespace)
                if (
                    finding.get("id") == finding_id
                    and finding_file == normalized_file_path
                    and finding_code_snippet == normalized_code_snippet
                ):
                    should_mark_ignored = True

            elif ignore_type == "rule_in_file":
                # Rule in specific file
                if (
                    finding.get("id") == finding_id
                    and finding_file == normalized_file_path
                ):
                    should_mark_ignored = True

            elif ignore_type == "file":
                # Any finding in this file
                if finding_file == normalized_file_path:
                    should_mark_ignored = True

            elif ignore_type == "rule_in_repo":
                # This rule anywhere in repo
                if finding.get("id") == finding_id:
                    should_mark_ignored = True

            elif ignore_type == "cwe_in_file":
                # CWE in specific file - normalize CWE IDs for comparison
                finding_cwe_ids = []
                for cwe_entry in finding_cwes:
                    if isinstance(cwe_entry, str):
                        # Extract CWE ID from entries like "CWE-269: Description"
                        cwe_id_from_entry = (
                            cwe_entry.split(":")[0].strip()
                            if ":" in cwe_entry
                            else cwe_entry.strip()
                        )
                        finding_cwe_ids.append(cwe_id_from_entry)
                
                if (
                    cwe_id
                    and cwe_id in finding_cwe_ids
                    and finding_file == normalized_file_path
                ):
                    should_mark_ignored = True

            elif ignore_type == "cwe_in_repo":
                # CWE anywhere in repo - normalize CWE IDs for comparison
                finding_cwe_ids = []
                for cwe_entry in finding_cwes:
                    if isinstance(cwe_entry, str):
                        # Extract CWE ID from entries like "CWE-269: Description"
                        cwe_id_from_entry = (
                            cwe_entry.split(":")[0].strip()
                            if ":" in cwe_entry
                            else cwe_entry.strip()
                        )
                        finding_cwe_ids.append(cwe_id_from_entry)
                
                if cwe_id and cwe_id in finding_cwe_ids:
                    should_mark_ignored = True

            if should_mark_ignored:
                finding["ignored"] = True
                updated_count += 1

        if updated_count > 0:
            # Update the results in the database
            # Explicitly mark the JSONB column as modified so SQLAlchemy detects the change
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(analysis, "results")
            db_session.commit()
            logger.info(
                f"Updated {updated_count} finding(s) as ignored in database for {repo_name}"
            )
        else:
            logger.warning(
                f"No matching findings found to update for ignore_type={ignore_type} in {repo_name}. "
                f"Search criteria: finding_id={finding_id}, cwe_id={cwe_id}, "
                f"file={normalized_file_path}, workspace_id={workspace_id}, repo_type={repo_type}"
            )

    except Exception as e:
        logger.error(
            f"Error updating findings ignored status: {str(e)}", exc_info=True
        )
        if db_session:
            db_session.rollback()


def add_ignore_status_to_findings(
    user_id, repo_name, findings, workspace_id=None, repo_type=None
):
    """Add ignore status to findings based on user's ignore records with normalized paths and CWE support"""
    import logging
    logger = logging.getLogger(__name__)
    LOG_TAG = "[IGNORE-CHECK]"

    if not findings:
        logger.info(f"{LOG_TAG} No findings provided to add_ignore_status_to_findings.")
        return findings

    logger.info(
        f"{LOG_TAG} Adding ignore status: user_id={user_id}, repo_name={repo_name}, findings_count={len(findings)}, workspace_id={workspace_id}, repo_type={repo_type}"
    )

    # Get user's ignore records for this repo with workspace filtering
    ignore_records = get_user_ignores(user_id, repo_name, workspace_id, repo_type)
    logger.info(f"{LOG_TAG} Fetched {len(ignore_records)} ignore records from DB.")

    # Create lookup dictionaries with normalized paths
    ignore_lookup = {}
    for ignore in ignore_records:
        normalized_ignore_path = normalize_file_path(ignore.get("file_path", ""))
        logger.debug(f"{LOG_TAG} Processing ignore record: {ignore} with normalized path: {normalized_ignore_path}")

        if ignore["ignore_type"] == "finding":
            # Normalize code snippet (strip whitespace and normalize newlines) for consistent matching
            raw_snippet = ignore.get("code_snippet", "")
            # Normalize: strip leading/trailing whitespace, normalize newlines to \n, normalize multiple spaces
            normalized_snippet = raw_snippet.strip().replace("\r\n", "\n").replace("\r", "\n")
            key = (
                ignore["finding_id"],
                normalized_ignore_path,
                normalized_snippet,
            )
            ignore_lookup[key] = ignore
            logger.debug(f"{LOG_TAG} Added ignore_lookup key for finding: finding_id={ignore['finding_id']}, file={normalized_ignore_path}, snippet_len={len(normalized_snippet)}")
        elif ignore["ignore_type"] == "rule_in_file":
            key = (ignore["finding_id"], normalized_ignore_path)
            ignore_lookup[key] = ignore
            logger.debug(f"{LOG_TAG} Added ignore_lookup key for rule_in_file: {key}")
        elif ignore["ignore_type"] == "file":
            key = ("*", normalized_ignore_path)
            ignore_lookup[key] = ignore
            logger.debug(f"{LOG_TAG} Added ignore_lookup key for file: {key}")
        elif ignore["ignore_type"] == "rule_in_repo":
            key = (ignore["finding_id"], "*")
            ignore_lookup[key] = ignore
            logger.debug(f"{LOG_TAG} Added ignore_lookup key for rule_in_repo: {key}")
        elif ignore["ignore_type"] == "cwe_in_file":
            key = ("cwe", ignore.get("cwe_id"), normalized_ignore_path)
            ignore_lookup[key] = ignore
            logger.debug(f"{LOG_TAG} Added ignore_lookup key for cwe_in_file: {key}")
        elif ignore["ignore_type"] == "cwe_in_repo":
            key = ("cwe", ignore.get("cwe_id"), "*")
            ignore_lookup[key] = ignore
            logger.debug(f"{LOG_TAG} Added ignore_lookup key for cwe_in_repo: {key}")

    logger.info(f"{LOG_TAG} Ignore lookup table created with {len(ignore_lookup)} keys: {list(ignore_lookup.keys())[:10]}{'...' if len(ignore_lookup) > 10 else ''}")

    # Apply ignore status to findings
    ignored_count = 0
    for idx, finding in enumerate(findings):
        normalized_finding_path = normalize_file_path(finding.get("file", ""))
        finding_id = finding.get("id", "")
        code_snippet = finding.get("code_snippet", "")
        finding_cwes = finding.get("cwe", [])
        
        normalized_code_snippet = code_snippet.strip().replace("\r\n", "\n").replace("\r", "\n") if code_snippet else ""

        logger.debug(
            f"{LOG_TAG} Checking finding #{idx}: id={finding_id}, file={finding.get('file')}, "
            f"normalized_file={normalized_finding_path}, snippet_len={len(normalized_code_snippet)}, cwes={finding_cwes}"
        )

        ignore_info = None

        # 1. Exact finding match (most specific) - use normalized code snippet
        lookup_key = (finding_id, normalized_finding_path, normalized_code_snippet)
        if lookup_key in ignore_lookup:
            ignore_info = ignore_lookup[lookup_key]
            logger.info(
                f"{LOG_TAG} Finding {finding_id} matched exact finding ignore. "
                f"Key: finding_id={finding_id}, file={normalized_finding_path}, snippet_len={len(normalized_code_snippet)}"
            )
        else:
            for lookup_key_check, ignore_record in ignore_lookup.items():
                if isinstance(lookup_key_check, tuple) and len(lookup_key_check) == 3:
                    check_finding_id, check_file, check_snippet = lookup_key_check
                    if check_finding_id == finding_id and check_file == normalized_finding_path:
                        logger.debug(
                            f"{LOG_TAG} Finding {finding_id} has matching ID and file but snippet mismatch. "
                            f"Expected snippet_len={len(check_snippet)}, got snippet_len={len(normalized_code_snippet)}"
                        )
                        break

        # 2. Rule in file match
        if not ignore_info and (finding_id, normalized_finding_path) in ignore_lookup:
            ignore_info = ignore_lookup[(finding_id, normalized_finding_path)]
            logger.info(
                f"{LOG_TAG} Finding {finding_id} matched rule_in_file ignore. "
                f"Key: finding_id={finding_id}, file={normalized_finding_path}"
            )

        # 3. CWE in file match - FIXED CWE MATCHING LOGIC
        if not ignore_info and finding_cwes:
            for cwe_entry in finding_cwes:
                cwe_id = cwe_entry.split(":")[0].strip() if ":" in cwe_entry else cwe_entry.strip()
                if ("cwe", cwe_id, normalized_finding_path) in ignore_lookup:
                    ignore_info = ignore_lookup[
                        ("cwe", cwe_id, normalized_finding_path)
                    ]
                    logger.info(f"{LOG_TAG} Finding {finding_id} matched cwe_in_file ignore: cwe_id={cwe_id}.")
                    break

        # 4. Entire file match
        if not ignore_info and ("*", normalized_finding_path) in ignore_lookup:
            ignore_info = ignore_lookup[("*", normalized_finding_path)]
            logger.info(f"{LOG_TAG} Finding {finding_id} matched file ignore.")

        # 5. Rule across repo match
        if not ignore_info and (finding_id, "*") in ignore_lookup:
            ignore_info = ignore_lookup[(finding_id, "*")]
            logger.info(f"{LOG_TAG} Finding {finding_id} matched rule_in_repo ignore.")

        # 6. CWE across repo match (least specific) - FIXED CWE MATCHING LOGIC
        if not ignore_info and finding_cwes:
            for cwe_entry in finding_cwes:
                cwe_id = cwe_entry.split(":")[0].strip() if ":" in cwe_entry else cwe_entry.strip()
                if ("cwe", cwe_id, "*") in ignore_lookup:
                    ignore_info = ignore_lookup[("cwe", cwe_id, "*")]
                    logger.info(f"{LOG_TAG} Finding {finding_id} matched cwe_in_repo ignore: cwe_id={cwe_id}.")
                    break

        # Apply ignore status
        if ignore_info:
            finding["ignored"] = True
            finding["ignore_reason"] = ignore_info.get("reason")
            finding["ignore_type"] = ignore_info.get("ignore_type")
            finding["ignored_at"] = ignore_info.get("ignored_at")
            finding["ignored_by"] = ignore_info.get("ignored_by")
            ignored_count += 1
            logger.info(f"{LOG_TAG} Marking finding id={finding_id} as IGNORED. Reason: {finding['ignore_reason']}, type={finding['ignore_type']}")
        else:
            finding["ignored"] = False
            finding["ignore_reason"] = None
            finding["ignore_type"] = None
            finding["ignored_at"] = None
            finding["ignored_by"] = None

    logger.info(f"{LOG_TAG} Processed ignore status for {len(findings)} findings. {ignored_count} marked as ignored.")
    return findings


def get_finding_ignore_status(
    user_id: str, repo_name: str, finding: Dict
) -> Optional["IgnoredFinding"]:
    """
    Check if a finding is ignored at any level with CWE support.
    Returns the ignore record if found, None otherwise.

    Hierarchy (most specific to least specific):
    1. Specific Finding (exact match)
    2. CWE in File (CWE type in specific file)
    3. CWE in Repository (CWE type across repo)
    4. Entire File (all findings in file)
    """
    from models import IgnoredFinding
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import and_
    from api import create_api_engine

    engine = None
    db_session = None

    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        finding_id = finding.get("id", "")
        file_path = finding.get("file", "")
        code_snippet = finding.get("code_snippet", "")
        finding_cwes = finding.get(
            "cwe", []
        )  # List of CWE IDs like ["CWE-89", "CWE-79"]

        # Normalize file path
        normalized_file_path = normalize_file_path(file_path)

        # 1. Exact finding match (most specific)
        exact_ignore = (
            db_session.query(IgnoredFinding)
            .filter(
                and_(
                    IgnoredFinding.user_id == user_id,
                    IgnoredFinding.repo_name == repo_name,
                    IgnoredFinding.ignore_type == "finding",
                    IgnoredFinding.finding_id == finding_id,
                    IgnoredFinding.file_path == normalized_file_path,
                    IgnoredFinding.code_snippet == code_snippet,
                )
            )
            .first()
        )

        if exact_ignore:
            return exact_ignore

        # 2. CWE in specific file
        if finding_cwes:
            for cwe_id in finding_cwes:
                cwe_file_ignore = (
                    db_session.query(IgnoredFinding)
                    .filter(
                        and_(
                            IgnoredFinding.user_id == user_id,
                            IgnoredFinding.repo_name == repo_name,
                            IgnoredFinding.ignore_type == "cwe_in_file",
                            IgnoredFinding.cwe_id == cwe_id,
                            IgnoredFinding.file_path == normalized_file_path,
                        )
                    )
                    .first()
                )

                if cwe_file_ignore:
                    return cwe_file_ignore

        # 3. CWE across entire repository
        if finding_cwes:
            for cwe_id in finding_cwes:
                cwe_repo_ignore = (
                    db_session.query(IgnoredFinding)
                    .filter(
                        and_(
                            IgnoredFinding.user_id == user_id,
                            IgnoredFinding.repo_name == repo_name,
                            IgnoredFinding.ignore_type == "cwe_in_repo",
                            IgnoredFinding.cwe_id == cwe_id,
                        )
                    )
                    .first()
                )

                if cwe_repo_ignore:
                    return cwe_repo_ignore

        # 4. Entire file ignored (least specific)
        file_ignore = (
            db_session.query(IgnoredFinding)
            .filter(
                and_(
                    IgnoredFinding.user_id == user_id,
                    IgnoredFinding.repo_name == repo_name,
                    IgnoredFinding.ignore_type == "file",
                    IgnoredFinding.file_path == normalized_file_path,
                )
            )
            .first()
        )

        if file_ignore:
            return file_ignore

        # Not ignored at any level
        return None

    except Exception as e:
        logger.error(f"Error checking ignore status: {str(e)}")
        return None
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


def calculate_affected_findings_for_ignore(ignore_record, findings):
    """
    Calculate how many findings are affected by a specific ignore rule
    
    Args:
        ignore_record: Dictionary containing the ignore rule details
        findings: List of findings from the latest analysis
    
    Returns:
        Dictionary with 'count' and 'finding_ids' keys
    """
    affected_count = 0
    affected_ids = []
    
    ignore_type = ignore_record.get("ignore_type")
    normalized_ignore_path = normalize_file_path(ignore_record.get("file_path", ""))
    
    def _normalize_cwe_id(raw_value):
        if not raw_value:
            return None
        cwe_value = raw_value.strip()
        if ":" in cwe_value:
            cwe_value = cwe_value.split(":", 1)[0].strip()
        return cwe_value if cwe_value.startswith("CWE-") else None

    normalized_cwe_id = _normalize_cwe_id(ignore_record.get("cwe_id"))

    for finding in findings:
        finding_file = normalize_file_path(finding.get("file", ""))
        raw_finding_cwes = finding.get("cwe", [])
        finding_cwes = []
        for cwe_entry in raw_finding_cwes:
            normalized_entry = _normalize_cwe_id(cwe_entry if isinstance(cwe_entry, str) else "")
            if normalized_entry:
                finding_cwes.append(normalized_entry)
        match_found = False
        
        if ignore_type == "finding":
            # Exact match: rule + file + code snippet
            if (
                finding.get("id") == ignore_record.get("finding_id")
                and finding_file == normalized_ignore_path
                and finding.get("code_snippet", "") == ignore_record.get("code_snippet", "")
            ):
                match_found = True
                
        elif ignore_type == "rule_in_file":
            # Rule in specific file
            if (
                finding.get("id") == ignore_record.get("finding_id")
                and finding_file == normalized_ignore_path
            ):
                match_found = True
                
        elif ignore_type == "file":
            # Any finding in this file
            if finding_file == normalized_ignore_path:
                match_found = True
                
        elif ignore_type == "rule_in_repo":
            # This rule anywhere in repo
            if finding.get("id") == ignore_record.get("finding_id"):
                match_found = True
                
        elif ignore_type == "cwe_in_file":
            # CWE in specific file

            cwe_id = normalized_cwe_id or _normalize_cwe_id(ignore_record.get("finding_id"))
            if (
                cwe_id
                and cwe_id in finding_cwes
                and finding_file == normalized_ignore_path
            ):
                match_found = True
                
        elif ignore_type == "cwe_in_repo":
            # CWE anywhere in repo
            cwe_id = normalized_cwe_id or _normalize_cwe_id(ignore_record.get("finding_id"))
            if cwe_id and cwe_id in finding_cwes:
                match_found = True
        
        if match_found:
            affected_count += 1
            affected_ids.append(finding.get("ID") or finding.get("id"))
    
    return {
        "count": affected_count,
        "finding_ids": affected_ids
    }


def get_user_ignores(user_id, repo_name=None, workspace_id=None, repo_type=None):
    """Get all ignore records with workspace-first filtering and backwards compatibility"""
    from models import IgnoredFinding
    from sqlalchemy.orm import sessionmaker
    from api import create_api_engine
    import logging

    logger = logging.getLogger(__name__)
    engine = None
    db_session = None

    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Start with base query
        query = db_session.query(IgnoredFinding).filter_by(repo_name=repo_name)
        logger.info(f"Filtering by repo_name='{repo_name}'")
        if repo_type:
            logger.info(f"Adding repo type to filter. repo_type='{repo_type}'")
            query = query.filter_by(repo_type=repo_type)

        if workspace_id is None:
            logger.info(
                f"No workspace id provided so falling back to user id. user_id='{user_id}'"
            )
            query = query.filter_by(user_id=user_id)
        else:
            logger.info(
                f"Filtering for ignored findings by workspace id. workspace_id='{workspace_id}'"
            )
            query = query.filter_by(workspace_id=workspace_id)

        ignore_records = query.order_by(IgnoredFinding.ignored_at.desc()).all()

        # Convert to dictionaries
        result = []
        for record in ignore_records:
            record_dict = {
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
            }

            # Add CWE info if it exists
            if hasattr(record, "cwe_id") and record.cwe_id:
                record_dict["cwe_id"] = record.cwe_id

            # Add workspace and repo type info if they exist
            if hasattr(record, "workspace_id"):
                record_dict["workspace_id"] = record.workspace_id
            if hasattr(record, "repo_type"):
                record_dict["repo_type"] = record.repo_type

            result.append(record_dict)

        return result

    except Exception as e:
        logger.error(f"Error getting user ignores: {str(e)}")
        return []
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


def remove_ignore_record(
    user_id, repo_name, ignore_data, workspace_id=None, repo_type=None
):
    """Remove an ignore record with normalized file paths and CWE support"""
    from models import IgnoredFinding
    from sqlalchemy.orm import sessionmaker
    from api import create_api_engine
    import logging

    logger = logging.getLogger(__name__)
    engine = None
    db_session = None

    try:
        ignore_type = ignore_data.get("ignore_type")
        finding_id = ignore_data.get("finding_id")
        file_path = ignore_data.get("file_path")
        code_snippet = ignore_data.get("code_snippet")
        cwe_id = ignore_data.get("cwe_id")

        # Normalize file path if provided
        if file_path:
            file_path = normalize_file_path(file_path)

        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Log the search criteria for debugging
        logger.info(
            f"Searching for ignore record to delete - user_id: {user_id}, repo_name: {repo_name}, repo_type = {repo_type}"
            f"ignore_type: {ignore_type}, workspace_id: {workspace_id}, repo_type: '{repo_type}'"
        )

        query = db_session.query(IgnoredFinding).filter_by(repo_name=repo_name)
        logger.info(f"Filtering by repo_name='{repo_name}'")
        if repo_type:
            logger.info(f"Adding repo type to filter. repo_type='{repo_type}'")
            query = query.filter_by(repo_type=repo_type)

        if workspace_id is None:
            logger.info(
                f"No workspace id provided so falling back to user id. user_id='{user_id}'"
            )
            query = query.filter_by(user_id=user_id)
        else:
            logger.info(
                f"Filtering for ignored findings by workspace id. workspace_id='{workspace_id}'"
            )
            query = query.filter_by(workspace_id=workspace_id)

        # Add specific filters based on ignore type
        if ignore_type == "finding":
            if not all([finding_id, file_path, code_snippet]):
                return {
                    "success": False,
                    "message": "finding_id, file_path, and code_snippet are required for finding ignore_type",
                }
            query = query.filter_by(
                finding_id=finding_id, file_path=file_path, code_snippet=code_snippet
            )

        elif ignore_type == "rule_in_file":
            if not all([finding_id, file_path]):
                return {
                    "success": False,
                    "message": "finding_id and file_path are required for rule_in_file ignore_type",
                }
            query = query.filter_by(
                finding_id=finding_id, file_path=file_path, code_snippet=code_snippet
            )

        elif ignore_type == "file":
            if not file_path:
                return {
                    "success": False,
                    "message": "file_path is required for file ignore_type",
                }
            query = query.filter_by(file_path=file_path, code_snippet=code_snippet)

        elif ignore_type == "rule_in_repo":
            if not finding_id:
                return {
                    "success": False,
                    "message": "finding_id is required for rule_in_repo ignore_type",
                }
            query = query.filter_by(finding_id=finding_id, code_snippet=code_snippet)

        elif ignore_type == "cwe_in_file":
            # Handle both valid cwe_id and malformed finding_id cases for cleanup
            if cwe_id and file_path:
                query = query.filter_by(
                    cwe_id=cwe_id, file_path=file_path, code_snippet=code_snippet
                )
            elif finding_id and file_path:
                # CLEANUP: Handle malformed records that used finding_id instead of cwe_id
                logger.info(
                    f"Attempting cleanup of malformed cwe_in_file record with finding_id: {finding_id}"
                )
                query = query.filter_by(
                    finding_id=finding_id,
                    file_path=file_path,
                    code_snippet=code_snippet,
                )
            else:
                return {
                    "success": False,
                    "message": "Either (cwe_id and file_path) or (finding_id and file_path) required for cwe_in_file cleanup",
                }

        elif ignore_type == "cwe_in_repo":
            # Handle both valid cwe_id and malformed finding_id cases for cleanup
            if cwe_id:
                query = query.filter_by(cwe_id=cwe_id, code_snippet=code_snippet)
            elif finding_id:
                # CLEANUP: Handle malformed records that used finding_id instead of cwe_id
                logger.info(
                    f"Attempting cleanup of malformed cwe_in_repo record with finding_id: {finding_id}"
                )
                query = query.filter_by(
                    finding_id=finding_id, code_snippet=code_snippet
                )
            else:
                return {
                    "success": False,
                    "message": "Either cwe_id or finding_id is required for cwe_in_repo cleanup",
                }
        else:
            return {"success": False, "message": f"Invalid ignore_type: {ignore_type}"}

        # Execute query to find the ignore record
        ignore_record = query.first()

        # Log the query result for debugging
        if ignore_record:
            logger.info(
                f"Found ignore record to delete - ID: {ignore_record.id}, "
                f"workspace_id: {getattr(ignore_record, 'workspace_id', 'N/A')}, "
                f"repo_type: '{getattr(ignore_record, 'repo_type', 'N/A')}'"
            )
        else:
            logger.warning(
                f"No ignore record found matching criteria - user_id: {user_id}, "
                f"repo_name: {repo_name}, ignore_type: {ignore_type}, "
                f"workspace_id: {workspace_id}, repo_type: '{repo_type}'"
            )

        if not ignore_record:
            # Try to find record by ID if provided for direct deletion
            record_id = ignore_data.get("id")
            if record_id:
                logger.info(f"Attempting direct deletion by ID: {record_id}")
                ignore_record = (
                    db_session.query(IgnoredFinding)
                    .filter_by(id=record_id, user_id=user_id, repo_name=repo_name)
                    .first()
                )

        if not ignore_record:
            logger.warning(
                f"No ignore record found for deletion - user: {user_id}, repo: {repo_name}, "
                f"type: {ignore_type}, finding_id: {finding_id}, cwe_id: {cwe_id}, file: {file_path}"
            )
            return {
                "success": False,
                "message": f"No {ignore_type} ignore found to remove",
            }

        # Log what we're about to delete for debugging
        logger.info(
            f"Found ignore record to delete - ID: {ignore_record.id}, "
            f"type: {ignore_record.ignore_type}, finding_id: {ignore_record.finding_id}, "
            f"cwe_id: {getattr(ignore_record, 'cwe_id', None)}, file: {ignore_record.file_path}"
        )

        # Delete the record
        db_session.delete(ignore_record)
        db_session.commit()

        logger.info(
            f"Successfully removed ignore record ID {ignore_record.id} for user {user_id}, "
            f"repo {repo_name}, type {ignore_type}"
        )

        return {
            "success": True,
            "message": f"Successfully removed {ignore_type} ignore",
            "deleted_record_id": ignore_record.id,
        }

    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Error removing ignore record: {str(e)}", exc_info=True)
        return {"success": False, "message": f"Database error: {str(e)}"}
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


def create_azure_devops_ignore_record(user_id, repo_name, ignore_data):
    """Create ignore record for Azure DevOps with CWE support and metadata extraction"""
    from models import IgnoredFinding, AzureDevOpsAnalysisResult
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy import desc
    from api import create_api_engine
    import logging
    from datetime import datetime

    logger = logging.getLogger(__name__)
    engine = None
    db_session = None

    try:
        # UPDATED: Validate ignore_type with CWE support
        valid_ignore_types = ["finding", "cwe_in_file", "cwe_in_repo", "file"]
        ignore_type = ignore_data.get("ignore_type")

        if ignore_type not in valid_ignore_types:
            return {
                "success": False,
                "message": f'Invalid ignore_type. Must be one of: {", ".join(valid_ignore_types)}',
            }

        # Get basic ignore data
        finding_id = ignore_data.get("finding_id")
        file_path = ignore_data.get("file_path")
        code_snippet = ignore_data.get("code_snippet")
        cwe_id = ignore_data.get("cwe_id")  # NEW: CWE support
        reason = ignore_data.get("reason", "")

        # Normalize file path if provided
        if file_path:
            file_path = normalize_file_path(file_path)

        # UPDATED: Validation based on ignore type with CWE
        if ignore_type == "finding":
            if not all([finding_id, file_path, code_snippet]):
                return {
                    "success": False,
                    "message": "finding_id, file_path, and code_snippet are required for finding ignore_type",
                }
        elif ignore_type == "cwe_in_file":
            if not all([cwe_id, file_path]):
                return {
                    "success": False,
                    "message": "cwe_id and file_path are required for cwe_in_file ignore_type",
                }
        elif ignore_type == "cwe_in_repo":
            if not cwe_id:
                return {
                    "success": False,
                    "message": "cwe_id is required for cwe_in_repo ignore_type",
                }
        elif ignore_type == "file":
            if not file_path:
                return {
                    "success": False,
                    "message": "file_path is required for file ignore_type",
                }

        # Validate CWE format if provided
        if cwe_id and not cwe_id.startswith("CWE-"):
            return {
                "success": False,
                "message": 'CWE ID must be in format "CWE-XXX" (e.g., "CWE-89")',
            }

        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # AUTO-EXTRACT METADATA (for response only, not stored in DB)
        severity = None
        cwe = []
        owasp = []
        category = None
        message = None

        try:
            # Get the latest Azure DevOps analysis for this repo
            analysis = (
                db_session.query(AzureDevOpsAnalysisResult)
                .filter_by(repository_name=repo_name)
                .order_by(desc(AzureDevOpsAnalysisResult.timestamp))
                .first()
            )

            if analysis and analysis.results:
                findings = analysis.results.get("findings", [])
                normalized_ignore_path = (
                    normalize_file_path(file_path) if file_path else None
                )

                # Find the matching finding
                target_finding = None
                for finding in findings:
                    finding_file = normalize_file_path(finding.get("file", ""))

                    # UPDATED: Match based on ignore type including CWE
                    if ignore_type == "finding":
                        # Exact match: rule + file + code snippet
                        if (
                            finding.get("id") == finding_id
                            and finding_file == normalized_ignore_path
                            and finding.get("code_snippet", "") == code_snippet
                        ):
                            target_finding = finding
                            break
                    elif ignore_type == "cwe_in_file":
                        # CWE in specific file
                        finding_cwes = finding.get("cwe", [])
                        if (
                            cwe_id in finding_cwes
                            and finding_file == normalized_ignore_path
                        ):
                            target_finding = finding
                            break
                    elif ignore_type == "cwe_in_repo":
                        # CWE anywhere in repo
                        finding_cwes = finding.get("cwe", [])
                        if cwe_id in finding_cwes:
                            target_finding = finding
                            break
                    elif ignore_type == "file":
                        # Any finding in this file
                        if finding_file == normalized_ignore_path:
                            target_finding = finding
                            break

                # Extract metadata from found finding
                if target_finding:
                    severity = target_finding.get("severity", "").upper()
                    cwe = target_finding.get("cwe", [])
                    owasp = target_finding.get("owasp", [])
                    category = target_finding.get("category", "")
                    message = target_finding.get("message", "")

                    logger.info(
                        f"Auto-extracted metadata for Azure DevOps: severity={severity}, cwe={len(cwe)} items, category={category}"
                    )
                else:
                    logger.warning(
                        f"Could not find matching finding for metadata extraction in Azure DevOps: {finding_id or cwe_id}"
                    )

        except Exception as e:
            logger.warning(
                f"Failed to auto-extract metadata from Azure DevOps analysis: {str(e)}"
            )
            # Continue without metadata - not a critical failure

        # UPDATED: Check if ignore already exists with CWE support
        query = db_session.query(IgnoredFinding).filter_by(
            user_id=user_id, repo_name=repo_name, ignore_type=ignore_type
        )

        # Add specific filters based on ignore type
        if ignore_type == "finding":
            query = query.filter_by(
                finding_id=finding_id, file_path=file_path, code_snippet=code_snippet
            )
        elif ignore_type == "cwe_in_file":
            query = query.filter_by(cwe_id=cwe_id, file_path=file_path)
        elif ignore_type == "cwe_in_repo":
            query = query.filter_by(cwe_id=cwe_id)
        elif ignore_type == "file":
            query = query.filter_by(file_path=file_path)

        existing_ignore = query.first()

        if existing_ignore:
            return {
                "success": False,
                "message": f"This {ignore_type} is already ignored",
                "existing_reason": existing_ignore.reason,
                "existing_ignored_at": (
                    existing_ignore.ignored_at.isoformat()
                    if existing_ignore.ignored_at
                    else None
                ),
            }

        # UPDATED: Create new ignore record with CWE support
        ignored_at = datetime.utcnow()
        new_ignore = IgnoredFinding(
            user_id=user_id,
            repo_name=repo_name,
            ignore_type=ignore_type,
            finding_id=finding_id,
            file_path=file_path,
            code_snippet=code_snippet,
            cwe_id=cwe_id,  # NEW: Include CWE field
            reason=reason,
            ignored_at=ignored_at,
            ignored_by=user_id,
        )

        db_session.add(new_ignore)
        db_session.commit()

        logger.info(
            f"Created Azure DevOps ignore record with extracted metadata: {ignore_type}, severity={severity}"
        )

        # update findings in the database to mark them as ignored
        try:
            workspace_id = ignore_data.get("workspace_id")
            repo_type = "azure-devops"
            update_findings_ignored_status(
                user_id=user_id,
                repo_name=repo_name,
                ignore_type=ignore_type,
                finding_id=finding_id,
                file_path=file_path,
                code_snippet=code_snippet,
                cwe_id=cwe_id,
                workspace_id=workspace_id,
                repo_type=repo_type,
                db_session=db_session,
            )
        except Exception as update_error:
            logger.warning(
                f"Failed to update findings ignored status in database: {str(update_error)}"
            )

        return {
            "success": True,
            "message": f"Successfully ignored {ignore_type}",
            "ignore_id": new_ignore.id,
            "metadata": {
                "severity": severity,
                "cwe": cwe if cwe else [],
                "category": category,
                "ignored_at": ignored_at.isoformat(),
            },
        }

    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Error creating Azure DevOps ignore record: {str(e)}")
        return {"success": False, "message": f"Database error: {str(e)}"}
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


def remove_azure_devops_ignore_record(user_id, repo_name, ignore_data):
    """Remove an Azure DevOps ignore record with CWE support"""
    from models import IgnoredFinding
    from sqlalchemy.orm import sessionmaker
    from api import create_api_engine
    import logging

    logger = logging.getLogger(__name__)
    engine = None
    db_session = None

    try:
        ignore_type = ignore_data.get("ignore_type")
        finding_id = ignore_data.get("finding_id")
        file_path = ignore_data.get("file_path")
        code_snippet = ignore_data.get("code_snippet")
        cwe_id = ignore_data.get("cwe_id")  # NEW: CWE support

        # Normalize file path if provided
        if file_path:
            file_path = normalize_file_path(file_path)

        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        # Build query
        query = db_session.query(IgnoredFinding).filter_by(
            user_id=user_id, repo_name=repo_name, ignore_type=ignore_type
        )

        # UPDATED: Add specific filters based on ignore type including CWE
        if ignore_type == "finding":
            query = query.filter_by(
                finding_id=finding_id, file_path=file_path, code_snippet=code_snippet
            )
        elif ignore_type == "cwe_in_file":
            query = query.filter_by(cwe_id=cwe_id, file_path=file_path)
        elif ignore_type == "cwe_in_repo":
            query = query.filter_by(cwe_id=cwe_id)
        elif ignore_type == "file":
            query = query.filter_by(file_path=file_path)

        ignore_record = query.first()

        if not ignore_record:
            return {
                "success": False,
                "message": f"No {ignore_type} ignore found to remove",
            }

        db_session.delete(ignore_record)
        db_session.commit()

        logger.info(
            f"Removed Azure DevOps ignore record for user {user_id}, repo {repo_name}, type {ignore_type}"
        )

        return {
            "success": True,
            "message": f"Successfully removed {ignore_type} ignore",
        }

    except Exception as e:
        if db_session:
            db_session.rollback()
        logger.error(f"Error removing Azure DevOps ignore record: {str(e)}")
        return {"success": False, "message": f"Database error: {str(e)}"}
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()