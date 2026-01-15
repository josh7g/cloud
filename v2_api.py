import os
import logging
import asyncio
import threading
import shutil
from pathlib import Path
from db_utils import create_db_engine
from flask import Blueprint, request, jsonify
from pydantic import ValidationError
from helpers.validators import (
    ScanRepoGithub,
    ScanRepoAzureDevops,
    ScanRepoGitlab,
    ScanRepoCodecommit,
)
from sqlalchemy.orm import sessionmaker
from sqlalchemy import desc
from models import RepoScanResult
from helpers.cloners import clone_and_get_scan_info, ScanStrategy
from helpers.unified_scanner import scan_repository
from helpers.utils import get_github_token_from_installation_id


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

v2_api_bp = Blueprint("v2_api", __name__, url_prefix="/api/v2")


@v2_api_bp.route("/scan", methods=["POST"])
def scan_repo():
    try:
        data = request.json
        repo_type = data.get("repo_type") if data else None

        if not data or not repo_type:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": (
                                "Request body is required"
                                if not data
                                else "repo_type is required"
                            ),
                            "code": "MISSING_DATA" if not data else "MISSING_REPO_TYPE",
                        },
                    }
                ),
                400,
            )

        validators = {
            "github": ScanRepoGithub,
            "azure-devops": ScanRepoAzureDevops,
            "gitlab": ScanRepoGitlab,
            "codecommit": ScanRepoCodecommit,
        }

        validator_class = validators.get(repo_type.lower())
        if not validator_class:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": {
                            "message": f"Invalid repo_type: {repo_type}. Supported types: {', '.join(validators.keys())}",
                            "code": "INVALID_REPO_TYPE",
                        },
                    }
                ),
                400,
            )

        # validate the data
        validated_data = validator_class(**data)
        logger.info(f"Successfully validated {repo_type} repo scan request")
        org_name = validated_data.org_name
        repo_name = validated_data.repo_name
        workspace_id = validated_data.workspace_id
        user_id = validated_data.user_id
        project_name = None

        if repo_type == "azure-devops":
            project_name = validated_data.project_name
        # actual scan logic here
        engine = create_db_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()

        last_scan = db_session.query(RepoScanResult).filter(
            RepoScanResult.org_name == org_name,
            RepoScanResult.repo_name == repo_name,
            RepoScanResult.workspace_id == workspace_id,
            RepoScanResult.status == "completed",
        )

        # azure devops projects have project_names
        if repo_type == "azure-devops":
            last_scan = last_scan.filter(RepoScanResult.project_name == project_name)

        last_scan = last_scan.order_by(desc(RepoScanResult.timestamp)).first()
        previous_sha = getattr(last_scan, "scanned_commit_sha", None)

        new_analysis_results = RepoScanResult(
            org_name=org_name,
            repo_name=repo_name,
            project_name=project_name,
            workspace_id=workspace_id,
            user_id=user_id,
            repo_type=repo_type,
            status="pending",
        )
        db_session.add(new_analysis_results)
        db_session.commit()

        # Store record ID and previous findings info for background task
        record_id = new_analysis_results.id
        previous_sha = getattr(last_scan, "scanned_commit_sha", None)
        previous_findings = None
        if last_scan and last_scan.results:
            previous_findings = last_scan.results.get("findings", [])

        logger.critical(f"New scan created for {repo_type}. Record ID: {record_id}")

        # Close the current db session before starting background task
        db_session.close()

        # Build repo identifier
        repo_identifier = (
            f"{org_name}/{project_name + '/' if project_name else ''}{repo_name}"
        )

        # Get installation token for GitHub repos (needed for RAG processing)
        installation_token = None
        if repo_type.lower() == "github":
            try:
                GITHUB_APP_ID = os.getenv("GITHUB_APP_ID")
                GITHUB_APP_PRIVATE_KEY = os.getenv("GITHUB_APP_PRIVATE_KEY")

                # Enhanced logging for debugging
                logger.info(
                    f"GITHUB_APP_ID present: {bool(GITHUB_APP_ID)}, length: {len(GITHUB_APP_ID) if GITHUB_APP_ID else 0}"
                )
                logger.info(
                    f"GITHUB_APP_PRIVATE_KEY present: {bool(GITHUB_APP_PRIVATE_KEY)}, length: {len(GITHUB_APP_PRIVATE_KEY) if GITHUB_APP_PRIVATE_KEY else 0}"
                )

                if GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY:
                    token_response = get_github_token_from_installation_id(
                        installation_id=validated_data.installation_id,
                        app_id=GITHUB_APP_ID,
                        private_key=GITHUB_APP_PRIVATE_KEY,
                    )
                    installation_token = token_response["token"]
                    logger.info(
                        "Successfully obtained GitHub installation token for RAG processing"
                    )
                else:
                    missing = []
                    if not GITHUB_APP_ID:
                        missing.append("GITHUB_APP_ID")
                    if not GITHUB_APP_PRIVATE_KEY:
                        missing.append("GITHUB_APP_PRIVATE_KEY")
                    logger.warning(
                        f"Missing GitHub credentials: {', '.join(missing)}. RAG processing will be skipped"
                    )
            except Exception as token_err:
                logger.warning(
                    f"Failed to get installation token: {token_err}. RAG processing will be skipped"
                )

        # Define the background scan task that includes cloning
        def run_background_scan():
            """Background task to clone and scan the repository asynchronously."""
            from progress_tracking import (
                get_redis_client,
                update_scan_progress,
                clear_scan_progress,
            )
            import time

            # Create a new database session for this thread
            bg_engine = create_db_engine()
            BgSession = sessionmaker(bind=bg_engine)
            bg_session = BgSession()

            try:
                # Get the record we need to update
                analysis_record = bg_session.query(RepoScanResult).get(record_id)
                if not analysis_record:
                    logger.error(f"Could not find analysis record {record_id}")
                    return

                # Initialize progress tracking
                redis_client = get_redis_client()
                completion_key = f"scan_complete:{user_id}:{repo_identifier}"
                progress_key = f"scan_progress:{user_id}:{repo_identifier}"
                redis_client.delete(completion_key)
                redis_client.delete(progress_key)

                clear_scan_progress(user_id, repo_identifier)
                update_scan_progress(user_id, repo_identifier, "initializing", 5)

                analysis_record.status = "in_progress"
                bg_session.commit()

                # Run the async clone and scan
                async def execute_clone_and_scan():
                    repo_dir = None
                    try:
                        # Step 1: Clone the repository
                        update_scan_progress(user_id, repo_identifier, "cloning", 10)
                        clone_result = await clone_and_get_scan_info(
                            **validated_data.model_dump(), previous_sha=previous_sha
                        )

                        if not clone_result.get("success"):
                            raise Exception(
                                f"Clone failed: {clone_result.get('error')}"
                            )

                        # Store repo_dir for cleanup
                        repo_dir = clone_result.get("destination")
                        detected_language = clone_result.get("detected_language")
                        strategy = clone_result.get("strategy")

                        # Check if we should skip scanning
                        if strategy == ScanStrategy.SKIP_SCAN:
                            logger.info(
                                f"Skipping scan - no changes detected: {clone_result.get('reason')}"
                            )
                            update_scan_progress(
                                user_id, repo_identifier, "completed", 100
                            )
                            return {
                                "success": True,
                                "skipped": True,
                                "reason": clone_result.get("reason"),
                                "current_sha": clone_result.get("current_sha"),
                            }

                        # Determine files to scan (incremental vs full)
                        files_to_scan = None
                        if strategy == ScanStrategy.INCREMENTAL_SCAN:
                            files_to_scan = clone_result.get("changed_files", [])
                            logger.info(
                                f"Incremental scan: {len(files_to_scan)} files to scan"
                            )

                        # Step 2: Create progress callback
                        async def async_progress_callback(stage: str, progress: int):
                            update_scan_progress(
                                user_id, repo_identifier, stage, progress
                            )

                        # Step 3: Run the scan (includes reranking)
                        update_scan_progress(user_id, repo_identifier, "scanning", 20)
                        scan_result = await scan_repository(
                            repo_dir=repo_dir,
                            detected_language=detected_language,
                            include_files=files_to_scan,
                            previous_findings=previous_findings,
                            progress_callback=async_progress_callback,
                            repo_identifier=repo_identifier,
                            user_id=user_id,
                            scan_id=record_id,
                            installation_token=installation_token,
                        )

                        scan_result["current_sha"] = clone_result.get("current_sha")
                        scan_result["skipped"] = False
                        return scan_result

                    finally:
                        # Always cleanup the cloned repository directory
                        if repo_dir:
                            try:
                                repo_path = Path(repo_dir)
                                # Clean up the parent directory which contains both:
                                # - repo_<timestamp>_<id> (the actual cloned repo)
                                # - <repo-type>_scanner_<id> (the parent temp folder)
                                if repo_path.exists():
                                    parent_dir = repo_path.parent
                                    if parent_dir.exists():
                                        shutil.rmtree(parent_dir)
                                        logger.info(
                                            f"Cleaned up scanner directory: {parent_dir}"
                                        )
                                    else:
                                        # Fallback: clean just the repo dir if parent doesn't exist
                                        shutil.rmtree(repo_path)
                                        logger.info(
                                            f"Cleaned up cloned repository: {repo_dir}"
                                        )
                            except Exception as cleanup_error:
                                logger.error(
                                    f"Failed to clean up cloned repository {repo_dir}: {str(cleanup_error)}"
                                )

                result = asyncio.run(execute_clone_and_scan())

                # Update database with results
                if result.get("skipped"):
                    # When scan is skipped (no changes), copy findings from previous scan
                    # Skipped scans only happen when there's a previous scan to compare against
                    previous_results = last_scan.results.copy()
                    previous_rerank = (
                        last_scan.rerank.copy() if last_scan.rerank else {}
                    )

                    # Update metadata to reflect this is a skipped scan
                    if "metadata" in previous_results:
                        previous_results["metadata"]["skipped"] = True
                        previous_results["metadata"]["skip_reason"] = result.get(
                            "reason"
                        )
                        previous_results["metadata"]["scanned_commit_sha"] = result.get(
                            "current_sha"
                        )

                    analysis_record.status = "completed"
                    analysis_record.results = previous_results
                    analysis_record.rerank = previous_rerank
                    analysis_record.scanned_commit_sha = result.get("current_sha")
                    findings_count = len(previous_results.get("findings", []))
                    logger.info(
                        f"Scan skipped - copied {findings_count} findings from previous scan"
                    )
                    update_scan_progress(user_id, repo_identifier, "completed", 100)
                elif result.get("success"):
                    # Build results_data matching original scanner.py structure
                    rerank_data = result.get("rerank", {})
                    results_data = {
                        "findings": rerank_data.get(
                            "findings", result.get("findings", [])
                        ),
                        "stats": rerank_data.get("stats", result.get("stats", {})),
                        "metadata": {
                            "repository_url": result.get("metadata", {}).get(
                                "repository_url", repo_identifier
                            ),
                            "user_id": user_id,
                            "scan_start": result.get("metadata", {}).get("scan_start"),
                            "scan_end": result.get("metadata", {}).get("scan_end"),
                            "scan_duration_seconds": result.get("metadata", {}).get(
                                "scan_duration_seconds"
                            ),
                            "rag_processed": result.get("metadata", {}).get(
                                "rag_processed", False
                            ),
                            "rag_responses_count": result.get("metadata", {}).get(
                                "rag_responses_count", 0
                            ),
                            "scanned_commit_sha": result.get("current_sha"),
                        },
                    }

                    analysis_record.status = "completed"
                    analysis_record.results = results_data
                    analysis_record.rerank = rerank_data
                    analysis_record.scanned_commit_sha = result.get("current_sha")
                    findings_count = len(results_data.get("findings", []))
                    logger.info(
                        f"Scan completed successfully with {findings_count} findings"
                    )
                    update_scan_progress(user_id, repo_identifier, "completed", 100)
                else:
                    analysis_record.status = "error"
                    analysis_record.error = str(result.get("errors", ["Unknown error"]))
                    logger.error(f"Scan failed: {result.get('errors')}")
                    update_scan_progress(user_id, repo_identifier, "error", 0)

                bg_session.commit()
                logger.info(f"Results saved to database for record {record_id}")

            except Exception as e:
                logger.error(f"Background scan error: {str(e)}")
                import traceback

                logger.error(f"Traceback: {traceback.format_exc()}")
                try:
                    analysis_record = bg_session.query(RepoScanResult).get(record_id)
                    if analysis_record:
                        analysis_record.status = "error"
                        analysis_record.error = str(e)
                        bg_session.commit()
                    update_scan_progress(user_id, repo_identifier, "error", 0)
                except Exception as db_err:
                    logger.error(f"Failed to update error status: {db_err}")
                    bg_session.rollback()
            finally:
                bg_session.close()

        # Start the background scan in a separate thread
        scan_thread = threading.Thread(target=run_background_scan, daemon=True)
        scan_thread.start()
        logger.info(f"Started background scan thread for record {record_id}")

        # Return immediately with scan initiated response
        return jsonify(
            {
                "success": True,
                "message": "Scan initiated",
                "data": {
                    "scan_id": record_id,
                    "status": "pending",
                    **validated_data.model_dump(),
                },
            }
        )

    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        # Extract missing fields from validation errors
        missing_fields = [
            err["loc"][0] for err in e.errors() if err["type"] == "missing"
        ]
        return (
            jsonify(
                {
                    "success": False,
                    "error": {
                        "message": (
                            f'Missing required parameters: {", ".join(missing_fields)}'
                            if missing_fields
                            else f"Validation failed: {str(e)}"
                        ),
                        "code": "INVALID_PARAMETERS",
                    },
                }
            ),
            400,
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
                    },
                }
            ),
            500,
        )
