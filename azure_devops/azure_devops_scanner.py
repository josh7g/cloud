from .utils import (
    logger,
    create_secure_client_session,
    create_ssl_context,
    create_auth_header,
)
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Union, Tuple
from sqlalchemy.orm import Session
import json
from pathlib import Path
import time
import psutil
import asyncio
from progress_tracking import clear_scan_progress, update_scan_progress
from collections import defaultdict
from datetime import datetime
import shutil
import git
import os
import aiohttp
import re
import traceback
import base64
from urllib.parse import quote, unquote
import uuid
import tempfile
from models import AzureDevOpsAnalysisResult


async def scan_azure_devops_repo(
    PAT,
    access_token,
    organization_name,
    project,
    repo_name,
    user_id,
    db_session,
    azure_analysis_record,
    multi_scan,
    files_to_scan=None,
    previous_findings=None,
    current_commit_sha=None,
):
    """
    Trigger a semgrep scan for an Azure Devops repo with incremental scanning support.

    INCREMENTAL SCANNING:
    - If files_to_scan is provided: Only scan the specified changed files
    - If previous_findings is provided: Merge new findings with existing findings
    - If current_commit_sha is provided: Track the commit SHA for future incremental scans

    MERGING LOGIC:
    - Keep findings from unchanged files (not in files_to_scan)
    - Replace findings from changed files (in files_to_scan) with new scan results

    Args:
        PAT (str, optional): Personal Access Token for authentication
        access_token (str, optional): OAuth access token for authentication
        organization_name (str): The Azure Devops organization where the repo is located
        project (str): The Azure Devops project where the repo is location
        repo (str): The name of the repo
        user_id (str): The id of the logged in user
        db_session (Session): The database session
        azure_analysis_record (AzureDevOpsAnalysisResult): The analysis details in the database to be updated
        multi_scan (bool): Whether to run multiple scans
        files_to_scan (List[str]|None): Limit scan to these files/paths for incremental scanning
        previous_findings (List[Dict]|None): Previous findings to merge with
        current_commit_sha (str|None): Current commit SHA for tracking

    Note: Either PAT or access_token must be provided, but not both.
    """
    logger.info(
        f"Starting scan for azure devops repository: {organization_name}/{project}/{repo_name} files_to_scan={files_to_scan}"
    )

    try:
        azure_analysis = azure_analysis_record

        clear_scan_progress(user_id, repo_name)

        config = ScanConfig()
        async with AzureSecurityScanner(
            config,
            db_session,
            azure_analysis_record.id if azure_analysis_record else None,
        ) as scanner:
            try:
                size_info = await scanner._check_repository_size(
                    organization_name=organization_name,
                    project_name=project,
                    repo_name=repo_name,
                    PAT=PAT,
                    access_token=access_token,
                )
                if not size_info["is_compatible"]:
                    if azure_analysis_record:
                        azure_analysis_record.status = "failed"
                        azure_analysis_record.error = (
                            "Repository is too large for analysis"
                        )
                        db_session.commit()
                    return {
                        "success": False,
                        "error": {
                            "message": "Repository too large for analysis",
                            "code": "REPOSITORY_TOO_LARGE",
                            "details": {
                                "size_mb": size_info["size_mb"],
                                "limit_mb": config.max_total_size_mb,
                                "recommendation": "Consider analyzing specific directories or branches",
                            },
                        },
                    }

                repo_dir = await scanner._clone_repository(
                    organization_name=organization_name,
                    project_name=project,
                    repo_name=repo_name,
                    branch=size_info["default_branch"],
                    repo_size=size_info["size_mb"],
                    PAT=PAT,
                    access_token=access_token,
                )

                try:
                    results = await scanner.scan_repository(
                        organization_name=organization_name,
                        project_name=project,
                        repo_name=repo_name,
                        PAT=PAT,
                        access_token=access_token,
                        user_id=user_id,
                        multi_scan=multi_scan,
                        files_to_scan=files_to_scan,
                        previous_findings=previous_findings,
                        current_commit_sha=current_commit_sha,
                    )
                finally:
                    if repo_dir and repo_dir.exists():
                        shutil.rmtree(repo_dir)

                if results.get("success"):
                    results["data"]["repository_info"] = {
                        "size_mb": size_info["size_mb"],
                        "primary_language": size_info["language"],
                        "default_branch": size_info["default_branch"],
                        "visibility": size_info["visibility"],
                        "fork_count": size_info["fork_count"],
                        "star_count": size_info["star_count"],
                        "created_at": size_info["created_at"],
                        "updated_at": size_info["updated_at"],
                    }
                return results

            except Exception as e:
                error_msg = f"Scan error: {str(e)}"
                logger.error(error_msg)
                if azure_analysis:
                    azure_analysis.status = "error"
                    azure_analysis.error = error_msg
                    db_session.commit()
                return {
                    "success": False,
                    "error": {
                        "message": str(e),
                        "code": "SCAN_ERROR",
                        "type": type(e).__name__,
                        "timestamp": datetime.now().isoformat(),
                    },
                }
    except Exception as e:
        error_msg = f"Handler error: {str(e)}"
        logger.error(error_msg)
        if azure_analysis:
            azure_analysis.status = "error"
            azure_analysis.error = error_msg
            db_session.commit()
        return {
            "success": False,
            "error": {
                "message": "Unexpected error in scan handler",
                "code": "INTERNAL_ERROR",
                "details": str(e),
                "type": type(e).__name__,
                "timestamp": datetime.now().isoformat(),
            },
        }
    # check repository size

    # clone repository

    # scan repository


async def get_full_file_content_with_details(
    session: aiohttp.ClientSession,
    organization_name: str,
    project_name: str,
    repo_name: str,
    file_path: str,
    PAT: str = None,
    access_token: str = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Dict[str, Any]:
    """
    Fetch full file content from Azure DevOps with detailed error information

    Args:
        session: aiohttp client session
        organization_name: Azure DevOps organization name
        project_name: Azure DevOps project name
        repo_name: Azure DevOps repository name
        file_path: Path to the file
        PAT: Personal Access Token for authentication (optional)
        access_token: OAuth access token for authentication (optional)
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries (will be exponentially increased)

    Note: Either PAT or access_token must be provided, but not both.

    Returns:
        Dict[str, Any]: Result with 'success', 'content', 'error' fields
    """
    try:
        logger.info(f"Attempting to fetch file content for: {file_path}")
        api_url = f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/git/repositories/{quote(repo_name)}/items?path={quote(file_path)}&api-version=7.1"

        auth_header = create_auth_header(PAT=PAT, access_token=access_token)
        headers = {
            **auth_header,
            "Content-Type": "text/plain",
        }

        logger.info(f"Azure Devops API URL: {api_url}")

        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                async with session.get(api_url, headers=headers) as response:
                    status = response.status
                    logger.info(f"Azure Devops API Response Status: {status}")

                    if status == 200:
                        data = await response.text()
                        if data:
                            logger.info(f"Successfully fetched content for {file_path}")
                            return {"success": True, "content": data, "error": None}
                        else:
                            logger.warning(
                                f"No content field in Azure Devops response for {file_path}"
                            )
                            return {
                                "success": False,
                                "content": None,
                                "error": {
                                    "message": "File exists but contains no content",
                                    "code": "EMPTY_FILE",
                                    "details": f"File {file_path} was found but is empty",
                                },
                            }
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Unexpected Azure Devops API status ({status}): {error_text}"
                        )
                        return {
                            "success": False,
                            "content": None,
                            "error": {
                                "message": f"Azure DevOps API error: {status}",
                                "code": "API_ERROR",
                                "details": (
                                    error_text[:200]
                                    if error_text
                                    else f"HTTP {status} error"
                                ),
                            },
                        }

            except aiohttp.ClientResponseError as e:
                # Handle HTTP error status codes that are raised due to raise_for_status=True
                status = e.status
                logger.info(
                    f"Azure DevOps API Response Status (ClientResponseError): {status}"
                )

                if status == 404:
                    logger.warning(
                        f"File not found: {file_path} (Original path: {file_path})"
                    )
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": f"File not found: {file_path}",
                            "code": "FILE_NOT_FOUND",
                            "details": f"The file '{file_path}' does not exist in the repository",
                        },
                    }
                elif status == 403:
                    # For 403, we need to check if it's rate limiting or access denied
                    # We need to read the response body, but with ClientResponseError we might not have access to it
                    # Let's check the error message for rate limiting keywords
                    error_message = str(e)
                    if "rate limit" in error_message.lower():
                        retry_delay = base_delay * (2**retry_count)
                        logger.warning(
                            f"Rate limited. Waiting {retry_delay}s before retry {retry_count + 1}/{max_retries}"
                        )
                        await asyncio.sleep(retry_delay)
                        retry_count += 1
                        continue
                    else:
                        logger.error(f"Access denied: {str(e)}")
                        return {
                            "success": False,
                            "content": None,
                            "error": {
                                "message": f"Access denied: {e.message if hasattr(e, 'message') else str(e)}",
                                "code": "ACCESS_DENIED",
                                "details": "You don't have permission to access this file or the authentication token is invalid",
                            },
                        }
                elif status in {502, 503, 504}:
                    retry_delay = base_delay * (2**retry_count)
                    logger.warning(
                        f"Gateway error {status}. Retrying in {retry_delay}s ({retry_count + 1}/{max_retries})"
                    )
                    await asyncio.sleep(retry_delay)
                    retry_count += 1
                    continue
                else:
                    # For other HTTP errors, don't retry
                    logger.error(f"Azure DevOps API error ({status}): {str(e)}")
                    return {
                        "success": False,
                        "content": None,
                        "error": {
                            "message": f"Azure DevOps API error: {status}",
                            "code": "API_ERROR",
                            "details": f"HTTP {status} error: {e.message}",
                        },
                    }
            except aiohttp.ClientError as e:
                last_error = e
                retry_delay = base_delay * (2**retry_count)
                logger.warning(
                    f"Network error: {str(e)}. Retrying in {retry_delay}s ({retry_count + 1}/{max_retries})"
                )
                await asyncio.sleep(retry_delay)
                retry_count += 1
                continue

        if last_error:
            logger.error(
                f"Failed to fetch file content after {max_retries} retries: {str(last_error)}"
            )
            return {
                "success": False,
                "content": None,
                "error": {
                    "message": f"Network error after {max_retries} retries: {str(last_error)}",
                    "code": "NETWORK_ERROR",
                    "details": "Failed to connect to Azure DevOps API after multiple attempts",
                },
            }

        return {
            "success": False,
            "content": None,
            "error": {
                "message": "Unknown error occurred",
                "code": "UNKNOWN_ERROR",
                "details": "An unexpected error occurred while fetching the file",
            },
        }

    except Exception as e:
        logger.error(f"Unexpected error fetching file content: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return {
            "success": False,
            "content": None,
            "error": {
                "message": f"Unexpected error: {str(e)}",
                "code": "UNEXPECTED_ERROR",
                "details": str(e),
            },
        }


async def get_full_file_content(
    session: aiohttp.ClientSession,
    organization_name: str,
    project_name: str,
    repo_name: str,
    file_path: str,
    PAT: str = None,
    access_token: str = None,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Optional[str]:
    """
    Fetch full file content from Azure DevOps

    Args:
        session: aiohttp client session
        organization_name: Azure DevOps organization name
        project_name: Azure DevOps project name
        repo_name: Azure DevOps repository name
        file_path: Path to the file
        PAT: Personal Access Token for authentication (optional)
        access_token: OAuth access token for authentication (optional)
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries (will be exponentially increased)

    Note: Either PAT or access_token must be provided, but not both.

    Returns:
        Optional[str]: File content if successful, None otherwise
    """
    result = await get_full_file_content_with_details(
        session=session,
        organization_name=organization_name,
        project_name=project_name,
        repo_name=repo_name,
        file_path=file_path,
        PAT=PAT,
        access_token=access_token,
        max_retries=max_retries,
        base_delay=base_delay,
    )
    return result.get("content")


async def send_findings_to_semgrep_rag(session, findings, user_id, repo_name):
    """Send semgrep findings to RAG API for additional analysis - all at once after deleting previous data."""
    try:
        logger.info(f"Starting semgrep RAG processing for {len(findings)} findings")
        RAG_URL = os.getenv("RAG_URL")
        if not RAG_URL:
            logger.error("RAG_URL environment variable is not set")
            return {"error": "RAG_URL environment variable is not set"}

        # Step 1: Delete previous repo data (no retry logic)
        delete_endpoint = f"{RAG_URL}/delete_repo"
        delete_payload = {"user_id": user_id, "reponame": repo_name}

        logger.info(f"Attempting to delete previous RAG data for repo: {repo_name}")
        try:
            async with session.post(
                delete_endpoint, json=delete_payload, timeout=30
            ) as response:
                if response.status == 200:
                    logger.info(
                        f"Successfully deleted previous RAG data for repo: {repo_name}"
                    )
                else:
                    error_text = await response.text()
                    logger.warning(
                        f"Delete operation returned status {response.status}: {error_text}"
                    )
        except Exception as delete_error:
            logger.warning(
                f"Delete operation failed (continuing anyway): {str(delete_error)}"
            )

        # Step 2: Send all findings at once with retry logic
        rag_endpoint = f"{RAG_URL}/rag_semgrep_analysis"
        payload = {
            "user_id": user_id,
            "reponame": repo_name,
            "file": findings,  # All findings in one request
        }

        logger.info(
            f"Sending all {len(findings)} findings to semgrep RAG API in single request"
        )

        # Retry logic for the main RAG analysis (3 attempts)
        for retry in range(3):
            try:
                async with session.post(
                    rag_endpoint, json=payload, timeout=60
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(
                            f"Successfully processed all {len(findings)} findings through semgrep RAG API"
                        )
                        return result
                    elif response.status in {502, 503, 504} and retry < 2:
                        logger.warning(
                            f"Retrying semgrep RAG request in {2 * (retry + 1)} seconds"
                        )
                        await asyncio.sleep(2 * (retry + 1))
                        continue
                    else:
                        error_text = await response.text()
                        logger.warning(
                            f"Semgrep RAG API error: {response.status} - {error_text[:100]}"
                        )
                        break
            except Exception as e:
                if retry < 2:
                    logger.warning(f"Request error, retrying semgrep RAG: {str(e)}")
                    await asyncio.sleep(2)
                    continue
                logger.error(
                    f"Failed to process semgrep RAG after all retries: {str(e)}"
                )
                break

        return {
            "error": "Failed to process findings through semgrep RAG API after all retries"
        }

    except Exception as e:
        logger.error(f"Error in send_findings_to_semgrep_rag: {str(e)}")
        return {"error": str(e)}


async def process_findings_with_rag(
    session: aiohttp.ClientSession,
    findings: List[Dict],
    user_id: str,
    organization_name: str,
    project_name: str,
    repo_name: str,
    PAT: str = None,
    access_token: str = None,
    batch_size: int = 5,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Process findings with RAG API.

    Args:
        session: aiohttp client session
        findings: List of findings to process
        user_id: User identifier
        organization_name: organization where Azure Devops repository is located
        project_name: project where Azure Devops repository is located
        repo_name: Azure Devops repository name
        PAT: Personal Access Token (optional)
        access_token: OAuth access token (optional)
        batch_size: Number of files to process in each batch

    Note: Either PAT or access_token must be provided, but not both.
        repo_name: Azure Devops repository name
        PAT: Azure devops PAT
        batch_size: Number of files to process in each batch

    Returns:
        Tuple[List[Dict], List[Dict]]: (RAG responses, findings)
    """
    try:
        logger.info(f"Starting RAG processing for {len(findings)} findings")
        RAG_API_URL = os.getenv("RAG_API_URL")
        if not RAG_API_URL:
            logger.warning("RAG_API_URL not configured, skipping RAG processing")
            return [], findings  # Return original findings if RAG not available

        # Group findings by file for efficient processing
        file_findings = {}
        for finding in findings:
            file_path = finding.get("file")
            if file_path:
                if file_path not in file_findings:
                    file_findings[file_path] = []
                file_findings[file_path].append(finding)

        logger.info(f"Unique files with findings to process: {len(file_findings)}")

        # Process files in batches
        total_size = 0
        rag_responses = []
        RETRYABLE_STATUS_CODES = {502, 503, 504}
        PERMANENT_ERROR_CODES = {400, 401, 403}
        max_retries = 3
        base_retry_delay = 2

        for i in range(0, len(file_findings), batch_size):
            batch_files = list(file_findings.keys())[i : i + batch_size]
            logger.info(
                f"Processing batch {i//batch_size + 1} of {len(file_findings)//batch_size + 1}"
            )

            batch_payload = []
            batch_size_bytes = 0

            # Prepare batch payload
            for file_path in batch_files:
                logger.info(f"Fetching content for file: {file_path}")
                file_content = await get_full_file_content(
                    session=session,
                    organization_name=organization_name,
                    project_name=project_name,
                    repo_name=repo_name,
                    file_path=file_path,
                    PAT=PAT,
                    access_token=access_token,
                )

                if file_content:
                    content_size = len(file_content.encode("utf-8"))
                    total_size += content_size
                    batch_size_bytes += content_size

                    logger.info(f"File {file_path} size: {content_size/1024:.2f} KB")

                    batch_payload.append(
                        {
                            "user_id": user_id,
                            "file": file_content,
                            "reponame": repo_name,
                            "filename": file_path,
                        }
                    )
                else:
                    logger.warning(f"Failed to fetch content for file: {file_path}")

            if batch_payload:
                logger.info(f"Sending batch of {len(batch_payload)} files to RAG API")
                logger.info(f"Batch size: {batch_size_bytes/1024:.2f} KB")

                # Retry loop for RAG API calls
                for retry in range(max_retries):
                    try:
                        retry_delay = base_retry_delay * (retry + 1)

                        async with session.post(
                            RAG_API_URL, json=batch_payload, timeout=30
                        ) as response:
                            logger.info(f"RAG API Response Status: {response.status}")

                            if response.status == 200:
                                result = await response.json()
                                new_responses = result.get("results", [])
                                logger.info(
                                    f"Successfully processed {len(new_responses)} files through RAG API"
                                )
                                rag_responses.extend(new_responses)
                                break

                            elif response.status in RETRYABLE_STATUS_CODES:
                                error_text = await response.text()
                                if retry < max_retries - 1:
                                    logger.warning(
                                        f"RAG API returned {response.status}, attempt {retry + 1}/{max_retries}. "
                                        f"Retrying in {retry_delay} seconds..."
                                    )
                                    await asyncio.sleep(retry_delay)
                                    continue
                                else:
                                    logger.error(
                                        f"RAG API failed after all retries. Status: {response.status}, Error: {error_text}"
                                    )

                            elif response.status in PERMANENT_ERROR_CODES:
                                error_text = await response.text()
                                logger.error(
                                    f"RAG API permanent error (status {response.status}): {error_text}"
                                )
                                break

                            else:
                                error_text = await response.text()
                                logger.error(
                                    f"RAG API unexpected error (status {response.status}): {error_text}"
                                )
                                if retry < max_retries - 1:
                                    await asyncio.sleep(retry_delay)
                                    continue

                    except asyncio.TimeoutError:
                        logger.warning(
                            f"RAG API timeout, attempt {retry + 1}/{max_retries}"
                        )
                        if retry < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
                        logger.error("RAG API timeout after all retries")

                    except Exception as e:
                        logger.error(f"RAG API request failed: {str(e)}")
                        logger.error(f"Full error: {traceback.format_exc()}")
                        if retry < max_retries - 1:
                            await asyncio.sleep(retry_delay)
                            continue
                        break

                # Small delay between batches
                await asyncio.sleep(1)

        logger.info(f"RAG processing completed. Files processed: {len(rag_responses)}")
        logger.info(f"Total size processed: {total_size/1024:.2f} KB")

        return rag_responses, findings  # Always return original findings

    except Exception as e:
        logger.error(f"Error in process_findings_with_rag: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return [], findings


@dataclass
class ScanConfig:
    """
    Configuration for repository scanning
    """

    max_file_size_mb: int = 50
    max_total_size_mb: int = 600
    max_memory_mb: int = 3000
    chunk_size_mb: int = 60
    max_files_per_chunk: int = 100

    timeout_map: Dict[str, int] = field(
        default_factory=lambda: {
            "ci": 1200,
            "security-audit": 540,
            "owasp-top-ten": 600,
            "supply-chain": 300,
            "insecure-transport": 300,
            "jwt": 300,
            "secrets": 300,
            "xss": 300,
            "sql-injection": 300,
            "javascript": 300,
            "python": 300,
            "java": 300,
            "php": 300,
            "csharp": 300,
            "csharp-security": 300,
            "csharp-webconfig": 180,
            "csharp-cors": 180,
            "csharp-jwt": 180,
            "csharp-csrf": 180,
            "csharp-auth": 240,
            "csharp-sqlinjection": 240,
            "csharp-xss": 180,
            "dotnet": 300,
        }
    )

    default_timeout: int = 600
    chunk_timeout: int = 120
    file_timeout_seconds: int = 20
    max_retries: int = 2
    concurrent_processes: int = 2

    exclude_patterns: List[str] = field(
        default_factory=lambda: [
            ".git",
            "node_modules",
            "vendor",
            "*.min.*",
            "*.bundle.*",
            "*.map",
            "*.{pdf,jpg,jpeg,png,gif,zip,tar,gz,rar,mp4,mov}",
        ]
    )

    core_configs: List[Dict] = field(
        default_factory=lambda: [
            {
                "name": "security-audit",
                "config": "p/security-audit",
                "rules_count": 225,
            },
            {"name": "owasp-top-ten", "config": "p/owasp-top-ten", "rules_count": 300},
            {"name": "secrets", "config": "p/secrets", "rules_count": 50},
            {"name": "supply-chain", "config": "p/supply-chain", "rules_count": 200},
        ]
    )

    web_configs: List[Dict] = field(
        default_factory=lambda: [
            {
                "name": "insecure-transport",
                "config": "p/insecure-transport",
                "rules_count": 100,
            },
            {"name": "jwt", "config": "p/jwt", "rules_count": 50},
            {"name": "xss", "config": "p/xss", "rules_count": 100},
            {"name": "sql-injection", "config": "p/sql-injection", "rules_count": 75},
            {
                "name": "command-injection",
                "config": "p/command-injection",
                "rules_count": 75,
            },
            {"name": "trailofbits", "config": "p/trailofbits", "rules_count": 100},
        ]
    )

    language_configs: Dict[str, List[Dict]] = field(
        default_factory=lambda: {
            "python": [
                {"name": "python", "config": "p/python", "rules_count": 100},
                {"name": "django", "config": "p/django", "rules_count": 75},
                {"name": "flask", "config": "p/flask", "rules_count": 50},
                {"name": "fastapi", "config": "p/fastapi", "rules_count": 40},
            ],
            "javascript": [
                {"name": "javascript", "config": "p/javascript", "rules_count": 100},
                {"name": "nodejs", "config": "p/nodejs", "rules_count": 100},
                {"name": "react", "config": "p/react", "rules_count": 100},
            ],
            "typescript": [
                {"name": "typescript", "config": "p/typescript", "rules_count": 100},
                {"name": "nodejs", "config": "p/nodejs", "rules_count": 100},
                {"name": "react", "config": "p/react", "rules_count": 100},
            ],
            "java": [
                {"name": "java", "config": "p/java", "rules_count": 100},
                {"name": "spring", "config": "p/spring", "rules_count": 100},
            ],
            "php": [
                {"name": "php", "config": "p/php", "rules_count": 100},
            ],
            "c#": [
                {"name": "csharp", "config": "r/csharp", "rules_count": 150},
                {
                    "name": "csharp-security",
                    "config": "r/csharp.security",
                    "rules_count": 200,
                },
                {
                    "name": "csharp-webconfig",
                    "config": "r/csharp.webconfig",
                    "rules_count": 50,
                },
                {
                    "name": "csharp-cors",
                    "config": "r/csharp.security.cors",
                    "rules_count": 25,
                },
                {
                    "name": "csharp-jwt",
                    "config": "r/csharp.security.jwt",
                    "rules_count": 30,
                },
                {
                    "name": "csharp-csrf",
                    "config": "r/csharp.security.csrf",
                    "rules_count": 25,
                },
                {
                    "name": "csharp-auth",
                    "config": "r/csharp.security.auth",
                    "rules_count": 75,
                },
                {
                    "name": "csharp-sqlinjection",
                    "config": "r/csharp.security.injection.sql",
                    "rules_count": 50,
                },
                {
                    "name": "csharp-xss",
                    "config": "r/csharp.security.xss",
                    "rules_count": 40,
                },
                {"name": "dotnet", "config": "r/dotnet", "rules_count": 175},
            ],
            "go": [
                {"name": "go", "config": "p/golang", "rules_count": 100},
            ],
            "ruby": [
                {"name": "ruby", "config": "p/ruby", "rules_count": 75},
                {"name": "rails", "config": "p/rails", "rules_count": 75},
            ],
        }
    )


class AzureSecurityScanner:
    def __init__(
        self,
        config: ScanConfig = ScanConfig(),
        db_session: Optional[Session] = None,
        analysis_id: Optional[int] = None,
    ):
        self.config = config
        self.db_session = db_session
        self.analysis_id = analysis_id
        self.temp_dir = None
        self.repo_dir = None
        self._session = None
        self.detected_language = None
        self._repo_name = None
        self._user_id = None
        self.scan_stats = {
            "start_time": None,
            "end_time": None,
            "total_files": 0,
            "files_processed": 0,
            "files_skipped": 0,
            "files_too_large": 0,
            "total_size_mb": 0,
            "memory_usage_mb": 0,
            "findings_count": 0,
            "scan_durations": {},
        }

    def get_language_specific_configs(self, language: str) -> List[Dict]:
        """Get relevant scan configs based on repository language."""
        configs = []

        # Always include core security configs
        configs.extend(self.config.core_configs)
        logger.info("Added core security configs")

        # Always include web security configs
        configs.extend(self.config.web_configs)
        logger.info("Added web security configs")

        if not language:
            logger.warning(
                "No language detected, using core and web security configs only"
            )
            return configs

        # Normalize language name
        language = language.lower()

        # Handle C# variations
        if language in ["csharp", "cs", "dotnet", "net"]:
            language = "c#"

        # Add language-specific configs if available
        if language in self.config.language_configs:
            configs.extend(self.config.language_configs[language])
            logger.info(f"Added {language}-specific configs")
        else:
            logger.warning(f"No specific configs available for language: {language}")

        logger.info(
            f"Total configs to run: {len(configs)} ({[c['name'] for c in configs]})"
        )
        return configs

    async def _run_semgrep_scan(
        self, target_dir: Path, scan_config: Dict, file_list: Optional[List[str]] = None
    ) -> Dict:
        """Execute semgrep scan with enhanced error handling and monitoring"""
        semgrepignore_path = target_dir / ".semgrepignore"
        start_time = time.time()
        scan_name = scan_config["name"]

        try:
            # Create .semgrepignore file
            with open(semgrepignore_path, "w") as f:
                for pattern in self.config.exclude_patterns:
                    f.write(f"{pattern}\n")

            timeout = self.config.timeout_map.get(
                scan_name, self.config.default_timeout
            )
            logger.info(f"Starting {scan_name} scan with {timeout}s timeout")

            cmd = [
                "semgrep",
                "scan",
                "--config",
                scan_config["config"],
                "--json",
                "--verbose",
                "--metrics=on",
                "--no-git-ignore",
                "--optimizations=all",
            ]

            if file_list:
                # Incremental scan: scan only specific files
                cmd.extend([str(Path(target_dir) / f) for f in file_list])
                logger.critical(
                    f"*** URGENT: Running Azure DevOps incremental Semgrep scan on {len(file_list)} files for config {scan_name}"
                )
                logger.debug(
                    f"Azure DevOps incremental semgrep files: {file_list[:5]}{'...' if len(file_list) > 5 else ''}"
                )
            else:
                # Full scan: scan entire directory
                cmd.append(str(target_dir))
                logger.critical(
                    f"*** URGENT: Running Azure DevOps full Semgrep scan for config {scan_name}"
                )
                logger.debug(
                    f"Azure DevOps full semgrep: target_dir={target_dir}, config={scan_name}"
                )

            memory_before = psutil.Process().memory_info().rss / (1024 * 1024)
            logger.info(f"Memory usage before {scan_name}: {memory_before:.2f}MB")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir),
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                elapsed_time = time.time() - start_time
                error_msg = f"Scan {scan_name} timed out after {elapsed_time:.2f}s"
                logger.error(error_msg)
                return self._create_empty_result(error=error_msg)

            memory_after = psutil.Process().memory_info().rss / (1024 * 1024)
            memory_diff = memory_after - memory_before
            logger.info(
                f"Memory usage after {scan_name}: {memory_after:.2f}MB (Δ: {memory_diff:+.2f}MB)"
            )

            stderr_output = stderr.decode() if stderr else ""
            if stderr_output:
                logger.warning(f"Semgrep stderr ({scan_name}): {stderr_output}")

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result(error=f"No output from {scan_name}")

            try:
                results = json.loads(output)
                processed_results = self._process_scan_results(results)
                scan_duration = time.time() - start_time
                self.scan_stats["scan_durations"][scan_name] = scan_duration

                processed_results["scan_source"] = scan_name
                processed_results["scan_duration"] = scan_duration
                processed_results["memory_usage"] = {
                    "before": memory_before,
                    "after": memory_after,
                    "difference": memory_diff,
                }

                logger.info(f"Completed {scan_name} scan in {scan_duration:.2f}s")
                return processed_results

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse {scan_name} output: {str(e)}"
                logger.error(error_msg)
                return self._create_empty_result(error=error_msg)

        except Exception as e:
            error_msg = f"Error in {scan_name} scan: {str(e)}"
            logger.error(error_msg)
            return self._create_empty_result(error=error_msg)

        finally:
            if semgrepignore_path.exists():
                semgrepignore_path.unlink()

    async def run_multiple_semgrep_scans(
        self, target_dir: Path, files_to_scan: Optional[list] = None
    ) -> Dict:
        """Run multiple semgrep scans based on detected language"""
        try:
            logger.info(f"Detected repository language: {self.detected_language}")

            # Get relevant configs based on language
            selected_configs = self.get_language_specific_configs(
                self.detected_language
            )

            # Add these lines for progress tracking
            user_id = getattr(self, "_user_id", "")
            repo_name = getattr(self, "_repo_name")
            total_configs = len(selected_configs)

            all_results = []
            merged_findings = []
            total_files_scanned = 0
            total_files_skipped = 0
            # **UPDATED: Initialize with all severity levels**
            severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
            category_counts = defaultdict(int)
            seen_findings = set()
            errors = []

            # Run selected scans sequentially
            for i, scan_config in enumerate(selected_configs):
                try:
                    # Update progress here
                    progress = (i / total_configs) * 100
                    update_scan_progress(user_id, repo_name, "analyzing", progress)

                    logger.info(
                        f"Starting scan with config: {scan_config['name']} ({scan_config['rules_count']} rules)"
                    )
                    result = await self._run_semgrep_scan(
                        target_dir, scan_config, files_to_scan
                    )
                    all_results.append(result)

                    findings = result.get("findings", [])
                    stats = result.get("stats", {})

                    # Update counters
                    total_files_scanned = max(
                        total_files_scanned,
                        stats.get("scan_stats", {}).get("files_scanned", 0),
                    )
                    total_files_skipped += stats.get("scan_stats", {}).get(
                        "skipped_files", 0
                    )

                    # Process and deduplicate findings
                    for finding in findings:
                        finding_id = (
                            finding.get("file", ""),
                            finding.get("line_start", 0),
                            finding.get("line_end", 0),
                            finding.get("code_snippet", ""),
                        )

                        if finding_id not in seen_findings:
                            seen_findings.add(finding_id)
                            finding["scan_source"] = scan_config["name"]
                            merged_findings.append(finding)
                            severity = finding.get("severity", "INFO").upper()
                            category = finding.get("category", "unknown")

                            # **UPDATED: Ensure severity is in our expected list**
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            else:
                                # Handle unexpected severities by mapping them to INFO
                                severity_counts["INFO"] += 1

                            category_counts[category] += 1

                except Exception as e:
                    error_msg = f"Error in {scan_config['name']} scan: {str(e)}"
                    logger.error(error_msg)
                    errors.append(
                        {
                            "config": scan_config["name"],
                            "error": str(e),
                            "timestamp": datetime.now().isoformat(),
                        }
                    )

            # Log finding counts
            logger.info(f"Found {len(merged_findings)} total findings")
            logger.info(f"Severity distribution: {dict(severity_counts)}")

            return {
                "findings": merged_findings,
                "stats": {
                    "total_findings": len(merged_findings),
                    "severity_counts": severity_counts,
                    "category_counts": dict(category_counts),
                    "scan_stats": {
                        "files_scanned": total_files_scanned,
                        "skipped_files": total_files_skipped,
                        "files_with_findings": len(
                            set(f.get("file", "") for f in merged_findings)
                        ),
                    },
                    "memory_usage_mb": psutil.Process().memory_info().rss
                    / (1024 * 1024),
                    "scan_durations": self.scan_stats["scan_durations"],
                },
                "errors": errors if errors else None,
                "language": self.detected_language,
            }

        except Exception as e:
            logger.error(f"Critical error in scan execution: {str(e)}")
            if self._user_id and self._repo_name:
                update_scan_progress(self._user_id, self._repo_name, "error", 0)

            return self._create_empty_result(error=str(e))

    async def _check_repository_size(
        self,
        organization_name: str,
        project_name: str,
        repo_name: str,
        PAT: str = None,
        access_token: str = None,
    ) -> Dict:
        """Check repository size and metadata using Azure Devops API"""
        if not self._session:
            raise RuntimeError("Scanner session not initialized")

        try:
            if not all([organization_name, project_name, repo_name]) or not (
                PAT or access_token
            ):
                raise ValueError(
                    "Organization name, Project name, Repo name and either PAT or access_token are required to check repository size on Azure Devops"
                )

            logger.info(
                f"Checking Azure Devops repository: {organization_name}/{project_name}/{repo_name}"
            )

            # url to get the repository metadata
            api_url = f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/git/repositories/{quote(repo_name)}?api-version=7.1"
            auth_header = create_auth_header(PAT=PAT, access_token=access_token)
            headers = {
                **auth_header,
                "Content-Type": "application/json",
            }

            data = {}
            async with self._session.get(api_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(
                        f"Azure Devops API error ({response.status}): {error_text}"
                    )

                az_repo_metadata = await response.json()
                size_mb = az_repo_metadata.get("size", 0) / 1000024

                logger.info(f"Repository size: {size_mb:.2f}MB")
                logger.info(
                    f"Default branch: {az_repo_metadata.get('defaultBranch', 'main')}"
                )

                az_default_branch_name = az_repo_metadata.get("defaultBranch", "main")
                default_branch = (
                    az_default_branch_name.split("refs/heads/")[1]
                    if "refs/heads/" in az_default_branch_name
                    else az_default_branch_name
                )
                data.update(
                    {
                        "size_mb": size_mb,
                        "is_compatible": size_mb <= self.config.max_total_size_mb,
                        "default_branch": default_branch,
                        "visibility": "private",
                        "fork_count": 0,
                        "star_count": 0,
                        "created_at": az_repo_metadata["project"]["lastUpdateTime"],
                        "updated_at": az_repo_metadata["project"]["lastUpdateTime"],
                    }
                )

            # url to get the language data. azure devops has it per organization so you have to filter for the repo
            api_url = f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/projectanalysis/languagemetrics?api-version=7.1"
            async with self._session.get(api_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(
                        f"Azure Devops API error ({response.status}): {error_text}"
                    )
                az_project_analysis_response = await response.json()
                repos = list(
                    filter(
                        lambda repo: repo["name"] == repo_name,
                        az_project_analysis_response["repositoryLanguageAnalytics"],
                    )
                )
                if len(repos) == 0:
                    print(data)
                    data.update({"language": "unknown"})
                    return data

                highest_language = "unknown"
                highest_language_percentage = 0
                for lang in repos[0]["languageBreakdown"]:
                    if lang.get("languagePercentage", 0) > highest_language_percentage:
                        highest_language = lang["name"]
                        highest_language_percentage = lang["languagePercentage"]
                self.detected_language = highest_language
                logger.info(f"Detected language: {self.detected_language}")
                data.update({"language": highest_language})
                return data

        except Exception as e:
            logger.error(f"Repository size check failed: {str(e)}")
            raise

    async def _clone_repository(
        self,
        organization_name: str,
        project_name: str,
        repo_name: str,
        branch: str,
        repo_size,
        PAT: str = None,
        access_token: str = None,
    ) -> Path:
        """
        Clone repository with size validation, optimizations, and improved directory handling.
        It assumes that repository size has already been confirmed
        """
        try:
            # Verify repository size
            # size_info = await self._check_repository_size(
            #     organization_name, project_name, repo_name, PAT
            # )
            # if not size_info["is_compatible"]:
            #     raise ValueError(
            #         f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
            #         f"limit of {self.config.max_total_size_mb}MB"
            #     )

            # Generate a unique directory name using timestamp and random identifier
            import uuid

            unique_id = uuid.uuid4().hex[:8]
            self.repo_dir = (
                self.temp_dir
                / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{unique_id}"
            )

            # Ensure the directory is clean before cloning
            if self.repo_dir.exists():
                logger.warning(f"Directory {self.repo_dir} already exists, cleaning up")
                shutil.rmtree(self.repo_dir)

            # Create parent directories if needed
            self.repo_dir.parent.mkdir(parents=True, exist_ok=True)

            # Construct authenticated URL based on authentication type
            if PAT:
                auth_url = f"https://{PAT}@dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_git/{quote(repo_name)}"
            elif access_token:
                # For OAuth access tokens, we need to use the token as the password with a dummy username
                auth_url = f"https://oauth:{access_token}@dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_git/{quote(repo_name)}"
            else:
                raise ValueError(
                    "Either PAT or access_token must be provided for git clone"
                )

            logger.info(f"Cloning repository to {self.repo_dir}")

            # Optimize clone operation
            git_options = [
                "--depth=1",
                "--single-branch",
                "--no-tags",
                f"--branch={branch}",
            ]

            repo = git.Repo.clone_from(
                auth_url, self.repo_dir, multi_options=git_options
            )

            logger.info(f"Successfully cloned repository: {repo_size:.2f}MB")
            return self.repo_dir

        except Exception as e:
            # Clean up the directory if it exists and clone failed
            if hasattr(self, "repo_dir") and self.repo_dir and self.repo_dir.exists():
                try:
                    shutil.rmtree(self.repo_dir)
                    logger.info(
                        f"Cleaned up directory after failed clone: {self.repo_dir}"
                    )
                except Exception as cleanup_error:
                    logger.error(f"Failed to clean up directory: {str(cleanup_error)}")

            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and normalize scan results"""
        findings = results.get("results", [])
        stats = results.get("stats", {})
        paths = results.get("paths", {})
        parse_metrics = results.get("parse_metrics", {})

        processed_findings = []
        # **UPDATED: Initialize with all severity levels**
        severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        category_counts = defaultdict(int)
        files_with_findings = set()

        for finding in findings:
            file_path = finding.get("path", "")
            if file_path:
                files_with_findings.add(file_path)

            severity = finding.get("extra", {}).get("severity", "INFO").upper()
            category = (
                finding.get("extra", {}).get("metadata", {}).get("category", "security")
            )

            # **UPDATED: Only increment if severity is in our expected list**
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                # Handle unexpected severities by mapping them to INFO
                severity_counts["INFO"] += 1

            category_counts[category] += 1

            processed_findings.append(
                {
                    "id": finding.get("check_id"),
                    "file": file_path,
                    "line_start": finding.get("start", {}).get("line"),
                    "line_end": finding.get("end", {}).get("line"),
                    "code_snippet": finding.get("extra", {}).get("lines", ""),
                    "message": finding.get("extra", {}).get("message", ""),
                    "severity": severity,
                    "category": category,
                    "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": finding.get("extra", {})
                    .get("metadata", {})
                    .get("owasp", []),
                    "fix_recommendations": finding.get("extra", {})
                    .get("metadata", {})
                    .get("fix", ""),
                    "references": finding.get("extra", {})
                    .get("metadata", {})
                    .get("references", []),
                }
            )

        scan_stats = {
            "total_files": stats.get("total", {}).get("files", 0),
            "files_scanned": len(paths.get("scanned", [])),
            "files_with_findings": len(files_with_findings),
            "skipped_files": len(paths.get("skipped", [])),
            "partially_scanned": parse_metrics.get("partially_parsed_files", 0),
        }

        return {
            "findings": processed_findings,
            "stats": {
                "total_findings": len(processed_findings),
                "severity_counts": severity_counts,  # **UPDATED: Always complete**
                "category_counts": dict(category_counts),
                "scan_stats": scan_stats,
                "memory_usage_mb": self.scan_stats.get("memory_usage_mb", 0),
            },
        }

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure with optional error information"""
        return {
            "findings": [],
            "stats": {
                "total_findings": 0,
                "severity_counts": {
                    "CRITICAL": 0,
                    "ERROR": 0,
                    "WARNING": 0,
                    "INFO": 0,
                },  # **UPDATED: Always include all severity levels**
                "category_counts": {},
                "scan_stats": self.scan_stats,
                "memory_usage_mb": self.scan_stats["memory_usage_mb"],
            },
            "errors": [error] if error else [],
        }

    async def scan_repository(
        self,
        organization_name: str,
        project_name: str,
        repo_name: str,
        PAT: str,
        access_token: str,
        user_id: str,
        multi_scan: bool = True,
        files_to_scan: Optional[list] = None,
        previous_findings: Optional[list] = None,
        current_commit_sha: Optional[str] = None,
    ) -> Dict:
        try:
            self._user_id = user_id
            self._repo_name = f"{organization_name}/{repo_name}"

            from progress_tracking import clear_scan_progress

            clear_scan_progress(user_id, f"{organization_name}/{repo_name}")

            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "initializing", 0
            )

            # Validate URLs for APIs
            AI_RERANK_URL = os.getenv("RERANK_API_URL")
            if not AI_RERANK_URL:
                raise ValueError("RERANK_API_URL not configured")

            # SCAN: if files_to_scan is set, restrict scans
            if files_to_scan:

                def file_filter(path):
                    norm_candidates = [path, path.lstrip("/")]
                    return any(
                        norm_path in (f.lstrip("/"))
                        for norm_path in norm_candidates
                        for f in files_to_scan
                    )

            else:
                file_filter = None

            # already checked repo size and cloned
            # size_info = await self._check_repository_size(repo_url, installation_token)
            # update_scan_progress(user_id, repo_name, "cloning", 0)

            # # Clone the repository and scan it
            # await self._clone_repository(repo_url, installation_token)
            # update_scan_progress(user_id, repo_name, "analyzing", 0)

            # Initial scan
            if files_to_scan:
                logger.critical(
                    f"*** URGENT: Running Azure DevOps incremental scan on {len(files_to_scan)} changed files"
                )
                logger.debug(
                    f"Azure DevOps incremental scan files: {files_to_scan[:10]}{'...' if len(files_to_scan) > 10 else ''}"
                )
                scan_results = (
                    await self.run_multiple_semgrep_scans(self.repo_dir, files_to_scan)
                    if multi_scan
                    else await self._run_semgrep_scan(
                        self.repo_dir, self.config.core_configs[0], files_to_scan
                    )
                )
            else:
                logger.critical(
                    f"*** URGENT: Running Azure DevOps full scan on entire repository"
                )
                logger.debug(
                    f"Azure DevOps full scan: repo_dir={self.repo_dir}, multi_scan={multi_scan}"
                )
                scan_results = (
                    await self.run_multiple_semgrep_scans(self.repo_dir)
                    if multi_scan
                    else await self._run_semgrep_scan(
                        self.repo_dir, self.config.core_configs[0]
                    )
                )
            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "processing", 0
            )

            # Get all findings
            all_findings = scan_results.get("findings", [])
            logger.info(f"Found {len(all_findings)} findings in this scan iteration")

            # MERGE LOGIC: Handle incremental scanning with previous findings
            merged_findings = all_findings
            if files_to_scan and previous_findings:
                # Incremental scan: merge with previous findings
                # Keep findings from unchanged files, replace findings from changed files
                changed_set = set(files_to_scan)
                unchanged_findings = [
                    f for f in previous_findings if f.get("file") not in changed_set
                ]
                merged_findings = unchanged_findings + all_findings
                logger.critical(
                    f"*** URGENT: Azure DevOps incremental scan merged findings: {len(unchanged_findings)} old findings kept, {len(all_findings)} new findings added"
                )
                logger.debug(
                    f"Azure DevOps merge details: changed_files={len(files_to_scan)}, previous_findings={len(previous_findings)}, merged_total={len(merged_findings)}"
                )
            else:
                logger.critical(
                    f"*** URGENT: Azure DevOps scan using {len(all_findings)} current findings (no previous findings or no changed files)"
                )
                logger.debug(
                    f"Azure DevOps scan details: files_to_scan={files_to_scan is not None}, previous_findings={previous_findings is not None}"
                )

            all_findings = merged_findings

            # Initialize variables
            rag_responses = []
            semgrep_rag_response = None

            # New: Send findings to semgrep RAG API
            update_scan_progress(
                user_id,
                f"{organization_name}/{repo_name}",
                "analyzing_vulnerabilities",
                30,
            )
            if merged_findings:
                async with create_secure_client_session() as session:
                    semgrep_rag_response = await send_findings_to_semgrep_rag(
                        session=session,
                        findings=merged_findings,
                        user_id=user_id,
                        repo_name=repo_name,
                    )
                    if semgrep_rag_response and not semgrep_rag_response.get("error"):
                        logger.info("Successfully received semgrep RAG analysis")
                    else:
                        error_msg = (
                            semgrep_rag_response.get("error", "Unknown error")
                            if semgrep_rag_response
                            else "Empty response"
                        )
                        logger.warning(
                            f"Semgrep RAG analysis failed or returned error: {error_msg}"
                        )

            # Process through RAG API if we have any findings (original file content RAG)
            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "analyzing_files", 60
            )
            if len(merged_findings) > 0:  # Explicit length check
                logger.info(
                    f"Processing {len(merged_findings)} findings through file content RAG"
                )
                async with create_secure_client_session() as session:
                    rag_responses, merged_findings = await process_findings_with_rag(
                        session=session,
                        findings=merged_findings,
                        user_id=user_id,
                        organization_name=organization_name,
                        project_name=project_name,
                        repo_name=repo_name,
                        PAT=PAT,
                        access_token=access_token,
                        batch_size=10,
                    )
                    logger.info(
                        f"Received {len(rag_responses)} file content RAG responses"
                    )
            else:
                logger.info("No findings to process through file content RAG")

            # Prepare reranking data
            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "reranking", 80
            )
            rerank_data = {
                "findings": [
                    {
                        "id": idx + 1,
                        "file": finding["file"],
                        "code_snippet": finding["code_snippet"],
                        "message": finding["message"],
                        "severity": finding["severity"],
                    }
                    for idx, finding in enumerate(merged_findings)
                ],
                "metadata": {
                    "repository": repo_name,
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "scan_id": self.analysis_id,
                    "rag_processed": bool(rag_responses),
                    "rag_responses": rag_responses,
                },
            }

            # Handle reranking
            RAG_URL = os.getenv("RAG_URL")
            if not RAG_URL:
                raise ValueError("RAG_URL not configured")
            AI_RERANK_URL = f"{RAG_URL}/vulnerability_reranker_labelled"

            reordered_findings = merged_findings.copy()
            if merged_findings and AI_RERANK_URL:
                import aiohttp

                logger.info(f"Sending {len(merged_findings)} findings for reranking")
                rerank_data = [
                    {
                        "id": f.get("id"),
                        "file": f.get("file"),
                        "severity": f.get("severity", ""),
                    }
                    for f in merged_findings
                ]
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            AI_RERANK_URL, json=rerank_data
                        ) as resp:
                            if resp.status == 200:
                                rerank_response = await resp.json()
                                logger.info(
                                    f"OBSERVING RERANKING RESPONSE: Rerank response: {rerank_response}"
                                )
                                tuples = extract_rerank_tuples(
                                    rerank_response["llm_response"], merged_findings
                                )
                                logger.info(f"[AZURE DEVOPS] OBSERVING RERANKING RESPONSE: Tuples: {tuples}")
                                if tuples:
                                    id_to_finding = {
                                        f.get("id"): f.copy() for f in merged_findings
                                    }
                                    reordered_findings_list = []
                                    for t_id, sev in tuples:
                                        f = id_to_finding.get(t_id)
                                        if f:
                                            f["severity"] = sev
                                            reordered_findings_list.append(f)
                                    reordered_findings = reordered_findings_list
                                else:
                                    pass
                except Exception as e:
                    pass
            else:
                logger.info("No findings to rerank")

            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "finalizing", 90
            )

            results_data = {
                "findings": reordered_findings,
                "stats": scan_results.get("stats", {}),
                "metadata": {
                    "repository_url": f"https://dev.azure.com/{quote(organization_name)}/{quote(project_name)}/_apis/git/repositories/{quote(repo_name)}",
                    "user_id": user_id,
                    "scan_start": self.scan_stats["start_time"].isoformat(),
                    "scan_end": datetime.now().isoformat(),
                    "scan_duration_seconds": (
                        datetime.now() - self.scan_stats["start_time"]
                    ).total_seconds(),
                    "rag_processed": bool(rag_responses),
                    "rag_responses_count": len(rag_responses),
                    "scanned_commit_sha": current_commit_sha,
                },
            }

            # Update database
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AzureDevOpsAnalysisResult).get(
                        self.analysis_id
                    )
                    if analysis:
                        analysis.results = results_data  # All findings
                        analysis.rerank = reordered_findings  # Selected findings with consistent structure
                        analysis.status = "completed"
                        analysis.completed_at = datetime.now()
                        if current_commit_sha:
                            analysis.scanned_commit_sha = current_commit_sha
                        self.db_session.commit()
                        logger.critical(
                            f"*** URGENT: Azure DevOps scan results stored in database - results: {len(all_findings)}, rerank: {len(reordered_findings)}, commit_sha: {current_commit_sha}"
                        )
                        logger.debug(
                            f"Azure DevOps database update: analysis_id={self.analysis_id}, status=completed, findings_count={len(all_findings)}"
                        )
                except Exception as e:
                    self.db_session.rollback()
                    logger.error(f"Database update failed: {str(e)}")

            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "completed", 100
            )

            return {"success": True, "data": results_data}

        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            update_scan_progress(
                user_id, f"{organization_name}/{repo_name}", "error", 0
            )

            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AzureDevOpsAnalysisResult).get(
                        self.analysis_id
                    )
                    if analysis:
                        analysis.status = "error"
                        analysis.error = str(e)
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                except Exception as db_e:
                    logger.error(f"Failed to store error record: {str(db_e)}")
                    self.db_session.rollback()

            return {
                "success": False,
                "error": {
                    "message": str(e),
                    "code": "SCAN_ERROR",
                    "type": type(e).__name__,
                    "timestamp": datetime.now().isoformat(),
                },
            }

    async def __aenter__(self):
        """Initialize scanner resources"""
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup scanner resources"""
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner with enhanced error handling"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix="scanner_"))
            logger.info(f"Created temporary directory: {self.temp_dir}")

            ssl_context = create_ssl_context()
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)

            self._session = aiohttp.ClientSession(
                connector=conn, timeout=timeout, raise_for_status=True
            )

            self.scan_stats["start_time"] = datetime.now()
            logger.info("Scanner initialization completed")

        except Exception as e:
            logger.error(f"Scanner initialization failed: {str(e)}")
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            raise

    async def _cleanup(self):
        """Cleanup scanner resources with proper error handling"""
        try:
            if self._session and not self._session.closed:
                await self._session.close()
                logger.info("Closed aiohttp session")

            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")

            self.scan_stats["end_time"] = datetime.now()

        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")


def deduplicate_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate findings from scan results"""
    if not scan_results.get("success") or "data" not in scan_results:
        return scan_results

    findings = scan_results["data"].get("findings", [])
    if not findings:
        return scan_results

    seen_findings = set()
    deduplicated_findings = []

    for finding in findings:
        finding_signature = (
            finding.get("file", ""),
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            finding.get("category", ""),
            finding.get("severity", ""),
            finding.get("code_snippet", ""),
        )

        if finding_signature not in seen_findings:
            seen_findings.add(finding_signature)
            deduplicated_findings.append(finding)

    scan_results["data"]["findings"] = deduplicated_findings
    scan_results["data"]["summary"]["total_findings"] = len(deduplicated_findings)

    return scan_results


def extract_ids_from_llm_response(
    response_data: Union[Dict, List, str], original_findings: List[Dict] = None
) -> Optional[List[int]]:
    """
    Extract IDs from LLM response text.

    Args:
        response_data: Response from reranking API
        original_findings: Original list of findings (for reference)

    Returns:
        Optional[List[int]]: List of reranked IDs or None if extraction fails
    """
    try:
        logger.info(
            f"Processing reranking response: {json.dumps(response_data, indent=2)}"
        )

        # Handle dictionary response
        if isinstance(response_data, dict):
            # Check for llm_response field
            if "llm_response" in response_data:
                response = response_data["llm_response"]
                logger.info(f"LLM Response content: {response}")

                if not response or response == "[]":
                    logger.warning("Empty llm_response, falling back to original order")
                    return (
                        list(range(1, len(original_findings) + 1))
                        if original_findings
                        else None
                    )

                if isinstance(response, list):
                    return response

                array_match = re.search(r"\[([\d,\s]+)\]", str(response))
                if array_match:
                    id_string = array_match.group(1)
                    return [int(id.strip()) for id in id_string.split(",")]

        # Handle list response
        elif isinstance(response_data, list):
            if not response_data:
                logger.warning("Empty list response")
                return (
                    list(range(1, len(original_findings) + 1))
                    if original_findings
                    else None
                )
            return response_data

        logger.warning("Could not extract IDs from response")
        return list(range(1, len(original_findings) + 1)) if original_findings else None

    except Exception as e:
        logger.error(f"Error extracting IDs from LLM response: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return list(range(1, len(original_findings) + 1)) if original_findings else None


def extract_rerank_tuples(response, selected_findings=None):
    """Parse [(ID, severity), ...] tuples from response (list or string); returns list of (ID, SEVERITY_UPPER) in order."""
    if isinstance(response, str):
        response = ast.literal_eval(response.strip())
    tuples = response if isinstance(response, list) else []
    normalize = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "error": "ERROR",
    }
    logger.info(f"OBSERVING RERANKING RESPONSE: Extracting rerank tuples: {tuples}")
    logger.info(f"OBSERVING RERANKING RESPONSE: Normalize: {normalize}")
    return [
        (int(i), normalize.get(str(s).lower(), str(s).upper()))
        for i, s in tuples
        if isinstance(i, (int, float, str)) and isinstance(s, str)
    ]
