"""
Security Scanner Module

This module provides a unified scanning interface for all repository types.
After a repository is cloned to a temp folder, the scanning process is the same
regardless of the source (GitHub, GitLab, Azure DevOps, CodeCommit).
"""

import os
import re
import ast
import ssl
import json
import base64
import asyncio
import logging
import psutil
import certifi
import aiohttp
import shutil
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
from urllib.parse import quote

from .scan_config import ScanConfig
from .utils import create_ssl_context

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def normalize_severity(severity: str) -> str:
    """Normalize severity string to standard format."""
    severity_map = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "error": "ERROR",
        "medium": "MEDIUM",
        "warning": "WARNING",
        "low": "LOW",
        "info": "INFO",
    }
    return severity_map.get(severity.lower(), severity.upper())


def get_language_specific_configs(
    language: Optional[str], config: ScanConfig
) -> List[Dict]:
    """
    Get relevant scan configs based on repository language.

    Args:
        language: Detected programming language
        config: ScanConfig instance with rule configurations

    Returns:
        List of scan configuration dictionaries
    """
    configs = []

    # Always include core security configs
    configs.extend(config.core_configs)
    logger.info("Added core security configs")

    # Always include web security configs
    configs.extend(config.web_configs)
    logger.info("Added web security configs")

    if not language:
        logger.warning("No language detected, using core and web security configs only")
        return configs

    # Normalize language name
    language = language.lower()

    # Handle C# variations
    if language in ["csharp", "cs", "dotnet", "net"]:
        language = "c#"

    # Add language-specific configs if available
    if language in config.language_configs:
        configs.extend(config.language_configs[language])
        logger.info(f"Added {language}-specific configs")
    else:
        logger.warning(f"No specific configs available for language: {language}")

    logger.info(
        f"Total configs to run: {len(configs)} ({[c['name'] for c in configs]})"
    )
    return configs


def process_scan_output(results: Dict) -> Dict:
    """
    Process and normalize semgrep scan results.

    Args:
        results: Raw semgrep JSON output

    Returns:
        Processed results with normalized findings and stats
    """
    findings = results.get("results", [])
    paths = results.get("paths", {})

    processed_findings = []
    # Match legacy scanner.py severity levels exactly
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

        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
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
                "owasp": finding.get("extra", {}).get("metadata", {}).get("owasp", []),
                "fix_recommendations": finding.get("extra", {})
                .get("metadata", {})
                .get("fix", ""),
                "references": finding.get("extra", {})
                .get("metadata", {})
                .get("references", []),
            }
        )

    scanned = paths.get("scanned", [])
    files_scanned = len(scanned) if scanned else 0

    scan_stats = {
        "total_files": files_scanned,
        "files_scanned": files_scanned,
        "files_with_findings": len(files_with_findings),
        "skipped_files": len(paths.get("skipped", [])),
        "partially_scanned": 0,
    }

    return {
        "findings": processed_findings,
        "stats": {
            "total_findings": len(processed_findings),
            "severity_counts": severity_counts,
            "category_counts": dict(category_counts),
            "scan_stats": scan_stats,
        },
    }


def create_empty_result(error: Optional[str] = None) -> Dict:
    """Create empty result structure with optional error information."""
    return {
        "findings": [],
        "stats": {
            "total_findings": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "ERROR": 0,
                "WARNING": 0,
                "INFO": 0,
            },
            "category_counts": {},
            "scan_stats": {
                "total_files": 0,
                "files_scanned": 0,
                "files_with_findings": 0,
                "skipped_files": 0,
                "partially_scanned": 0,
            },
        },
        "errors": [error] if error else [],
    }


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """
    Remove duplicate findings from a list.

    Args:
        findings: List of finding dictionaries

    Returns:
        Deduplicated list of findings
    """
    seen = set()
    deduplicated = []

    for finding in findings:
        signature = (
            finding.get("file", ""),
            finding.get("line_start", 0),
            finding.get("line_end", 0),
            finding.get("category", ""),
            finding.get("severity", ""),
            finding.get("code_snippet", ""),
        )

        if signature not in seen:
            seen.add(signature)
            deduplicated.append(finding)

    return deduplicated


def read_file_content_from_disk(
    file_path: str,
    repo_dir: Optional[Path] = None,
) -> Optional[str]:
    """
    Read file content from local disk (cloned repository).

    Since the repository is already cloned to a temp directory,
    we can read files directly from disk instead of making API calls.

    Args:
        file_path: Path to the file (can be absolute or relative)
        repo_dir: Optional base directory of the cloned repo

    Returns:
        Optional[str]: File content if successful, None otherwise
    """
    try:
        # If file_path is already absolute, use it directly
        target_path = Path(file_path)

        # If file_path is relative and repo_dir is provided, combine them
        if not target_path.is_absolute() and repo_dir:
            target_path = repo_dir / file_path

        # Check if file exists
        if not target_path.exists():
            logger.warning(f"File not found on disk: {target_path}")
            return None

        # Check if it's a file (not a directory)
        if not target_path.is_file():
            logger.warning(f"Path is not a file: {target_path}")
            return None

        # Read file content
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
            logger.info(f"Successfully read file from disk: {target_path}")
            return content
        except UnicodeDecodeError:
            # Try with latin-1 encoding as fallback
            try:
                with open(target_path, "r", encoding="latin-1") as f:
                    content = f.read()
                logger.info(f"Read file with latin-1 encoding: {target_path}")
                return content
            except Exception as e:
                logger.warning(f"Failed to read file with alternative encoding: {e}")
                return None
    except Exception as e:
        logger.error(f"Error reading file from disk: {str(e)}")
        return None


async def process_findings_with_rag(
    session: aiohttp.ClientSession,
    findings: List[Dict],
    user_id: str,
    repo_identifier: str,
    repo_dir: Optional[Path] = None,
    installation_token: Optional[str] = None,
    batch_size: int = 5,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Process findings with RAG API.

    Files are read from the local cloned repository (repo_dir) instead of
    making API calls. This works for all repository types since the repo
    has already been cloned to a temp directory.

    Args:
        session: aiohttp client session
        findings: List of findings to process
        user_id: User identifier
        repo_identifier: Repository identifier (e.g., "org/repo" or "org/project/repo")
        repo_dir: Path to the cloned repository directory (for reading files from disk)
        installation_token: Optional token (kept for backwards compatibility, not used)
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

            # Prepare batch payload - read files from local disk
            for file_path in batch_files:
                logger.info(f"Reading content for file: {file_path}")
                # Read from disk since repo is already cloned
                file_content = read_file_content_from_disk(file_path, repo_dir)

                if file_content:
                    content_size = len(file_content.encode("utf-8"))
                    total_size += content_size
                    batch_size_bytes += content_size

                    logger.info(f"File {file_path} size: {content_size/1024:.2f} KB")

                    # Extract filename from path for payload
                    filename = Path(file_path).name if file_path else file_path

                    batch_payload.append(
                        {
                            "user_id": user_id,
                            "file": file_content,
                            "reponame": repo_identifier,
                            "filename": filename,
                        }
                    )
                else:
                    logger.warning(f"Failed to read content for file: {file_path}")

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


async def send_findings_to_semgrep_rag(session, findings, user_id, repo_identifier):
    """
    Send semgrep findings to RAG API for additional analysis.

    All findings are sent at once after deleting previous data for the repo.

    Args:
        session: aiohttp client session
        findings: List of findings to send
        user_id: User identifier
        repo_identifier: Repository identifier (e.g., "org/repo" or "org/project/repo")

    Returns:
        Dict with RAG response or error
    """
    try:
        logger.info(f"Starting semgrep RAG processing for {len(findings)} findings")
        RAG_URL = os.getenv("RAG_URL")
        if not RAG_URL:
            logger.error("RAG_URL environment variable is not set")
            return {"error": "RAG_URL environment variable is not set"}

        # Use repo_identifier directly (already in org/repo format)
        repo_name = repo_identifier

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


def create_secure_client_session(timeout: int = 30) -> aiohttp.ClientSession:
    """Create aiohttp ClientSession with secure SSL configuration."""
    ssl_context = create_ssl_context()
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    return aiohttp.ClientSession(
        connector=conn, timeout=client_timeout, raise_for_status=True
    )


def extract_rerank_tuples(
    response: Any, selected_findings: Optional[List] = None
) -> List[Tuple[int, str]]:
    """
    Parse [(ID, severity), ...] tuples from response.

    Args:
        response: Response from reranking API (list or string)
        selected_findings: Optional list of original findings (unused, for compatibility)

    Returns:
        List of (ID, SEVERITY_UPPER) tuples in order
    """
    normalize = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "error": "ERROR",
    }

    try:
        if isinstance(response, str):
            response_str = response.strip()
            try:
                parsed = ast.literal_eval(response_str)
            except (ValueError, SyntaxError) as e:
                logger.warning(
                    f"Failed to parse rerank response as complete string: {str(e)}"
                )
                # Try to extract valid tuples from truncated string using regex
                tuple_pattern = r'\((\d+),\s*[\'"](\w+)[\'"]\)'
                matches = re.findall(tuple_pattern, response_str)
                if matches:
                    parsed = [(int(m[0]), m[1]) for m in matches]
                    logger.info(
                        f"Extracted {len(parsed)} tuples from truncated response using regex"
                    )
                else:
                    logger.error(f"Could not extract tuples from truncated response")
                    return []

            tuples = parsed if isinstance(parsed, list) else []
        elif isinstance(response, list):
            tuples = response
        else:
            logger.warning(f"Unexpected response type: {type(response)}")
            return []

        logger.info(
            f"OBSERVING RERANKING RESPONSE: Extracting rerank tuples: {len(tuples)} tuples found"
        )
        logger.info(f"OBSERVING RERANKING RESPONSE: Normalize: {normalize}")

        result = []
        for item in tuples:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                i, s = item
                if isinstance(i, (int, float, str)) and isinstance(s, str):
                    try:
                        result.append(
                            (int(i), normalize.get(str(s).lower(), str(s).upper()))
                        )
                    except (ValueError, TypeError) as e:
                        logger.warning(
                            f"Skipping invalid tuple item: {item}, error: {e}"
                        )
                        continue

        logger.info(f"Extracted {len(result)} rerank tuples")
        return result
    except Exception as e:
        logger.error(f"Error extracting rerank tuples: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return []


async def rerank_findings(
    findings: List[Dict],
    repo_identifier: str,
    user_id: str,
    scan_id: Optional[int] = None,
    scan_start: Optional[datetime] = None,
    rag_processed: bool = False,
    rag_responses: Optional[List[Dict]] = None,
    scanned_commit_sha: Optional[str] = None,
) -> Tuple[List[Dict], Dict]:
    """
    Send findings to reranking API to get prioritized severity ordering.

    Args:
        findings: List of findings to rerank
        repo_identifier: Repository identifier string
        user_id: User ID
        scan_id: Optional scan/analysis ID
        scan_start: Scan start time for metadata
        rag_processed: Whether RAG was used
        rag_responses: List of RAG responses to include in reranking
        scanned_commit_sha: Current commit SHA

    Returns:
        Tuple of (reranked_findings, rerank_data_dict)
    """
    if rag_responses is None:
        rag_responses = []

    rag_responses_count = len(rag_responses)

    # Build default rerank structure
    default_rerank = {
        "findings": findings.copy() if findings else [],
        "stats": {},
        "metadata": {
            "repository_url": repo_identifier,
            "user_id": user_id,
            "scan_start": scan_start.isoformat() if scan_start else None,
            "scan_end": datetime.now().isoformat(),
            "scan_duration_seconds": (
                (datetime.now() - scan_start).total_seconds() if scan_start else 0
            ),
            "rag_processed": rag_processed,
            "rag_responses_count": rag_responses_count,
            "scanned_commit_sha": scanned_commit_sha,
        },
    }

    if not findings:
        return findings, default_rerank

    RAG_URL = os.getenv("RAG_URL")
    if not RAG_URL:
        logger.warning("RAG_URL not configured, skipping reranking")
        return findings, default_rerank

    AI_RERANK_URL = f"{RAG_URL}/vulnerability_reranker_labelled"

    rerank_data = {
        "findings": [
            {
                "ID": idx + 1,
                "file": finding.get("file", ""),
                "code_snippet": finding.get("code_snippet", ""),
                "message": finding.get("message", ""),
                "severity": finding.get("severity", "INFO"),
            }
            for idx, finding in enumerate(findings)
        ],
        "metadata": {
            "repository": repo_identifier,
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_id": scan_id,
            "rag_processed": rag_processed,
            "rag_responses": rag_responses,
        },
    }

    try:
        async with create_secure_client_session() as session:
            async with session.post(AI_RERANK_URL, json=rerank_data) as response:
                if response.status == 200:
                    rerank_response = await response.json()
                    logger.info(
                        f"OBSERVING RERANKING RESPONSE: Rerank response: {rerank_response}"
                    )
                    tuples = extract_rerank_tuples(
                        rerank_response.get("llm_response", ""), findings
                    )
                    logger.info(f"OBSERVING RERANKING RESPONSE: Tuples: {tuples}")

                    if tuples:
                        findings_by_id = {idx + 1: f for idx, f in enumerate(findings)}
                        reordered = []
                        for t_id, sev in tuples:
                            f = findings_by_id.get(t_id)
                            if f:
                                out = f.copy()
                                out["severity"] = sev
                                reordered.append(out)

                        # Update severity counts - match legacy scanner.py exactly
                        severity_counts = {
                            "CRITICAL": len(
                                [f for f in reordered if f["severity"] == "CRITICAL"]
                            ),
                            "HIGH": len(
                                [f for f in reordered if f["severity"] == "HIGH"]
                            ),
                            "MEDIUM": len(
                                [f for f in reordered if f["severity"] == "MEDIUM"]
                            ),
                            "LOW": len(
                                [f for f in reordered if f["severity"] == "LOW"]
                            ),
                        }

                        # Build full rerank structure matching original scanner.py
                        rerank_data = {
                            "findings": reordered,
                            "stats": {"severity_counts": severity_counts},
                            "metadata": {
                                "repository_url": repo_identifier,
                                "user_id": user_id,
                                "scan_start": (
                                    scan_start.isoformat() if scan_start else None
                                ),
                                "scan_end": datetime.now().isoformat(),
                                "scan_duration_seconds": (
                                    (datetime.now() - scan_start).total_seconds()
                                    if scan_start
                                    else 0
                                ),
                                "rag_processed": rag_processed,
                                "rag_responses_count": rag_responses_count,
                                "scanned_commit_sha": scanned_commit_sha,
                            },
                        }

                        logger.info(
                            f"Reranking successful: {len(reordered)} findings reordered"
                        )
                        return reordered, rerank_data
                    else:
                        logger.warning(
                            "Rerank tuple output invalid/empty, using original order"
                        )
                else:
                    error_text = await response.text()
                    logger.error(
                        f"Reranking API error ({response.status}): {error_text[:200]}"
                    )

    except Exception as e:
        logger.error(f"Reranking request failed: {str(e)}")
        logger.error(f"Traceback: {traceback.format_exc()}")

    return findings, default_rerank


async def run_semgrep_scan(
    target_dir: Path,
    scan_config: Dict,
    config: ScanConfig,
    include_files: Optional[List[str]] = None,
) -> Dict:
    """
    Execute a single semgrep scan with the given configuration.

    Args:
        target_dir: Path to the repository directory
        scan_config: Scan configuration dictionary with 'name' and 'config' keys
        config: ScanConfig instance with timeout settings
        include_files: Optional list of specific files to scan (for incremental scans)

    Returns:
        Processed scan results dictionary
    """
    scan_name = scan_config["name"]
    semgrepignore_path = target_dir / ".semgrepignore"

    try:
        # Create .semgrepignore file
        with open(semgrepignore_path, "w") as f:
            for pattern in config.exclude_patterns:
                f.write(f"{pattern}\n")

        timeout = config.timeout_map.get(scan_name, config.default_timeout)
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

        # Add specific files or full directory
        if include_files:
            cmd += [str(target_dir / f) for f in include_files]
        else:
            cmd.append(str(target_dir))

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
            error_msg = f"Scan {scan_name} timed out after {timeout}s"
            logger.error(error_msg)
            return create_empty_result(error=error_msg)

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
            return create_empty_result(error=f"No output from {scan_name}")

        try:
            results = json.loads(output)
            processed_results = process_scan_output(results)
            processed_results["scan_source"] = scan_name
            processed_results["memory_usage"] = {
                "before": memory_before,
                "after": memory_after,
                "difference": memory_diff,
            }
            logger.info(f"Completed {scan_name} scan")
            return processed_results

        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse {scan_name} output: {str(e)}"
            logger.error(error_msg)
            return create_empty_result(error=error_msg)

    except Exception as e:
        error_msg = f"Error in {scan_name} scan: {str(e)}"
        logger.error(error_msg)
        return create_empty_result(error=error_msg)

    finally:
        if semgrepignore_path.exists():
            semgrepignore_path.unlink()


async def scan_repository(
    repo_dir: Path,
    detected_language: Optional[str] = None,
    include_files: Optional[List[str]] = None,
    previous_findings: Optional[List[Dict]] = None,
    config: Optional[ScanConfig] = None,
    progress_callback: Optional[callable] = None,
    repo_identifier: Optional[str] = None,
    user_id: Optional[str] = None,
    scan_id: Optional[int] = None,
    installation_token: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Scan a cloned repository for security vulnerabilities.

    This is the main entry point for scanning. It works with any repository
    type since scanning happens on the already-cloned local directory.

    Args:
        repo_dir: Path to the cloned repository directory
        detected_language: Primary programming language detected in the repository
        include_files: Optional list of specific files to scan (for incremental scans).
                      If None, scans all files.
        previous_findings: Optional list of findings from previous scan.
                          Used for incremental scan merging.
        config: Optional ScanConfig instance. Uses default if not provided.
        progress_callback: Optional async callback function for progress updates.
                          Signature: async def callback(stage: str, progress: int)
        repo_identifier: Repository identifier for reranking (e.g., "org/repo")
        user_id: User ID for reranking
        scan_id: Scan/analysis ID for reranking

    Returns:
        Dict with keys:
            - success: bool indicating if scan completed successfully
            - findings: List of finding dictionaries
            - stats: Statistics about the scan
            - language: Detected programming language
            - errors: List of any errors encountered
            - metadata: Additional scan metadata

    Example:
        from helpers.scanner import scan_repository
        from helpers.cloners import clone_and_get_scan_info

        # Clone the repo first
        clone_result = await clone_and_get_scan_info(
            repo_type="github",
            org_name="myorg",
            repo_name="myrepo",
            installation_id=12345,
        )

        if clone_result["success"]:
            # Scan the cloned repo
            scan_result = await scan_repository(
                repo_dir=clone_result["destination"],
                detected_language=clone_result["detected_language"],
                include_files=clone_result.get("changed_files"),  # For incremental
            )

            if scan_result["success"]:
                print(f"Found {len(scan_result['findings'])} issues")
    """
    if config is None:
        config = ScanConfig()

    start_time = datetime.now()
    scan_durations = {}

    try:
        if progress_callback:
            await progress_callback("initializing", 5)

        logger.info(f"Starting repository scan at {repo_dir}")
        logger.info(f"Detected language: {detected_language}")
        logger.info(f"Incremental scan: {bool(include_files)}")

        # Get language-specific scan configs
        selected_configs = get_language_specific_configs(detected_language, config)
        total_configs = len(selected_configs)

        all_findings = []
        merged_findings = []
        total_files_scanned = 0
        total_files_skipped = 0
        # Match legacy scanner.py severity levels exactly
        severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        category_counts = defaultdict(int)
        seen_findings = set()
        errors = []

        # Run scans sequentially
        for i, scan_config in enumerate(selected_configs):
            try:
                if progress_callback:
                    progress = int(10 + (i / total_configs) * 70)  # 10-80% range
                    await progress_callback("scanning", progress)

                logger.info(
                    f"Running scan {i + 1}/{total_configs}: {scan_config['name']} "
                    f"({scan_config['rules_count']} rules)"
                )

                scan_start = datetime.now()
                result = await run_semgrep_scan(
                    target_dir=repo_dir,
                    scan_config=scan_config,
                    config=config,
                    include_files=include_files,
                )
                scan_durations[scan_config["name"]] = (
                    datetime.now() - scan_start
                ).total_seconds()

                if result.get("errors"):
                    errors.extend(result["errors"])
                    continue

                findings = result.get("findings", [])
                stats = result.get("stats", {})

                # Update file counts
                scan_stats = stats.get("scan_stats", {})
                current_files_scanned = scan_stats.get("files_scanned", 0)
                if current_files_scanned > 0:
                    total_files_scanned = max(
                        total_files_scanned, current_files_scanned
                    )
                elif include_files:
                    total_files_scanned = max(total_files_scanned, len(include_files))

                total_files_skipped += scan_stats.get("skipped_files", 0)

                # Deduplicate and merge findings
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
                        all_findings.append(finding)

                        severity = finding.get("severity", "INFO").upper()
                        category = finding.get("category", "unknown")
                        if severity in severity_counts:
                            severity_counts[severity] += 1
                        else:
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

        if progress_callback:
            await progress_callback("processing", 85)

        # Merge with previous findings for incremental scans
        merged_findings = all_findings
        if include_files and previous_findings:
            # Keep findings from unchanged files
            changed_set = {Path(f).as_posix() for f in include_files}
            unchanged = [
                f
                for f in previous_findings
                if not any(
                    Path(f.get("file", "")).as_posix().endswith(nc)
                    for nc in changed_set
                )
            ]
            merged_findings = unchanged + all_findings
            logger.info(
                f"Merged incremental: {len(unchanged)} old findings kept, "
                f"{len(all_findings)} new findings"
            )

        # Final deduplication
        merged_findings = deduplicate_findings(merged_findings)

        # RAG processing - process findings with RAG API before reranking
        rag_responses = []
        rag_processed = False

        if merged_findings and repo_identifier and user_id:
            if progress_callback:
                await progress_callback("analyzing_vulnerabilities", 85)

            logger.info("Starting RAG processing for findings")
            try:
                async with create_secure_client_session(timeout=60) as session:
                    # Send findings to semgrep RAG first (like legacy scanner)
                    semgrep_rag_response = await send_findings_to_semgrep_rag(
                        session=session,
                        findings=merged_findings,
                        user_id=user_id,
                        repo_identifier=repo_identifier,
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

                    if progress_callback:
                        await progress_callback("analyzing_files", 88)

                    # Process findings with file content RAG API
                    rag_responses, _ = await process_findings_with_rag(
                        session=session,
                        findings=merged_findings,
                        user_id=user_id,
                        repo_identifier=repo_identifier,
                        repo_dir=repo_dir,
                        batch_size=10,
                    )

                    if rag_responses:
                        rag_processed = True
                        logger.info(
                            f"RAG processing completed: {len(rag_responses)} responses"
                        )
            except Exception as e:
                logger.error(f"RAG processing failed: {str(e)}")
                logger.error(f"Traceback: {traceback.format_exc()}")

        # Rerank findings if we have any
        if progress_callback:
            await progress_callback("reranking", 90)

        # Initialize rerank_data with default structure
        rerank_data = {
            "findings": merged_findings.copy() if merged_findings else [],
            "stats": {"severity_counts": dict(severity_counts)},
            "metadata": {
                "repository_url": repo_identifier,
                "user_id": user_id,
                "scan_start": start_time.isoformat(),
                "scan_end": datetime.now().isoformat(),
                "scan_duration_seconds": (datetime.now() - start_time).total_seconds(),
                "rag_processed": rag_processed,
                "rag_responses_count": len(rag_responses),
                "scanned_commit_sha": None,
            },
        }

        if merged_findings and repo_identifier:
            reranked_findings, rerank_data = await rerank_findings(
                findings=merged_findings,
                repo_identifier=repo_identifier,
                user_id=user_id or "",
                scan_id=scan_id,
                scan_start=start_time,
                rag_processed=rag_processed,
                rag_responses=rag_responses,
                scanned_commit_sha=None,
            )
            if reranked_findings:
                merged_findings = reranked_findings
                if rerank_data.get("stats", {}).get("severity_counts"):
                    severity_counts = rerank_data["stats"]["severity_counts"]
                logger.info(f"Reranking applied to {len(merged_findings)} findings")

        if progress_callback:
            await progress_callback("finalizing", 95)

        end_time = datetime.now()
        duration_seconds = (end_time - start_time).total_seconds()

        logger.info(f"Scan completed in {duration_seconds:.2f}s")
        logger.info(f"Found {len(merged_findings)} total findings")
        logger.info(f"Severity distribution: {dict(severity_counts)}")

        if progress_callback:
            await progress_callback("completed", 100)

        return {
            "success": True,
            "findings": merged_findings,
            "stats": {
                "total_findings": len(merged_findings),
                "severity_counts": severity_counts,
                "category_counts": dict(category_counts),
                "scan_stats": {
                    "total_files": total_files_scanned,
                    "files_scanned": total_files_scanned,
                    "files_with_findings": len(
                        set(f.get("file", "") for f in merged_findings)
                    ),
                    "skipped_files": total_files_skipped,
                    "partially_scanned": 0,
                },
                "memory_usage_mb": psutil.Process().memory_info().rss / (1024 * 1024),
                "scan_durations": scan_durations,
            },
            "language": detected_language,
            "errors": errors if errors else None,
            "metadata": {
                "repository_url": repo_identifier,
                "user_id": user_id,
                "scan_start": start_time.isoformat(),
                "scan_end": end_time.isoformat(),
                "scan_duration_seconds": duration_seconds,
                "incremental": bool(include_files),
                "configs_run": [c["name"] for c in selected_configs],
                "rag_processed": rag_processed,
                "rag_responses_count": len(rag_responses),
                "scanned_commit_sha": None,
            },
            "rerank": rerank_data,
        }

    except Exception as e:
        logger.error(f"Critical error in scan: {str(e)}")
        if progress_callback:
            await progress_callback("error", 0)
        return {
            "success": False,
            "findings": [],
            "stats": create_empty_result()["stats"],
            "language": detected_language,
            "errors": [str(e)],
            "metadata": {
                "repository_url": repo_identifier,
                "user_id": user_id,
                "scan_start": start_time.isoformat(),
                "scan_end": datetime.now().isoformat(),
                "scan_duration_seconds": (datetime.now() - start_time).total_seconds(),
                "error": str(e),
                "rag_processed": False,
                "rag_responses_count": 0,
                "scanned_commit_sha": None,
            },
            "rerank": None,
        }

    # Note: Repository cleanup is handled by the caller (v2_api.py)
    # to ensure cleanup happens after all processing including skip scenarios
