import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import aiohttp
import git
import ssl
import certifi
import traceback
import fnmatch
import base64
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from models import AnalysisResult
import time
import urllib.parse
from progress_tracking import update_scan_progress
from progress_utils import animate_progress_to_target
from typing import List, Dict, Tuple, Optional
from urllib.parse import quote
import sqlalchemy
import ast


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


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


async def get_full_file_content(
    session: aiohttp.ClientSession,
    repo_url: str,
    file_path: str,
    token: str,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Optional[str]:
    """
    Fetch full file content from GitHub

    Args:
        session: aiohttp client session
        repo_url: GitHub repository URL
        file_path: Path to the file
        token: GitHub authentication token
        max_retries: Maximum number of retry attempts
        base_delay: Base delay between retries (will be exponentially increased)

    Returns:
        Optional[str]: File content if successful, None otherwise
    """
    try:
        logger.info(f"Attempting to fetch file content for: {file_path}")

        # Extract actual file path using regex to remove temp directory prefix
        # Primary pattern for Linux/Unix: /tmp/scanner_*/repo_*/
        temp_dir_pattern_linux = r"^/tmp/scanner_[^/]+/repo_[^/]+/"
        actual_path = re.sub(temp_dir_pattern_linux, "", file_path)

        # Fallback pattern for macOS: /var/folders/.../T/scanner_*/repo_*/
        if actual_path == file_path:
            temp_dir_pattern_macos = (
                r"^/var/folders/[^/]+/[^/]+/T/scanner_[^/]+/repo_[^/]+/"
            )
            actual_path = re.sub(temp_dir_pattern_macos, "", file_path)

        # Add debug logging to see if the pattern is working
        if actual_path == file_path:
            logger.warning(
                f"Path transformation did not change the path. Neither Linux nor macOS temp dir patterns matched: {file_path}"
            )
            logger.warning(f"Linux pattern: {temp_dir_pattern_linux}")
            logger.warning(f"macOS (fallback) pattern: {temp_dir_pattern_macos}")
        else:
            logger.info(f"Transformed path from {file_path} to {actual_path}")

        # Normalize repository URL
        repo_parts = repo_url.rstrip(".git").split("github.com/")[-1].split("/")
        if len(repo_parts) != 2:
            raise ValueError(f"Invalid repository URL format: {repo_url}")

        owner, repo = repo_parts
        logger.info(f"Repository owner/name: {owner}/{repo}")

        # Handle potential URL-unsafe characters in the file path
        safe_path = quote(actual_path, safe="")
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{safe_path}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "SecurityScanner",
        }

        logger.info(f"GitHub API URL: {api_url}")

        retry_count = 0
        last_error = None

        while retry_count < max_retries:
            try:
                async with session.get(api_url, headers=headers) as response:
                    status = response.status
                    logger.info(f"GitHub API Response Status: {status}")

                    if status == 200:
                        data = await response.json()
                        if "content" in data:
                            content = base64.b64decode(data["content"]).decode("utf-8")
                            logger.info(
                                f"Successfully fetched content for {actual_path}"
                            )
                            return content
                        else:
                            logger.warning(
                                f"No content field in GitHub response for {actual_path}"
                            )
                            return None

                    elif status == 404:
                        logger.warning(
                            f"File not found: {actual_path} (Original path: {file_path})"
                        )
                        # Check if this might be a case of incorrect path transformation
                        if "/" in actual_path:
                            # Try fetching just the filename without directory structure as a fallback
                            filename = actual_path.split("/")[-1]
                            logger.info(
                                f"Attempting fallback with just filename: {filename}"
                            )
                            fallback_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{filename}"
                            try:
                                async with session.get(
                                    fallback_url, headers=headers
                                ) as fallback_response:
                                    if fallback_response.status == 200:
                                        logger.info(
                                            f"Fallback successful: file exists at root level with name {filename}"
                                        )
                                    else:
                                        logger.info(
                                            f"Fallback also failed with status {fallback_response.status}"
                                        )
                            except Exception as fallback_err:
                                logger.info(
                                    f"Fallback request failed: {str(fallback_err)}"
                                )
                        return None

                    elif status == 403:
                        error_data = await response.json()
                        if (
                            "message" in error_data
                            and "rate limit" in error_data["message"].lower()
                        ):
                            retry_delay = base_delay * (2**retry_count)
                            logger.warning(
                                f"Rate limited. Waiting {retry_delay}s before retry {retry_count + 1}/{max_retries}"
                            )
                            await asyncio.sleep(retry_delay)
                            retry_count += 1
                            continue
                        else:
                            logger.error(
                                f"Access denied: {error_data.get('message', 'Unknown error')}"
                            )
                            return None

                    elif status in {502, 503, 504}:
                        retry_delay = base_delay * (2**retry_count)
                        logger.warning(
                            f"Gateway error {status}. Retrying in {retry_delay}s ({retry_count + 1}/{max_retries})"
                        )
                        await asyncio.sleep(retry_delay)
                        retry_count += 1
                        continue

                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Unexpected GitHub API error ({status}): {error_text}"
                        )
                        return None

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

        return None

    except Exception as e:
        logger.error(f"Unexpected error fetching file content: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return None


async def process_findings_with_rag(
    session: aiohttp.ClientSession,
    findings: List[Dict],
    user_id: str,
    repo_url: str,
    installation_token: str,
    batch_size: int = 5,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Process findings with RAG API.

    Args:
        session: aiohttp client session
        findings: List of findings to process
        user_id: User identifier
        repo_url: GitHub repository URL
        installation_token: GitHub installation token
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
                    session, repo_url, file_path, installation_token
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
                            "reponame": repo_url.split("github.com/")[-1].rstrip(
                                ".git"
                            ),
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


async def send_findings_to_semgrep_rag(session, findings, user_id, repo_url):
    """Send semgrep findings to RAG API for additional analysis - all at once after deleting previous data."""
    try:
        logger.info(f"Starting semgrep RAG processing for {len(findings)} findings")
        RAG_URL = os.getenv("RAG_URL")
        if not RAG_URL:
            logger.error("RAG_URL environment variable is not set")
            return {"error": "RAG_URL environment variable is not set"}

        repo_name = repo_url.split("github.com/")[-1].rstrip(".git")

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


@dataclass
class ScanConfig:
    """Configuration for repository scanning with improved timeout handling"""

    # File size limits
    max_file_size_mb: int = 50
    max_total_size_mb: int = 600
    max_memory_mb: int = 3000
    chunk_size_mb: int = 60
    max_files_per_chunk: int = 100

    # Timeout configuration based on ruleset size
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
    default_timeout: int = 600  # 10 minutes default
    chunk_timeout: int = 120
    file_timeout_seconds: int = 20
    max_retries: int = 2
    concurrent_processes: int = 2

    # File exclusion patterns
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

    # Scan configurations with rule counts - organized by type
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


class SecurityScanner:
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
        self._repo_url = None
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

    def set_scan_info(self, repo_url: str, user_id: str):
        self._repo_url = repo_url
        self._user_id = user_id

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

    async def _run_semgrep_scan(self, target_dir: Path, scan_config: Dict) -> Dict:
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
                str(target_dir),
            ]

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
        self, target_dir: Path, total_prev_files: int = 0, include_files: list = None
    ) -> Dict:
        """Run multiple semgrep scans based on detected language, limited to include_files if provided"""
        try:
            logger.info(f"Detected repository language: {self.detected_language}")

            # Store file list for incremental scans
            self._current_file_list = include_files

            # Get relevant configs based on language
            selected_configs = self.get_language_specific_configs(
                self.detected_language
            )

            # Add these lines for progress tracking
            repo_url = getattr(self, "_repo_url", "")
            user_id = getattr(self, "_user_id", "")
            repo_name = repo_url.split("github.com/")[-1].rstrip(".git")
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
                    # If using include_files, add paths instead of full repo scan
                    if include_files:
                        # file paths are relative to repo dir
                        cmd += [str(Path(target_dir) / relf) for relf in include_files]
                    else:
                        cmd.append(str(target_dir))
                    memory_before = psutil.Process().memory_info().rss / (1024 * 1024)
                    logger.info(
                        f"Memory usage before {scan_config['name']}: {memory_before:.2f}MB"
                    )
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=str(target_dir),
                    )
                    try:
                        stdout, stderr = await asyncio.wait_for(
                            process.communicate(),
                            timeout=self.config.timeout_map.get(
                                scan_config["name"], self.config.default_timeout
                            ),
                        )
                    except asyncio.TimeoutError:
                        process.kill()
                        error_msg = f"Scan {scan_config['name']} timed out"
                        logger.error(error_msg)
                        all_results.append(self._create_empty_result(error=error_msg))
                        continue
                    memory_after = psutil.Process().memory_info().rss / (1024 * 1024)
                    memory_diff = memory_after - memory_before
                    stderr_output = stderr.decode() if stderr else ""
                    if stderr_output:
                        logger.warning(
                            f"Semgrep stderr ({scan_config['name']}): {stderr_output}"
                        )
                    output = stdout.decode() if stdout else ""
                    if not output.strip():
                        all_results.append(
                            self._create_empty_result(
                                error=f"No output from {scan_config['name']}"
                            )
                        )
                        continue
                    try:
                        results = json.loads(output)
                        processed_results = self._process_scan_results(results)
                        scan_duration = processed_results.get("scan_duration", 0)
                        processed_results["scan_source"] = scan_config["name"]
                        processed_results["scan_duration"] = scan_duration
                        processed_results["memory_usage"] = {
                            "before": memory_before,
                            "after": memory_after,
                            "difference": memory_diff,
                        }
                        all_results.append(processed_results)
                        findings = processed_results.get("findings", [])
                        stats = processed_results.get("stats", {})
                        current_files_scanned = stats.get("scan_stats", {}).get(
                            "files_scanned", 0
                        )

                        if include_files and current_files_scanned == 0:
                            total_files_scanned = max(total_prev_files, len(include_files))
                            logger.critical(
                                f"*** URGENT: Using file_list for incremental scan count: {total_files_scanned} files"
                            )
                        elif current_files_scanned > 0:
                            total_files_scanned = max(total_prev_files, current_files_scanned)
                        else:
                            total_files_scanned = max(
                                total_files_scanned, current_files_scanned, total_prev_files
                            )
                        total_files_skipped += stats.get("scan_stats", {}).get(
                            "skipped_files", 0
                        )
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
                                if severity in severity_counts:
                                    severity_counts[severity] += 1
                                else:
                                    severity_counts["INFO"] += 1
                                category_counts[category] += 1
                    except Exception as e:
                        error_msg = (
                            f"Failed to parse {scan_config['name']} output: {str(e)}"
                        )
                        logger.error(error_msg)
                        all_results.append(self._create_empty_result(error=error_msg))
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
            if self._user_id and self._repo_url:
                repo_name = self._repo_url.split("github.com/")[-1].rstrip(".git")
                update_scan_progress(self._user_id, repo_name, "error", 0)

            return self._create_empty_result(error=str(e))

    async def _check_repository_size(self, repo_url: str, token: str) -> Dict:
        """Check repository size and metadata using GitHub API"""
        if not self._session:
            raise RuntimeError("Scanner session not initialized")

        try:
            if not token:
                raise ValueError("GitHub token is required")

            # Parse repository URL
            if "github.com/" not in repo_url:
                raise ValueError(f"Invalid GitHub URL: {repo_url}")

            path_part = repo_url.split("github.com/")[-1].replace(".git", "")
            if "/" not in path_part:
                raise ValueError(f"Invalid repository path: {path_part}")

            owner, repo = path_part.split("/")
            logger.info(f"Checking repository: {owner}/{repo}")

            # Query GitHub API
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "SecurityScanner",
            }

            async with self._session.get(api_url, headers=headers) as response:
                if response.status != 200:
                    error_text = await response.text()
                    raise ValueError(
                        f"GitHub API error ({response.status}): {error_text}"
                    )

                data = await response.json()
                size_mb = data.get("size", 0) / 1024
                self.detected_language = data.get("language")  # Store detected language

                logger.info(f"Repository size: {size_mb:.2f}MB")
                logger.info(f"Detected language: {self.detected_language}")
                logger.info(f"Default branch: {data.get('default_branch', 'main')}")

                return {
                    "size_mb": size_mb,
                    "is_compatible": size_mb <= self.config.max_total_size_mb,
                    "language": self.detected_language,
                    "default_branch": data.get("default_branch", "main"),
                    "visibility": data.get("visibility", "unknown"),
                    "fork_count": data.get("forks_count", 0),
                    "star_count": data.get("stargazers_count", 0),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                }

        except Exception as e:
            logger.error(f"Repository size check failed: {str(e)}")
            raise

    async def _clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with size validation, optimizations, and improved directory handling"""
        try:
            # Verify repository size
            size_info = await self._check_repository_size(repo_url, token)
            if not size_info["is_compatible"]:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

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

            auth_url = repo_url.replace("https://", f"https://x-access-token:{token}@")

            logger.info(f"Cloning repository to {self.repo_dir}")

            # Optimize clone operation
            # Use depth=2 to get the current commit and its parent for better diff support
            git_options = [
                "--depth=2",
                "--single-branch",
                "--no-tags",
                f'--branch={size_info["default_branch"]}',
            ]

            repo = git.Repo.clone_from(
                auth_url, self.repo_dir, multi_options=git_options
            )

            logger.info(f"Successfully cloned repository: {size_info['size_mb']:.2f}MB")
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

        scanned = paths.get("scanned", [])
        files_scanned = len(scanned) if scanned else 0

        # For incremental scans, if we don't have proper path information,
        # calculate from the findings and file_list if available
        if (
            files_scanned == 0
            and hasattr(self, "_current_file_list")
            and self._current_file_list
        ):
            files_scanned = len(self._current_file_list)
            logger.critical(
                f"*** URGENT: Using file_list count for incremental scan: {files_scanned} files"
            )
        elif files_scanned == 0:
            logger.critical(
                f"*** URGENT: files_scanned is 0, _current_file_list: {getattr(self, '_current_file_list', None)}"
            )

        scan_stats = {
            "total_files": stats.get("total", {}).get("files", 0),
            "files_scanned": files_scanned,
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
        repo_url: str,
        installation_token: str,
        user_id: str,
        total_prev_files: int,
        multi_scan: bool = True,
        files_to_scan: Optional[list] = None,
        previous_findings: Optional[list] = None,
        current_commit_sha: Optional[str] = None,
    ) -> Dict:
        """
        Main scan method. If files_to_scan is given, scan only those; supports incremental scan merge if previous_findings provided.
        """
        try:
            self.set_scan_info(repo_url, user_id)
            self._current_commit_sha = current_commit_sha
            self._current_file_list = files_to_scan
            repo_name = repo_url.split("github.com/")[-1].rstrip(".git")
            from progress_tracking import clear_scan_progress

            clear_scan_progress(user_id, repo_name)

            # Animate initializing stage: 0 → ~1.5% overall (0→50% of stage)
            await animate_progress_to_target(user_id, repo_name, "initializing", 50)

            RAG_URL = os.getenv("RAG_URL")
            if not RAG_URL:
                raise ValueError("RAG_URL not configured")
            AI_RERANK_URL = f"{RAG_URL}/vulnerability_reranker_labelled"
            size_info = await self._check_repository_size(repo_url, installation_token)

            # Animate cloning stage: ~1.5% → ~4.5% overall (0→50% of stage)
            await animate_progress_to_target(user_id, repo_name, "cloning", 50)

            await self._clone_repository(repo_url, installation_token)

            # Animate analyzing start: ~4.5% → ~13% overall (0→10% of stage)
            await animate_progress_to_target(user_id, repo_name, "analyzing", 10)
            if files_to_scan:
                logger.info(
                    f"Scanning incrementally (changed files only): {files_to_scan}"
                )
                scan_results = await self.run_multiple_semgrep_scans(
                    self.repo_dir, total_prev_files, include_files=files_to_scan
                )
            else:
                scan_results = (
                    await self.run_multiple_semgrep_scans(self.repo_dir)
                    if multi_scan
                    else await self._run_semgrep_scan(
                        self.repo_dir, self.config.core_configs[0]
                    )
                )
            update_scan_progress(user_id, repo_name, "processing", 0)
            all_findings = scan_results.get("findings", [])
            scan_stats = scan_results.get("stats", {})
            logger.info(f"OBSERVING SCAN RESULTS: Scan stats: {scan_stats}")
            logger.info(f"Found {len(all_findings)} findings in this scan iteration")
            merged_findings = all_findings
            if files_to_scan and previous_findings:
                changed_set = set(files_to_scan)
                # Merge: keep findings from unchanged files in previous_findings
                normalized_changed = {Path(f).as_posix() for f in changed_set}
                unchanged = [
                    f for f in previous_findings 
                    if not any(Path(f.get("file", "")).as_posix().endswith(nc) for nc in normalized_changed)
                ]
                merged_findings = unchanged + all_findings
                logger.info(
                    f"Merged incremental: {len(unchanged)} old findings kept, {len(all_findings)} new findings replaced"
                )
            rag_responses = []
            semgrep_rag_response = None

            # New: Send findings to semgrep RAG API
            update_scan_progress(user_id, repo_name, "analyzing_vulnerabilities", 30)
            if merged_findings:
                async with create_secure_client_session() as session:
                    semgrep_rag_response = await send_findings_to_semgrep_rag(
                        session=session,
                        findings=merged_findings,
                        user_id=user_id,
                        repo_url=repo_url,
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
            update_scan_progress(user_id, repo_name, "analyzing_files", 60)
            if len(merged_findings) > 0:
                logger.info(
                    f"Processing {len(merged_findings)} findings through file content RAG"
                )
                async with create_secure_client_session() as session:
                    rag_responses, merged_findings = await process_findings_with_rag(
                        session=session,
                        findings=merged_findings,
                        user_id=user_id,
                        repo_url=repo_url,
                        installation_token=installation_token,
                        batch_size=10,
                    )
                    logger.info(
                        f"Received {len(rag_responses)} file content RAG responses"
                    )
            else:
                logger.info("No findings to process through file content RAG")
            update_scan_progress(user_id, repo_name, "reranking", 80)
            rerank_data = {
                "findings": [
                    {
                        "ID": idx + 1,
                        "file": finding["file"],
                        "code_snippet": finding["code_snippet"],
                        "message": finding["message"],
                        "severity": finding["severity"],
                    }
                    for idx, finding in enumerate(merged_findings)
                ],
                "metadata": {
                    "repository": repo_url.split("github.com/")[-1].rstrip(".git"),
                    "user_id": user_id,
                    "timestamp": datetime.utcnow().isoformat(),
                    "scan_id": self.analysis_id,
                    "rag_processed": bool(rag_responses),
                    "rag_responses": rag_responses,
                },
            }
            # Initialize reordered_findings as a dict structure to avoid 'list' object has no attribute 'get' error
            reordered_findings = {
                "findings": merged_findings.copy(),
                "stats": scan_stats,
                "metadata": {}
            }
            enriched_rerank_data = []  # Store enriched rerank data separately

            if len(merged_findings) > 0:
                logger.info(f"Sending {len(merged_findings)} findings for reranking")
                async with create_secure_client_session() as session:
                    try:
                        async with session.post(
                            AI_RERANK_URL, json=rerank_data
                        ) as response:
                            if response.status == 200:
                                rerank_response = await response.json()
                                logger.info(f"OBSERVING RERANKING RESPONSE: Rerank response: {rerank_response}")
                                tuples = extract_rerank_tuples(rerank_response.get("llm_response", ""), merged_findings)
                                if tuples:
                                    findings_by_id = {
                                        idx + 1: f
                                        for idx, f in enumerate(merged_findings)
                                    }
                                    reordered_findings_list = []
                                    for t_id, sev in tuples:
                                        f = findings_by_id.get(t_id)
                                        if f:
                                            out = f.copy()
                                            out["severity"] = sev
                                            reordered_findings_list.append(out)
                                    reordered_findings["findings"] = reordered_findings_list
                                    scan_stats["severity_counts"] = {
                                        "CRITICAL": len([f for f in reordered_findings_list if f["severity"] == "CRITICAL"]),
                                        "HIGH": len([f for f in reordered_findings_list if f["severity"] == "HIGH"]),
                                        "MEDIUM": len([f for f in reordered_findings_list if f["severity"] == "MEDIUM"]),
                                        "LOW": len([f for f in reordered_findings_list if f["severity"] == "LOW"]),
                                    }
                                    reordered_findings["stats"] = scan_stats
                                    # add metadata like in the results data
                                    reordered_findings["metadata"] = {
                                        "repository_url": repo_url,
                                        "user_id": user_id,
                                        "scan_start": self.scan_stats["start_time"].isoformat(),
                                        "scan_end": datetime.now().isoformat(),
                                        "scan_duration_seconds": (
                                            datetime.now() - self.scan_stats["start_time"]
                                        ).total_seconds(),
                                        "rag_processed": bool(rag_responses),
                                        "rag_responses_count": len(rag_responses),
                                        "scanned_commit_sha": getattr(self, "_current_commit_sha", None),
                                    }
                                    logger.info(f"Applied rerank tuple ordering/severity to findings. IDs: {[t_id for t_id, _ in tuples]}")
                                else:
                                    logger.warning("Rerank tuple output invalid/empty, using original order")
                                    # Ensure reordered_findings maintains dict structure with original findings
                                    reordered_findings["findings"] = merged_findings.copy()
                                    reordered_findings["stats"] = scan_stats
                    except Exception as e:
                        logger.error(f"Reranking request failed: {str(e)}")
                        logger.info("Falling back to original finding order")
                        # Ensure reordered_findings maintains dict structure with original findings
                        reordered_findings["findings"] = merged_findings.copy()
                        reordered_findings["stats"] = scan_stats
            else:
                logger.info("No findings to rerank")
            update_scan_progress(user_id, repo_name, "finalizing", 90)
            results_data = {
                "findings": reordered_findings.get("findings", []),
                "stats": reordered_findings.get("stats", {}),
                "metadata": {
                    "repository_url": repo_url,
                    "user_id": user_id,
                    "scan_start": self.scan_stats["start_time"].isoformat(),
                    "scan_end": datetime.now().isoformat(),
                    "scan_duration_seconds": (
                        datetime.now() - self.scan_stats["start_time"]
                    ).total_seconds(),
                    "rag_processed": bool(rag_responses),
                    "rag_responses_count": len(rag_responses),
                    "scanned_commit_sha": getattr(self, "_current_commit_sha", None),
                },
            }
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AnalysisResult).get(
                        self.analysis_id
                    )
                    if analysis:
                        analysis.results = results_data
                        analysis.rerank = reordered_findings
                        analysis.status = "completed"
                        analysis.completed_at = datetime.now()
                        self.db_session.commit()
                        logger.info(
                            f"Successfully stored in database - results: {len(merged_findings)}, rerank: {len(reordered_findings)}"
                        )
                except Exception as e:
                    self.db_session.rollback()
                    logger.error(f"Database update failed: {str(e)}")
            update_scan_progress(user_id, repo_name, "completed", 100)
            return {"success": True, "data": results_data}
        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            repo_name = (
                repo_url.split("github.com/")[-1].rstrip(".git")
                if repo_url
                else "unknown"
            )
            update_scan_progress(user_id, repo_name, "error", 0)
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AnalysisResult).get(
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


def get_current_commit_sha(repo_dir: Path) -> str:
    """Return the current commit SHA for the given repo directory."""
    import subprocess

    try:
        sha = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"])
        return sha.decode("utf-8").strip()
    except Exception as e:
        logger.error(f"Failed to get current commit SHA: {e}")
        return ""


def get_changed_files_between_commits(
    repo_dir: Path, old_sha: str, new_sha: str
) -> list:
    """Return a list of files changed between two commits in the repo."""
    import subprocess

    try:
        # checking if both commits exist
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", "-e", old_sha],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                f"Previous commit {old_sha} not found in repository - likely shallow clone or history rewritten"
            )

            # Checking if this is a shallow clone by looking at git log depth
            try:
                result = subprocess.run(
                    ["git", "-C", str(repo_dir), "rev-list", "--count", "HEAD"],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    commit_count = int(result.stdout.strip())
                    if commit_count == 1:
                        logger.info(
                            "Detected shallow clone (depth=1) - this is normal for incremental scanning"
                        )
                        # For shallow clones, we can't do proper diff, so return empty list
                        # The handler will detect this and scan all files as a fallback
                        return []
                    else:
                        logger.info(
                            f"Repository has {commit_count} commits, not a shallow clone"
                        )
            except Exception as e:
                logger.warning(f"Could not determine clone depth: {e}")

            # Fallback: compare against the merge base or HEAD~1
            logger.info("Attempting fallback: comparing against HEAD~1")
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo_dir),
                        "diff",
                        "--name-only",
                        "HEAD~1",
                        new_sha,
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    changed_files = [
                        f.strip() for f in result.stdout.split("\n") if f.strip()
                    ]
                    logger.info(
                        f"Fallback successful: found {len(changed_files)} changed files"
                    )
                    return changed_files
                else:
                    logger.warning("Fallback also failed, will scan all files")
                    return []
            except Exception as fallback_error:
                logger.warning(
                    f"Fallback failed: {fallback_error}, will scan all files"
                )
                return []

        result = subprocess.run(
            ["git", "-C", str(repo_dir), "cat-file", "-e", new_sha],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.error(f"Current commit {new_sha} not found in repository")
            return []

        # Get changed files
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", "--name-only", old_sha, new_sha],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            logger.error(
                f"Failed to get changed files between commits {old_sha}..{new_sha}: {result.stderr}"
            )
            # Try fallback approach
            logger.info("Attempting fallback: comparing against HEAD~1")
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo_dir),
                        "diff",
                        "--name-only",
                        "HEAD~1",
                        new_sha,
                    ],
                    capture_output=True,
                    text=True,
                )
                if result.returncode == 0:
                    changed_files = [
                        f.strip() for f in result.stdout.split("\n") if f.strip()
                    ]
                    logger.info(
                        f"Fallback successful: found {len(changed_files)} changed files"
                    )
                    return changed_files
                else:
                    logger.warning("Fallback also failed, will scan all files")
                    return []
            except Exception as fallback_error:
                logger.warning(
                    f"Fallback failed: {fallback_error}, will scan all files"
                )
                return []

        changed_files = [f.strip() for f in result.stdout.split("\n") if f.strip()]
        return changed_files
    except Exception as e:
        logger.error(f"Error getting changed files: {e}")
        return []


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


def extract_enriched_rerank_data(
    response_data: Union[Dict, List, str], original_findings: List[Dict] = None
) -> Optional[List[Dict]]:
    """
    Enhanced: Support for tuple outputs like [(2,'critical'),(11,'critical'),...] including stringified lists.
    Returns: List of dicts [{"ID": int, "Severity": str, ...}], ordered as given.
    """
    try:
        logger.info(f"Processing enriched reranking response: {json.dumps(response_data, indent=2)}")
        enriched_data = []

        # Try original logic (list of dicts, etc)
        if isinstance(response_data, dict) and "llm_response" in response_data:
            response = response_data["llm_response"]
        else:
            response = response_data

        # If it's the new tuple output (can be string or list)
        parsed = None
        if isinstance(response, str):
            response = response.strip()
            # Try parse as list of tuples
            try:
                parsed = ast.literal_eval(response)
            except Exception:
                try:
                    parsed = json.loads(response)
                except Exception:
                    parsed = None
        elif isinstance(response, list):
            parsed = response

        if parsed and isinstance(parsed, list) and all(isinstance(x, (list, tuple)) and len(x) == 2 for x in parsed):
            result = []
            for i, (id_val, sev_val) in enumerate(parsed):
                sev_map = {  
                    'critical': 'CRITICAL',
                    'high': 'HIGH',
                    'medium': 'MEDIUM',
                    'low': 'LOW',
                    'info': 'INFO',
                    'error': 'ERROR',
                }
                sev = str(sev_val).strip().upper()
                sev = sev_map.get(sev.lower(), sev.upper())
                result.append({"ID": int(id_val), "Severity": sev, "Rank": i + 1})
            return result
        
        # fallback to prior logic
        if isinstance(response, list):
            enriched_data = []
            for item in response:
                if isinstance(item, dict) and ("ID" in item or "id" in item):
                    enriched_data.append(item)
            if enriched_data:
                return enriched_data

        logger.warning("Could not parse rerank response as tuple or enriched dict list")
        return None
    except Exception as e:
        logger.error(f"Error extracting enriched data from LLM response: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return None


async def scan_repository_handler(
    repo_url: str,
    installation_token: str,
    user_id: str,
    multi_scan: bool = True,
    db_session: Optional[Session] = None,
    analysis_record: Optional[AnalysisResult] = None,
) -> Dict:
    """Handler function for web routes with enhanced input validation, now supports incremental scans"""
    logger.info(f"Starting scan request for repository: {repo_url}")

    if not all([repo_url, installation_token, user_id]):
        return {
            "success": False,
            "error": {
                "message": "Missing required parameters",
                "code": "INVALID_PARAMETERS",
            },
        }

    if not repo_url.startswith(("https://github.com/", "git@github.com:")):
        return {
            "success": False,
            "error": {
                "message": "Invalid repository URL format",
                "code": "INVALID_REPOSITORY_URL",
                "details": "Only GitHub repositories are supported",
            },
        }

    try:
        analysis = analysis_record
        repo_name = repo_url.split("github.com/")[-1].rstrip(".git")

        # Determine previous scan's commit SHA (for incremental scan)
        previous_sha = None
        previous_findings = []
        unchanged_findings = []
        unchanged_files_set = set()
        total_prev_files = 0
        if db_session:
            # Get latest completed analysis for this repo/user/workspace, with findings and commit sha
            urgent_log_msg = f"*** URGENT: Checking DB for previous analysis: repo={repo_name} workspace_id={(analysis.workspace_id if analysis else None)} user_id={user_id}"
            logger.critical(urgent_log_msg)
            prev_query = (
                db_session.query(AnalysisResult)
                .filter(
                    AnalysisResult.repository_name == repo_name,
                    AnalysisResult.workspace_id
                    == (analysis.workspace_id if analysis else None),
                )
                .order_by(sqlalchemy.desc(AnalysisResult.timestamp))
            )
            prev_result = prev_query.first()
            logger.critical(
                f"*** URGENT: DB previous analysis result found: {bool(prev_result)}, sha={[getattr(prev_result,'scanned_commit_sha',None)] if prev_result else None}"
            )
            if prev_result:
                total_prev_files = 0
                try:
                    stats = (prev_result.results or {}).get("stats", {})
                    scan_stats = stats.get("scan_stats", {})
                    total_prev_files = scan_stats.get("files_scanned", 0)
                    logger.critical(
                        f"*** URGENT: Previous analysis details - ID: {prev_result.id}, Status: {prev_result.status}, Timestamp: {prev_result.timestamp}, SHA: {getattr(prev_result, 'scanned_commit_sha', 'MISSING')}"
                    )
                    logger.critical(
                        f"*** URGENT: TOTAL SCANNED: {total_prev_files}"
                    )
                except Exception as stat_err:
                    logger.critical(f"*** URGENT: Failed extracting scan stats from previous analysis: {stat_err}")
            if prev_result and getattr(prev_result, "scanned_commit_sha", None):
                previous_sha = prev_result.scanned_commit_sha
                if prev_result.results and "findings" in prev_result.results:
                    previous_findings = prev_result.results["findings"]
            elif prev_result and prev_result.results:
                metadata = prev_result.results.get("metadata", {})
                if "scanned_commit_sha" in metadata:
                    previous_sha = metadata["scanned_commit_sha"]
                    logger.critical(
                        f"*** URGENT: Found commit SHA in metadata: {previous_sha}"
                    )
                if "findings" in prev_result.results:
                    previous_findings = prev_result.results["findings"]
        config = ScanConfig()
        async with SecurityScanner(
            config, db_session, analysis.id if analysis else None
        ) as scanner:
            try:
                size_info = await scanner._check_repository_size(
                    repo_url, installation_token
                )
                if not size_info["is_compatible"]:
                    if analysis:
                        analysis.status = "failed"
                        analysis.error = "Repository too large for analysis"
                        db_session.commit()
                    logger.critical(
                        f"*** URGENT: Skipping scan, repo too large: {size_info}"
                    )
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
                repo_dir = await scanner._clone_repository(repo_url, installation_token)
                from pathlib import Path

                new_sha = get_current_commit_sha(Path(repo_dir))
                logger.critical(
                    f"*** URGENT: File diff: Previous={previous_sha} | New={new_sha}"
                )
                files_to_scan = None
                skip_scan = False
                all_files_new = False
                changed_files = []
                if previous_sha and previous_sha != new_sha:
                    changed_files = get_changed_files_between_commits(
                        Path(repo_dir), previous_sha, new_sha
                    )
                    logger.critical(f"*** URGENT: Changed files list: {changed_files}")
                    if changed_files:
                        files_to_scan = changed_files
                        logger.critical(
                            f"*** URGENT: Will scan changed files only: {changed_files}"
                        )
                    else:

                        logger.critical(
                            f"*** URGENT: No changed files detected or git diff failed. Checking if this is due to history rewrite..."
                        )

                        import subprocess

                        try:
                            result = subprocess.run(
                                [
                                    "git",
                                    "-C",
                                    str(repo_dir),
                                    "cat-file",
                                    "-e",
                                    previous_sha,
                                ],
                                capture_output=True,
                                text=True,
                            )
                            if result.returncode != 0:
                                # Check if this is a shallow clone (depth=1)
                                try:
                                    depth_result = subprocess.run(
                                        [
                                            "git",
                                            "-C",
                                            str(repo_dir),
                                            "rev-list",
                                            "--count",
                                            "HEAD",
                                        ],
                                        capture_output=True,
                                        text=True,
                                    )
                                    if depth_result.returncode == 0:
                                        commit_count = int(depth_result.stdout.strip())
                                        if commit_count == 1:
                                            logger.critical(
                                                f"*** URGENT: Shallow clone detected (depth=1) - previous commit not available. Will scan all files as fallback."
                                            )
                                            files_to_scan = None
                                            all_files_new = True
                                            # Update the stored commit SHA to the current one
                                            if prev_result:
                                                prev_result.scanned_commit_sha = new_sha
                                                db_session.commit()
                                                logger.critical(
                                                    f"*** URGENT: Updated stored commit SHA to {new_sha} due to shallow clone"
                                                )
                                        else:
                                            logger.critical(
                                                f"*** URGENT: Previous commit {previous_sha} not found - likely history rewritten. Will scan all files as fallback."
                                            )
                                            files_to_scan = None
                                            all_files_new = True
                                            # Update the stored commit SHA to the current one since history was rewritten
                                            if prev_result:
                                                prev_result.scanned_commit_sha = new_sha
                                                db_session.commit()
                                                logger.critical(
                                                    f"*** URGENT: Updated stored commit SHA to {new_sha} due to history rewrite"
                                                )
                                    else:
                                        logger.critical(
                                            f"*** URGENT: Previous commit {previous_sha} not found - likely history rewritten. Will scan all files as fallback."
                                        )
                                        files_to_scan = None
                                        all_files_new = True
                                        # Update the stored commit SHA to the current one since history was rewritten
                                        if prev_result:
                                            prev_result.scanned_commit_sha = new_sha
                                            db_session.commit()
                                            logger.critical(
                                                f"*** URGENT: Updated stored commit SHA to {new_sha} due to history rewrite"
                                            )
                                except Exception as depth_error:
                                    logger.critical(
                                        f"*** URGENT: Error checking clone depth: {depth_error}. Will scan all files as fallback."
                                    )
                                    files_to_scan = None
                                    all_files_new = True
                                    if prev_result:
                                        prev_result.scanned_commit_sha = new_sha
                                        db_session.commit()
                                        logger.critical(
                                            f"*** URGENT: Updated stored commit SHA to {new_sha} due to verification error"
                                        )
                            else:
                                logger.critical(
                                    f"*** URGENT: No changed files detected, skipping scan and using cached results."
                                )
                                skip_scan = True
                                from progress_tracking import update_scan_progress
                                import asyncio

                                update_scan_progress(
                                    user_id, repo_name, "checking_changes", 20
                                )
                                await asyncio.sleep(0.5)
                                update_scan_progress(
                                    user_id, repo_name, "no_changed_files", 50
                                )
                                await asyncio.sleep(0.5)
                                update_scan_progress(
                                    user_id, repo_name, "using_cached_results", 80
                                )
                                await asyncio.sleep(0.5)
                                update_scan_progress(
                                    user_id, repo_name, "completed", 100
                                )
                        except Exception as e:
                            logger.critical(
                                f"*** URGENT: Error checking commit existence: {e}. Will scan all files as fallback."
                            )
                            files_to_scan = None
                            all_files_new = True
                            # Update the stored commit SHA to the current one since we can't verify the old one
                            if prev_result:
                                prev_result.scanned_commit_sha = new_sha
                                db_session.commit()
                                logger.critical(
                                    f"*** URGENT: Updated stored commit SHA to {new_sha} due to verification error"
                                )
                elif previous_sha == new_sha:
                    logger.critical(
                        f"*** URGENT: No new commits detected for repo {repo_name} at {new_sha}, skipping scan."
                    )
                    skip_scan = True
                    from progress_tracking import update_scan_progress
                    import asyncio

                    update_scan_progress(user_id, repo_name, "checking_commits", 20)
                    await asyncio.sleep(0.5)
                    update_scan_progress(user_id, repo_name, "no_new_commits", 50)
                    await asyncio.sleep(0.5)
                    update_scan_progress(user_id, repo_name, "using_cached_results", 80)
                    await asyncio.sleep(0.5)
                    update_scan_progress(user_id, repo_name, "completed", 100)
                else:
                    logger.critical(
                        f"*** URGENT: First scan or missing previous_sha for repo {repo_name}, will scan all files."
                    )
                    all_files_new = True
                    if prev_result and not getattr(
                        prev_result, "scanned_commit_sha", None
                    ):
                        logger.critical(
                            f"*** URGENT: Attempting to backfill missing commit SHA for previous scan ID {prev_result.id}"
                        )
                        try:
                            if repo_dir and Path(repo_dir).exists():
                                backfill_sha = get_current_commit_sha(Path(repo_dir))
                                if backfill_sha:
                                    prev_result.scanned_commit_sha = backfill_sha
                                    db_session.commit()
                                    logger.critical(
                                        f"*** URGENT: Successfully backfilled commit SHA: {backfill_sha}"
                                    )
                                    previous_sha = backfill_sha
                        except Exception as e:
                            logger.critical(
                                f"*** URGENT: Failed to backfill commit SHA: {e}"
                            )
                try:
                    if skip_scan:
                        logger.critical(
                            f"*** URGENT: Returning cached findings (No code changes detected)"
                        )

                        from progress_tracking import update_scan_progress
                        import asyncio

                        update_scan_progress(user_id, repo_name, "checking_changes", 20)
                        await asyncio.sleep(0.5)
                        update_scan_progress(
                            user_id, repo_name, "no_changes_detected", 50
                        )
                        await asyncio.sleep(0.5)
                        update_scan_progress(
                            user_id, repo_name, "using_cached_results", 80
                        )
                        await asyncio.sleep(0.5)
                        update_scan_progress(user_id, repo_name, "completed", 100)

                        results_data = {
                            "findings": previous_findings,
                            "stats": (
                                prev_result.results.get("stats", {})
                                if prev_result and prev_result.results
                                else {}
                            ),
                            "metadata": (
                                prev_result.results.get("metadata", {})
                                if prev_result and prev_result.results
                                else {}
                            ),
                        }
                        if analysis:
                            analysis.status = "completed"
                            analysis.results = results_data
                            analysis.rerank = prev_result.rerank
                            analysis.completed_at = datetime.now()
                            analysis.scanned_commit_sha = previous_sha
                            db_session.commit()
                        logger.critical(
                            f"*** URGENT: Scan SKIPPED for repo {repo_name}, findings reused."
                        )
                        return {"success": True, "data": results_data}
                    # SCAN START
                    if files_to_scan:
                        logger.critical(
                            f"*** URGENT: SCANNING INCREMENTALLY, ONLY CHANGED FILES: {files_to_scan}"
                        )
                    else:
                        logger.critical(f"*** URGENT: SCANNING ENTIRE REPOSITORY")
                    scan_results = await scanner.scan_repository(
                        repo_url,
                        installation_token,
                        user_id,
                        multi_scan=multi_scan,
                        files_to_scan=files_to_scan,
                        total_prev_files=total_prev_files,
                        previous_findings=(
                            previous_findings
                            if files_to_scan and previous_findings
                            else None
                        ),
                        current_commit_sha=new_sha,
                    )
                    # store commit sha
                    if analysis:
                        analysis.scanned_commit_sha = new_sha
                        db_session.commit()
                    if scan_results.get("success"):
                        scan_results["data"]["scanned_commit_sha"] = new_sha
                    logger.critical(
                        f"*** URGENT: SCAN COMPLETED for repo {repo_name} at SHA {new_sha}. Type: {'incremental' if files_to_scan else 'full'}"
                    )
                    return scan_results
                finally:
                    if repo_dir and Path(repo_dir).exists():
                        shutil.rmtree(repo_dir)
            except Exception as e:
                error_msg = f"Scan error: {str(e)}"
                logger.critical(f"*** URGENT: Exception in scan: {error_msg}")
                logger.error(error_msg)
                if analysis:
                    analysis.status = "error"
                    analysis.error = error_msg
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
        logger.critical(f"*** URGENT: Handler-level exception: {error_msg}")
        logger.error(error_msg)
        if analysis:
            analysis.status = "error"
            analysis.error = error_msg
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


def extract_rerank_tuples(response, selected_findings=None):
    """Parse [(ID, severity), ...] tuples from response (list or string); returns list of (ID, SEVERITY_UPPER) in order."""
    normalize = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW', 'info': 'INFO', 'error': 'ERROR'}
    
    try:
        if isinstance(response, str):
            response_str = response.strip()
            # Try to parse as-is first
            try:
                parsed = ast.literal_eval(response_str)
            except (ValueError, SyntaxError) as e:
                logger.warning(f"Failed to parse rerank response as complete string: {str(e)}")
                # Try to extract valid tuples from truncated string using regex
                # Pattern to match (number, 'severity') tuples
                tuple_pattern = r'\((\d+),\s*[\'"](\w+)[\'"]\)'
                matches = re.findall(tuple_pattern, response_str)
                if matches:
                    parsed = [(int(m[0]), m[1]) for m in matches]
                    logger.info(f"Extracted {len(parsed)} tuples from truncated response using regex")
                else:
                    logger.error(f"Could not extract tuples from truncated response: {response_str[:200]}...")
                    return []
            
            tuples = parsed if isinstance(parsed, list) else []
        elif isinstance(response, list):
            tuples = response
        else:
            logger.warning(f"Unexpected response type: {type(response)}")
            return []
        
        logger.info(f"OBSERVING RERANKING RESPONSE: Extracting rerank tuples: {len(tuples)} tuples found")
        logger.info(f"OBSERVING RERANKING RESPONSE: Normalize: {normalize}")
        
        result = []
        for item in tuples:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                i, s = item
                if isinstance(i, (int, float, str)) and isinstance(s, str):
                    try:
                        result.append((int(i), normalize.get(str(s).lower(), str(s).upper())))
                    except (ValueError, TypeError) as e:
                        logger.warning(f"Skipping invalid tuple item: {item}, error: {e}")
                        continue
        
        return result
    except Exception as e:
        logger.error(f"Error extracting rerank tuples: {str(e)}")
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return []
