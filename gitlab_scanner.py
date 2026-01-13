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
import traceback
import fnmatch
import requests
import time
from typing import Dict, List, Optional, Union, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from models import GitLabAnalysisResult
from progress_tracking import update_scan_progress
from utils import create_secure_client_session
import ast

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


@dataclass
class GitLabScanConfig:
    """Configuration for GitLab repository scanning with language-specific rules"""

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


class GitLabSecurityScanner:
    def __init__(
        self,
        config: GitLabScanConfig = GitLabScanConfig(),
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
        self._project_url = None
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

    def set_scan_info(self, project_url: str, user_id: str):
        """Store project URL and user ID for use in progress tracking"""
        self._project_url = project_url
        self._user_id = user_id

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
            self.temp_dir = Path(tempfile.mkdtemp(prefix="gitlab_scanner_"))
            logger.info(f"Created temporary directory: {self.temp_dir}")

            self._session = create_secure_client_session(timeout=30)

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
        if language in ["csharp", "cs", "dotnet", "net", "c#"]:
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

    async def _check_repository_size(self, project_id: int, access_token: str) -> Dict:
        """Check repository size and detect primary language using GitLab API"""
        if not self._session:
            logger.error("HTTP session not initialized")
            raise RuntimeError("Scanner session not initialized")

        try:
            if not access_token:
                raise ValueError("GitLab token is empty or invalid")

            logger.info(f"Checking size and language for project ID: {project_id}")

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            }

            api_url = f"https://gitlab.com/api/v4/projects/{project_id}"

            async with self._session.get(api_url, headers=headers) as response:
                response_text = await response.text()
                logger.info(f"GitLab API Status: {response.status}")

                if response.status != 200:
                    raise ValueError(f"GitLab API error: {response_text}")

                data = json.loads(response_text)

                # Get repository size
                size_kb = data.get("statistics", {}).get("repository_size", 0)
                size_mb = size_kb / 1024

                # Get primary language - different field in GitLab API
                self.detected_language = data.get("predominant_language")

                logger.info(f"Repository size: {size_mb:.2f}MB")
                logger.info(f"Detected language: {self.detected_language}")
                logger.info(f"Default branch: {data.get('default_branch', 'main')}")

                # For better language detection, also check languages in repository
                languages_url = (
                    f"https://gitlab.com/api/v4/projects/{project_id}/languages"
                )

                try:
                    async with self._session.get(
                        languages_url, headers=headers
                    ) as lang_response:
                        if lang_response.status == 200:
                            languages_data = await lang_response.json()
                            if languages_data:
                                # Languages are returned with percentage values
                                # Get the one with highest percentage
                                primary_language = max(
                                    languages_data.items(), key=lambda x: x[1]
                                )[0]
                                logger.info(
                                    f"Primary language from languages API: {primary_language}"
                                )

                                # If languages API returned a value, prefer it over predominant_language
                                if primary_language and not self.detected_language:
                                    self.detected_language = primary_language
                except Exception as lang_error:
                    logger.warning(f"Error getting languages data: {str(lang_error)}")

                return {
                    "size_mb": size_mb,
                    "is_compatible": size_mb <= self.config.max_total_size_mb,
                    "language": self.detected_language,
                    "default_branch": data.get("default_branch", "main"),
                    "visibility": data.get("visibility", "unknown"),
                    "star_count": data.get("star_count", 0),
                    "fork_count": data.get("forks_count", 0),
                    "created_at": data.get("created_at"),
                    "last_activity_at": data.get("last_activity_at"),
                }

        except Exception as e:
            logger.error(f"Error checking repository size: {str(e)}")
            raise

    async def _clone_repository(self, project_url: str, access_token: str) -> Path:
        """Clone repository with size validation and optimizations"""
        try:
            project_id = self._extract_project_id(project_url, access_token)
            size_info = await self._check_repository_size(project_id, access_token)

            if not size_info["is_compatible"]:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            self.repo_dir = (
                self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            )
            auth_url = project_url.replace(
                "https://", f"https://oauth2:{access_token}@"
            )

            logger.info(f"Cloning repository to {self.repo_dir}")

            # Optimize clone operation
            # USING  depth=2 to get the current commit and its parent for diff support
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
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

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
                # Prepend target_dir to file paths for semgrep
                cmd.extend([str(Path(target_dir) / f) for f in file_list])
                logger.critical(
                    f"*** URGENT: Running incremental GitLab Semgrep scan on {len(file_list)} files for config {scan_name}."
                )
            else:
                cmd.append(str(target_dir))
                logger.critical(
                    f"*** URGENT: Running full GitLab Semgrep scan for config {scan_name}."
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

            # file list for incremental scans
            self._current_file_list = files_to_scan

            # Get relevant configs based on language
            selected_configs = self.get_language_specific_configs(
                self.detected_language
            )

            # Add these lines for progress tracking
            project_url = getattr(self, "_project_url", "")
            user_id = getattr(self, "_user_id", "")
            project_id = self._extract_project_id(project_url, None, use_cached=True)
            total_configs = len(selected_configs)

            all_results = []
            merged_findings = []
            total_files_scanned = 0
            total_files_skipped = 0
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            seen_findings = set()
            errors = []

            # Run selected scans sequentially
            for i, scan_config in enumerate(selected_configs):
                try:
                    # Update progress here
                    progress = (i / total_configs) * 100
                    update_scan_progress(
                        user_id, project_id, "analyzing", progress, None, "gitlab"
                    )

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
                    current_files_scanned = stats.get("scan_stats", {}).get(
                        "files_scanned", 0
                    )

                    # FOR INCREMENTAL SCANS, USING THE file list count
                    if files_to_scan and current_files_scanned == 0:
                        total_files_scanned = len(files_to_scan)
                        logger.critical(
                            f"*** URGENT: Using file_list for incremental scan count: {total_files_scanned} files"
                        )
                    elif current_files_scanned > 0:
                        total_files_scanned = current_files_scanned
                    else:
                        total_files_scanned = max(
                            total_files_scanned, current_files_scanned
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
                            severity = finding.get("severity", "UNKNOWN").upper()
                            category = finding.get("category", "unknown")
                            severity_counts[severity] += 1
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
                    "severity_counts": dict(severity_counts),
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
            if self._user_id and self._project_url:
                project_id = self._extract_project_id(
                    self._project_url, None, use_cached=True
                )
                update_scan_progress(
                    self._user_id, project_id, "error", 0, None, "gitlab"
                )

            return self._create_empty_result(error=str(e))

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process and normalize scan results"""
        findings = results.get("results", [])
        stats = results.get("stats", {})
        paths = results.get("paths", {})
        parse_metrics = results.get("parse_metrics", {})

        processed_findings = []
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)

        total_files = stats.get("total", {}).get("files", 0)
        if not total_files:
            total_files = stats.get("total_files", 0)

        skipped = paths.get("skipped", [])
        skipped_count = len(skipped) if skipped else 0

        scanned = paths.get("scanned", [])
        files_scanned = len(scanned) if scanned else total_files - skipped_count

        # FOR INCREMENTAL SCANS, if we don't have proper path information,
        # CALCULATE FROM THE FINDINGS AND file_list if available
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

        files_with_findings = set()

        for finding in findings:
            file_path = finding.get("path", "")
            if file_path:
                files_with_findings.add(file_path)

            severity = finding.get("extra", {}).get("severity", "INFO").upper()
            category = (
                finding.get("extra", {}).get("metadata", {}).get("category", "security")
            )

            severity_counts[severity] += 1
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
            "total_files": total_files,
            "files_scanned": files_scanned,
            "files_with_findings": len(files_with_findings),
            "skipped_files": skipped_count,
            "partially_scanned": parse_metrics.get("partially_parsed_files", 0),
        }

        return {
            "findings": processed_findings,
            "stats": {
                "total_findings": len(processed_findings),
                "severity_counts": dict(severity_counts),
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
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "INFO": 0,
                },
                "category_counts": {},
                "scan_stats": self.scan_stats,
                "memory_usage_mb": self.scan_stats.get("memory_usage_mb", 0),
            },
            "errors": [error] if error else [],
        }

    def _extract_project_id(
        self, project_url: str, access_token: str = None, use_cached: bool = False
    ) -> str:
        """Extract GitLab project ID from URL or path, with caching option"""

        # If using cached ID and we have a valid project URL, parse it from the URL
        # This is useful when we've already looked up the project ID but need it again without an API call
        if use_cached and hasattr(self, "_cached_project_id"):
            return self._cached_project_id

        try:
            # Handle both URL and path formats
            if project_url and "gitlab.com" in project_url:
                path = project_url.split("gitlab.com/")[-1].rstrip(".git")
            elif project_url:
                path = project_url.lstrip("/")
            else:
                raise ValueError("Project URL is empty")

            # If we don't have an access token, just return the encoded path as the ID
            # This is useful for progress tracking where we just need a consistent ID
            if not access_token:
                return path.replace("/", "%2F")

            # Make API call to get project ID using OAuth token
            url = f"https://gitlab.com/api/v4/projects/{path.replace('/', '%2F')}"
            headers = {"Authorization": f"Bearer {access_token}"}

            logger.info(f"Fetching project ID for path: {path}")
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                project_data = response.json()
                project_id = str(project_data["id"])
                logger.info(f"Successfully got project ID: {project_id}")

                # Cache the project ID for future use
                self._cached_project_id = project_id
                return project_id

            logger.error(
                f"Failed to get project ID. Status: {response.status_code}, Response: {response.text}"
            )
            raise ValueError(
                f"Failed to get project ID for {path}. Status: {response.status_code}"
            )

        except Exception as e:
            logger.error(f"Error extracting project ID: {str(e)}")
            raise ValueError(f"Invalid GitLab project URL or path: {str(e)}")

    async def scan_repository(
        self,
        project_url: str,
        access_token: str,
        user_id: str,
        files_to_scan: Optional[list] = None,
        previous_findings: Optional[list] = None,
        current_commit_sha: Optional[str] = None,
    ) -> Dict:
        """Main method to scan a repository with multiple configurations based on language"""
        try:
            # Store project URL and user ID for progress tracking
            self.set_scan_info(project_url, user_id)

            # Extract project ID for progress tracking
            project_id = self._extract_project_id(project_url, access_token)

            # Update progress to initializing
            update_scan_progress(user_id, project_id, "initializing", 0, None, "gitlab")

            # Check repository size and language in a single API call
            size_info = await self._check_repository_size(int(project_id), access_token)
            update_scan_progress(user_id, project_id, "cloning", 20, None, "gitlab")

            # Clone repository
            repo_dir = await self._clone_repository(project_url, access_token)
            update_scan_progress(user_id, project_id, "analyzing", 40, None, "gitlab")

            # Get current commit SHA
            current_sha = get_current_commit_sha(repo_dir)
            self._current_commit_sha = current_sha

            # Store file list for statistics calculation
            self._current_file_list = files_to_scan

            # Run multiple scans based on detected language
            if files_to_scan:
                logger.critical(
                    f"*** URGENT: Running incremental GitLab scan on {len(files_to_scan)} files"
                )
                scan_results = await self.run_multiple_semgrep_scans(
                    repo_dir, files_to_scan
                )
            else:
                logger.critical(f"*** URGENT: Running full GitLab scan")
                scan_results = await self.run_multiple_semgrep_scans(repo_dir)
            update_scan_progress(user_id, project_id, "processing", 70, None, "gitlab")

            # Get all findings
            all_findings = scan_results.get("findings", [])
            logger.info(f"Found {len(all_findings)} total findings")

            # Prepare reranking data
            RAG_URL = os.getenv("RAG_URL")
            if not RAG_URL:
                raise ValueError("RAG_URL not configured")
            rerank_api_url = f"{RAG_URL}/vulnerability_reranker_labelled"

            reordered_findings = all_findings.copy()
            if all_findings and rerank_api_url:
                import aiohttp
                logger.info(f"Sending {len(all_findings)} findings for reranking")
                rerank_data = [{"ID": f["ID"], "file": f.get("file"), "severity": f.get("severity")} for f in all_findings]
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(rerank_api_url, json=rerank_data, timeout=30) as resp:
                            if resp.status == 200:
                                rerank_response = await resp.json()
                                logger.info(f"OBSERVING RERANKING RESPONSE: Rerank response: {rerank_response}")
                                tuples = extract_rerank_tuples(rerank_response["llm_response"], all_findings)
                                if tuples:
                                    id_to_finding = {f["ID"]: f.copy() for f in all_findings}
                                    reordered_findings = {}
                                    reordered_findings_list = []
                                    for t_id, sev in tuples:
                                        f = id_to_finding.get(t_id)
                                        if f:
                                            f["severity"] = sev
                                            reordered_findings_list.append(f)
                                    reordered_findings["findings"] = reordered_findings_list
                                    reordered_findings["stats"] = scan_results.get("stats", {})
                                    reordered_findings["stats"]["severity_counts"] = {
                                        "CRITICAL": len([f for f in reordered_findings_list if f["severity"] == "CRITICAL"]),
                                        "HIGH": len([f for f in reordered_findings_list if f["severity"] == "HIGH"]),
                                        "MEDIUM": len([f for f in reordered_findings_list if f["severity"] == "MEDIUM"]),
                                        "LOW": len([f for f in reordered_findings_list if f["severity"] == "LOW"]),
                                    }
                                    logger.info(f"Applied rerank tuple ordering/severity to findings. IDs: {[t_id for t_id, _ in tuples]}")
                                else:
                                    logger.warning("Rerank tuple output invalid/empty, using original order")
                            else:
                                logger.error(f"Reranker API error: status={resp.status}")
                except Exception as e:
                    logger.error(f"Reranker integration error: {e}")

            # Add IDs to findings if needed
            for idx, finding in enumerate(reordered_findings, 1):
                if "ID" not in finding:
                    finding["ID"] = idx

            # Prepare complete results data
            results_data = {
                "findings": reordered_findings,
                "stats": reordered_findings.get("stats", {}),
                "metadata": {
                    "repository_url": project_url,
                    "project_id": project_id,
                    "user_id": user_id,
                    "scan_start": self.scan_stats["start_time"].isoformat(),
                    "scan_end": datetime.now().isoformat(),
                    "scan_duration_seconds": (
                        datetime.now() - self.scan_stats["start_time"]
                    ).total_seconds(),
                    "language": self.detected_language,
                    "scanned_commit_sha": getattr(self, "_current_commit_sha", None),
                },
            }

            # Update progress to reranking
            update_scan_progress(user_id, project_id, "reranking", 85, None, "gitlab")

            # Update database with full results
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(GitLabAnalysisResult).get(
                        self.analysis_id
                    )
                    if analysis:
                        analysis.results = results_data
                        analysis.rerank = reordered_findings
                        analysis.status = "completed"
                        analysis.completed_at = datetime.now()
                        analysis.scanned_commit_sha = getattr(
                            self, "_current_commit_sha", None
                        )
                        self.db_session.commit()
                        try:
                            self.db_session.refresh(analysis)
                            logger.critical(
                                f"*** DEBUG: Post-commit refresh (scan_repository): analysis_id={analysis.id} scanned_commit_sha={analysis.scanned_commit_sha}"
                            )
                        except Exception as refresh_exc:
                            logger.warning(
                                f"Could not refresh analysis after commit: {refresh_exc}"
                            )
                        logger.critical(
                            f"*** URGENT: Successfully stored GitLab scan in database - results: {len(all_findings)}, rerank: {len(reordered_findings)}, commit_sha: {getattr(self, '_current_commit_sha', None)}"
                        )
                except Exception as e:
                    self.db_session.rollback()
                    logger.critical(
                        f"*** URGENT: GitLab database update failed: {str(e)}"
                    )

            # Update progress to completed
            update_scan_progress(user_id, project_id, "completed", 100, None, "gitlab")

            return {
                "success": True,
                "data": {
                    "project_url": project_url,
                    "project_id": project_id,
                    "user_id": user_id,
                    "timestamp": datetime.now().isoformat(),
                    "findings": reordered_findings,
                    "stats": reordered_findings["stats"],
                    "metadata": results_data["metadata"],
                    "repository_info": {
                        "size_mb": size_info["size_mb"],
                        "primary_language": size_info["language"],
                        "default_branch": size_info["default_branch"],
                        "visibility": size_info["visibility"],
                        "star_count": size_info["star_count"],
                        "fork_count": size_info["fork_count"],
                    },
                },
            }

        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")

            # Update progress to error
            try:
                if user_id and project_id:
                    update_scan_progress(
                        user_id, project_id, "error", 0, None, "gitlab"
                    )
            except Exception as pe:
                logger.error(f"Error updating progress: {str(pe)}")

            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(GitLabAnalysisResult).get(
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


def format_file_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.2f} TB"


def validate_gitlab_url(url: str) -> bool:
    """Validate GitLab repository URL format"""
    if not url:
        return False

    valid_formats = [
        r"https://gitlab\.com/[\w-]+/[\w-]+(?:\.git)?$",
        r"git@gitlab\.com:[\w-]+/[\w-]+(?:\.git)?$",
    ]

    return any(re.match(pattern, url) for pattern in valid_formats)


def get_current_commit_sha(repo_dir: Path) -> str:
    """Get the current commit SHA from the repository directory"""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
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
            # fallback approach
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


def get_severity_weight(severity: str) -> int:
    """Get numerical weight for severity level for sorting"""
    weights = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return weights.get(severity.upper(), 0)


def sort_findings_by_severity(findings: List[Dict]) -> List[Dict]:
    """Sort findings by severity level"""
    return sorted(
        findings,
        key=lambda x: get_severity_weight(x.get("severity", "INFO")),
        reverse=True,
    )


def deduplicate_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate findings from scan results based on multiple criteria"""
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

    severity_counts = defaultdict(int)
    category_counts = defaultdict(int)

    for finding in deduplicated_findings:
        severity = finding.get("severity", "UNKNOWN")
        category = finding.get("category", "unknown")
        severity_counts[severity] += 1
        category_counts[category] += 1

    stats = scan_results["data"].setdefault("stats", {})
    scan_stats = stats.setdefault("scan_stats", {})
    scan_stats["total_findings"] = len(deduplicated_findings)
    scan_stats["files_scanned"] = (
        scan_results["data"].get("stats", {}).get("files_scanned", 0)
    )
    scan_stats["files_with_findings"] = (
        scan_results["data"].get("stats", {}).get("files_with_findings", 0)
    )
    scan_stats["skipped_files"] = (
        scan_results["data"].get("stats", {}).get("skipped_files", 0)
    )
    scan_stats["partially_scanned"] = (
        scan_results["data"].get("stats", {}).get("partially_scanned", 0)
    )

    stats["severity_counts"] = dict(severity_counts)
    stats["category_counts"] = dict(category_counts)
    stats["deduplication_info"] = {
        "original_count": len(findings),
        "deduplicated_count": len(deduplicated_findings),
        "duplicates_removed": len(findings) - len(deduplicated_findings),
    }

    scan_results["data"]["findings"] = deduplicated_findings
    scan_results["data"]["stats"] = stats

    return scan_results


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


async def scan_gitlab_repository_handler(
    project_id: str,
    project_url: str,
    access_token: str,
    user_id: str,
    db_session: Optional[Session] = None,
    analysis_record: Optional[GitLabAnalysisResult] = None,
) -> Dict:
    """Handler function for GitLab web routes with input validation"""
    logger.info(f"Starting scan request for GitLab project: {project_url}")

    if not all([project_url, access_token, user_id]):
        return {
            "success": False,
            "error": {
                "message": "Missing required parameters",
                "code": "INVALID_PARAMETERS",
            },
        }

    if not validate_gitlab_url(project_url):
        return {
            "success": False,
            "error": {
                "message": "Invalid project URL format",
                "code": "INVALID_PROJECT_URL",
                "details": "Only GitLab.com repositories are supported",
            },
        }

    try:
        # Extract repository name for progress tracking
        repo_name = project_url.split("/")[-1].replace(".git", "")

        # Clear previous progress
        from progress_tracking import clear_scan_progress

        clear_scan_progress(user_id, project_id)

        # Initialize scanner with config and record ID
        config = GitLabScanConfig()
        analysis_id = analysis_record.id if analysis_record else None

        async with GitLabSecurityScanner(config, db_session, analysis_id) as scanner:
            try:
                # Get project ID and check size (update with progress)
                update_scan_progress(
                    user_id, project_id, "validating", 10, None, "gitlab"
                )

                # Extract project ID (numeric)
                project_id = scanner._extract_project_id(project_url, access_token)

                # Update project_id in database if possible
                if analysis_record and db_session:
                    try:
                        analysis_record.project_id = str(project_id)
                        db_session.commit()
                    except Exception as e:
                        logger.error(f"Failed to update project ID: {str(e)}")
                        db_session.rollback()

                # Check repository size
                size_info = await scanner._check_repository_size(
                    project_id, access_token
                )

                if not size_info["is_compatible"]:
                    # Update progress to error
                    update_scan_progress(
                        user_id, project_id, "error", 0, None, "gitlab"
                    )

                    # Update analysis record
                    if analysis_record and db_session:
                        try:
                            analysis_record.status = "error"
                            analysis_record.error = (
                                f"Repository too large: {size_info['size_mb']}MB"
                            )
                            analysis_record.completed_at = datetime.now()
                            db_session.commit()
                        except Exception:
                            db_session.rollback()

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

                # --- Incremental Scan for GitLab ---

                previous_findings = []
                previous_commit_sha = None
                last_analysis_id = None

                logger.critical(
                    f"*** URGENT: Checking GitLab DB for previous analysis: project_path={analysis_record.project_path if analysis_record else 'N/A'} workspace_id={analysis_record.workspace if analysis_record else 'N/A'} user_id={user_id}"
                )

                if db_session:
                    from sqlalchemy import desc

                    prev_query = (
                        db_session.query(GitLabAnalysisResult)
                        .filter(
                            GitLabAnalysisResult.project_path
                            == (
                                analysis_record.project_path
                                if analysis_record
                                else project_url.split("gitlab.com/")[-1].rstrip(".git")
                            ),
                            GitLabAnalysisResult.project_id == str(project_id),
                            GitLabAnalysisResult.workspace
                            == (analysis_record.workspace if analysis_record else None),
                        )
                        .order_by(desc(GitLabAnalysisResult.timestamp))
                    )
                    prev_result = prev_query.first()
                    if prev_result and db_session:
                        try:
                            db_session.refresh(prev_result)
                            logger.critical(
                                f"*** DEBUG: After refresh prev_result: id={prev_result.id} scanned_commit_sha={getattr(prev_result,'scanned_commit_sha', None)}"
                            )
                        except Exception as r_exc:
                            logger.warning(f"Could not refresh prev_result: {r_exc}")
                    logger.critical(
                        f"*** URGENT: GitLab DB previous analysis result found: {bool(prev_result)}, sha={[getattr(prev_result,'scanned_commit_sha',None)] if prev_result else None}"
                    )
                    if prev_result:
                        logger.critical(
                            f"*** URGENT: GitLab Previous analysis details - ID: {prev_result.id}, Status: {prev_result.status}, Timestamp: {prev_result.timestamp}, SHA: {getattr(prev_result, 'scanned_commit_sha', 'MISSING')}"
                        )
                    if prev_result and getattr(prev_result, "scanned_commit_sha", None):
                        previous_commit_sha = prev_result.scanned_commit_sha
                        if prev_result.results and "findings" in prev_result.results:
                            previous_findings = prev_result.results["findings"]
                    elif prev_result and prev_result.results:
                        metadata = prev_result.results.get("metadata", {})
                        if "scanned_commit_sha" in metadata:
                            previous_commit_sha = metadata["scanned_commit_sha"]
                            logger.critical(
                                f"*** URGENT: Found GitLab commit SHA in metadata: {previous_commit_sha}"
                            )
                        if "findings" in prev_result.results:
                            previous_findings = prev_result.results["findings"]

                # Clone the repository
                repo_dir = await scanner._clone_repository(project_url, access_token)
                current_commit_sha = get_current_commit_sha(repo_dir)

                logger.critical(
                    f"*** URGENT: GitLab File diff: Previous={previous_commit_sha} | New={current_commit_sha}"
                )
                files_to_scan = None
                skip_scan = False
                all_files_new = False
                changed_files = []

                if previous_commit_sha and previous_commit_sha != current_commit_sha:
                    changed_files = get_changed_files_between_commits(
                        repo_dir, previous_commit_sha, current_commit_sha
                    )
                    logger.critical(
                        f"*** URGENT: GitLab Changed files list: {changed_files}"
                    )
                    if changed_files:
                        files_to_scan = changed_files
                        logger.critical(
                            f"*** URGENT: Will scan changed files only: {changed_files}"
                        )
                    else:
                        # Check if this is because git diff failed (history rewritten) or truly no changes
                        logger.critical(
                            f"*** URGENT: No changed files detected or git diff failed. Checking if this is due to history rewrite..."
                        )

                        # Try to detect if this is a history rewrite by checking if we can find the old commit
                        import subprocess

                        try:
                            result = subprocess.run(
                                [
                                    "git",
                                    "-C",
                                    str(repo_dir),
                                    "cat-file",
                                    "-e",
                                    previous_commit_sha,
                                ],
                                capture_output=True,
                                text=True,
                            )
                            if result.returncode != 0:
                                # Check if this is a shallow clone (depth=2)
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
                                        if commit_count == 2:
                                            logger.critical(
                                                f"*** URGENT: Shallow clone detected (depth=2) - previous commit not available. Will scan all files as fallback."
                                            )
                                            files_to_scan = None
                                            all_files_new = True
                                            # Update the stored commit SHA to the current one
                                            if prev_result:
                                                prev_result.scanned_commit_sha = (
                                                    current_commit_sha
                                                )
                                                db_session.commit()
                                                try:
                                                    db_session.refresh(prev_result)
                                                    logger.critical(
                                                        f"*** DEBUG: After commit-refresh (prev_result shallow clone): id={prev_result.id} scanned_commit_sha={prev_result.scanned_commit_sha}"
                                                    )
                                                except Exception as rr:
                                                    logger.warning(
                                                        f"Refresh failed after setting prev_result SHA: {rr}"
                                                    )
                                        else:
                                            logger.critical(
                                                f"*** URGENT: Previous commit {previous_commit_sha} not found - likely history rewritten. Will scan all files as fallback."
                                            )
                                            files_to_scan = None
                                            all_files_new = True
                                            # Update the stored commit SHA to the current one since history was rewritten
                                            if prev_result:
                                                prev_result.scanned_commit_sha = (
                                                    current_commit_sha
                                                )
                                                db_session.commit()
                                                try:
                                                    db_session.refresh(prev_result)
                                                    logger.critical(
                                                        f"*** DEBUG: After commit-refresh (prev_result history rewrite): id={prev_result.id} scanned_commit_sha={prev_result.scanned_commit_sha}"
                                                    )
                                                except Exception as rr:
                                                    logger.warning(
                                                        f"Refresh failed after setting prev_result SHA: {rr}"
                                                    )
                                    else:
                                        logger.critical(
                                            f"*** URGENT: Previous commit {previous_commit_sha} not found - likely history rewritten. Will scan all files as fallback."
                                        )
                                        files_to_scan = None
                                        all_files_new = True
                                        # Update the stored commit SHA to the current one since history was rewritten
                                        if prev_result:
                                            prev_result.scanned_commit_sha = (
                                                current_commit_sha
                                            )
                                            db_session.commit()
                                            try:
                                                db_session.refresh(prev_result)
                                                logger.critical(
                                                    f"*** DEBUG: After commit-refresh (prev_result history rewrite): id={prev_result.id} scanned_commit_sha={prev_result.scanned_commit_sha}"
                                                )
                                            except Exception as rr:
                                                logger.warning(
                                                    f"Refresh failed after setting prev_result SHA: {rr}"
                                                )
                                except Exception as depth_error:
                                    logger.critical(
                                        f"*** URGENT: Error checking GitLab clone depth: {depth_error}. Will scan all files as fallback."
                                    )
                                    files_to_scan = None
                                    all_files_new = True
                                    # Update the stored commit SHA to the current one since we can't verify the old one
                                    if prev_result:
                                        prev_result.scanned_commit_sha = (
                                            current_commit_sha
                                        )
                                        db_session.commit()
                                        try:
                                            db_session.refresh(prev_result)
                                            logger.critical(
                                                f"*** DEBUG: After commit-refresh (prev_result verify error): id={prev_result.id} scanned_commit_sha={prev_result.scanned_commit_sha}"
                                            )
                                        except Exception as rr:
                                            logger.warning(
                                                f"Refresh failed after setting prev_result SHA: {rr}"
                                            )
                            else:
                                logger.critical(
                                    f"*** URGENT: No changed files detected, skipping scan and using cached results."
                                )
                                skip_scan = True
                                update_scan_progress(
                                    user_id,
                                    project_id,
                                    "checking_changes",
                                    20,
                                    None,
                                    "gitlab",
                                )
                                await asyncio.sleep(0.5)
                                update_scan_progress(
                                    user_id,
                                    project_id,
                                    "no_changed_files",
                                    50,
                                    None,
                                    "gitlab",
                                )
                                await asyncio.sleep(0.5)
                                update_scan_progress(
                                    user_id,
                                    project_id,
                                    "using_cached_results",
                                    80,
                                    None,
                                    "gitlab",
                                )
                                await asyncio.sleep(0.5)
                                update_scan_progress(
                                    user_id,
                                    project_id,
                                    "completed",
                                    100,
                                    None,
                                    "gitlab",
                                )
                        except Exception as e:
                            logger.critical(
                                f"*** URGENT: Error checking GitLab commit existence: {e}. Will scan all files as fallback."
                            )
                            files_to_scan = None
                            all_files_new = True
                            # Update the stored commit SHA to the current one since we can't verify the old one
                            if prev_result:
                                prev_result.scanned_commit_sha = current_commit_sha
                                db_session.commit()
                                try:
                                    db_session.refresh(prev_result)
                                    logger.critical(
                                        f"*** DEBUG: After commit-refresh (prev_result verification error 2): id={prev_result.id} scanned_commit_sha={prev_result.scanned_commit_sha}"
                                    )
                                except Exception as rr:
                                    logger.warning(
                                        f"Refresh failed after setting prev_result SHA: {rr}"
                                    )
                elif previous_commit_sha == current_commit_sha:
                    logger.critical(
                        f"*** URGENT: No new commits detected for GitLab project {project_url} at {current_commit_sha}, skipping scan."
                    )
                    skip_scan = True
                    update_scan_progress(
                        user_id, project_id, "checking_commits", 20, None, "gitlab"
                    )
                    await asyncio.sleep(0.5)
                    update_scan_progress(
                        user_id, project_id, "no_new_commits", 50, None, "gitlab"
                    )
                    await asyncio.sleep(0.5)
                    update_scan_progress(
                        user_id, project_id, "using_cached_results", 80, None, "gitlab"
                    )
                    await asyncio.sleep(0.5)
                    update_scan_progress(
                        user_id, project_id, "completed", 100, None, "gitlab"
                    )
                else:
                    logger.critical(
                        f"*** URGENT: First scan or missing previous_sha for GitLab project {project_url}, will scan all files."
                    )
                    all_files_new = True

                try:
                    if skip_scan:
                        logger.critical(
                            f"*** URGENT: Returning cached GitLab findings (No code changes detected)"
                        )

                        update_scan_progress(
                            user_id, project_id, "checking_changes", 20, None, "gitlab"
                        )
                        await asyncio.sleep(0.5)
                        update_scan_progress(
                            user_id,
                            project_id,
                            "no_changes_detected",
                            50,
                            None,
                            "gitlab",
                        )
                        await asyncio.sleep(0.5)
                        update_scan_progress(
                            user_id,
                            project_id,
                            "using_cached_results",
                            80,
                            None,
                            "gitlab",
                        )
                        await asyncio.sleep(0.5)
                        update_scan_progress(
                            user_id, project_id, "completed", 100, None, "gitlab"
                        )

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
                        if analysis_record:
                            analysis_record.status = "completed"
                            analysis_record.results = results_data
                            analysis_record.rerank = prev_result.rerank
                            analysis_record.completed_at = datetime.now()
                            analysis_record.scanned_commit_sha = previous_commit_sha
                            db_session.commit()
                        logger.critical(
                            f"*** URGENT: GitLab Scan SKIPPED for project {project_url}, findings reused."
                        )
                        return {"success": True, "data": results_data}

                    # SCAN START
                    if files_to_scan:
                        logger.critical(
                            f"*** URGENT: SCANNING GITLAB INCREMENTALLY, ONLY CHANGED FILES: {files_to_scan}"
                        )
                    else:
                        logger.critical(
                            f"*** URGENT: SCANNING GITLAB ENTIRE REPOSITORY"
                        )

                    results = await scanner.scan_repository(
                        project_url,
                        access_token,
                        user_id,
                        files_to_scan=files_to_scan,
                        previous_findings=(
                            previous_findings
                            if files_to_scan and previous_findings
                            else None
                        ),
                        current_commit_sha=current_commit_sha,
                    )

                    # Merge findings logic for GitLab
                    if previous_findings and files_to_scan:
                        updated_findings = {
                            f_id: f for f_id, f in enumerate(previous_findings)
                        }

                        # Remove findings from changed files in previous results
                        for old_finding_idx, old_finding in enumerate(
                            previous_findings
                        ):
                            if old_finding.get("file") in files_to_scan:
                                if old_finding_idx in updated_findings:
                                    del updated_findings[old_finding_idx]

                        # Add new findings
                        for new_finding in results.get("data", {}).get("findings", []):
                            new_finding_key = (
                                new_finding.get("file"),
                                new_finding.get("line_start"),
                                new_finding.get("id"),
                            )
                            updated_findings[f"new_{len(updated_findings)}"] = (
                                new_finding
                            )

                        all_findings = list(updated_findings.values())
                        logger.critical(
                            f"*** URGENT: GitLab Merged findings: {len(previous_findings)} old, {len(results.get('data', {}).get('findings', []))} new, resulting in {len(all_findings)} total."
                        )

                        # Update results with merged findings
                        if "data" in results:
                            results["data"]["findings"] = all_findings
                    else:
                        all_findings = (
                            results.get("data", {}).get("findings", [])
                            if "data" in results
                            else []
                        )
                        logger.critical(
                            f"*** URGENT: No previous findings or no changed files, using {len(all_findings)} current GitLab findings."
                        )

                    # store commit sha
                    if analysis_record:
                        analysis_record.scanned_commit_sha = current_commit_sha
                        analysis_record.status = "completed"
                        analysis_record.error = None
                        analysis_record.completed_at = datetime.now()
                        db_session.commit()
                    if results.get("success") and "data" in results:
                        results["data"]["scanned_commit_sha"] = current_commit_sha
                    logger.critical(
                        f"*** URGENT: GITLAB SCAN COMPLETED for project {project_url} at SHA {current_commit_sha}. Type: {'incremental' if files_to_scan else 'full'}"
                    )

                    return results
                finally:
                    if repo_dir and Path(repo_dir).exists():
                        shutil.rmtree(repo_dir)

            except ValueError as ve:
                # Update progress to error
                update_scan_progress(user_id, project_id, "error", 0, None, "gitlab")

                # Update analysis record
                if analysis_record and db_session:
                    try:
                        analysis_record.status = "error"
                        analysis_record.error = str(ve)
                        analysis_record.completed_at = datetime.now()
                        db_session.commit()
                    except Exception:
                        db_session.rollback()

                return {
                    "success": False,
                    "error": {
                        "message": str(ve),
                        "code": "VALIDATION_ERROR",
                        "timestamp": datetime.now().isoformat(),
                    },
                }

            except git.GitCommandError as ge:
                # Update progress to error
                update_scan_progress(user_id, project_id, "error", 0, None, "gitlab")

                # Update analysis record
                if analysis_record and db_session:
                    try:
                        analysis_record.status = "error"
                        analysis_record.error = f"Git error: {str(ge)}"
                        analysis_record.completed_at = datetime.now()
                        db_session.commit()
                    except Exception:
                        db_session.rollback()

                return {
                    "success": False,
                    "error": {
                        "message": "Git operation failed",
                        "code": "GIT_ERROR",
                        "details": str(ge),
                        "timestamp": datetime.now().isoformat(),
                    },
                }

    except Exception as e:
        import traceback

        logger.critical(
            f"*** DEBUG: Exception caught in scan_gitlab_repository_handler: {repr(e)}"
        )
        logger.critical(f"*** DEBUG: Traceback:\n{traceback.format_exc()}")
        if analysis_record and db_session:
            try:
                logger.critical(
                    f"*** DEBUG: Previous analysis_record.status: {analysis_record.status}"
                )
                if analysis_record.status != "completed":
                    analysis_record.status = "error"
                    analysis_record.error = str(e)
                    analysis_record.completed_at = datetime.now()
                    db_session.commit()
                    logger.critical(
                        f"*** DEBUG: Set analysis_record.status to ERROR, analysis_record.error={analysis_record.error}"
                    )
                else:
                    logger.critical(
                        f"*** DEBUG: NOT setting error because status is already completed"
                    )
            except Exception as commit_exc:
                db_session.rollback()
                logger.critical(
                    f"*** DEBUG: Exception during commit/rollback: {repr(commit_exc)}. Traceback:\n{traceback.format_exc()}"
                )
        logger.error(f"Handler error: {str(e)}")
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
