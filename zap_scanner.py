
import asyncio
import json
import logging
import os
import shlex
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
import time
from typing import Dict, List, Optional, Tuple, Callable


logger = logging.getLogger(__name__)


@dataclass
class ZapScanOptions:
    target_url: str
    scan_type: str = "baseline"  # baseline|full|ajax|api
    timeout_seconds: int = 1800  # 30 minutes default
    fail_on_warn: bool = False
    allow_https: bool = True
    additional_args: List[str] = None
    max_scan_duration: int = 3600
    progress_timeout: int = 300
    use_ajax_spider: bool = False
    enable_active_scan: bool = None
    use_docker: bool = False 


class ZapScanner:
    """
    Run OWASP ZAP scans using official Docker images.
    Production-minded defaults:
    - Uses ephemeral temp directories for reports
    - Timeouts enforced
    - Parses JSON output and returns normalized findings
    """

    BASELINE_IMAGES = [
        "ghcr.io/zaproxy/zaproxy:stable",
        "zaproxy/zap-stable",
        "zaproxy/zap-weekly",
    ]

    FULL_SCAN_IMAGES = [
        "ghcr.io/zaproxy/zaproxy:stable",
        "zaproxy/zap-stable",
        "zaproxy/zap-weekly",
    ]

    def __init__(self, docker_binary: str = "docker"):
        self.docker = docker_binary
        # Verify docker binary exists
        if not shutil.which(docker_binary):
            logger.warning(f"Docker binary '{docker_binary}' not found in PATH")

    def _error(self, message: str, details: str = "") -> Dict:
        """Create standardized error response"""
        return {
            "success": False,
            "error": {"message": message, "details": details, "type": "zap_scan_error"},
        }

    async def _check_docker_available(self) -> Tuple[bool, str]:
        """Check if Docker daemon is running and accessible"""
        try:
            check_cmd = [self.docker, "info"]
            process = await asyncio.create_subprocess_exec(
                *check_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)

            if process.returncode == 0:
                return True, "Docker is available"
            else:
                error_msg = stderr.decode().strip()
                return False, f"Docker not accessible: {error_msg}"

        except asyncio.TimeoutError:
            return False, "Docker info command timed out - Docker may not be running"
        except Exception as e:
            return False, f"Docker check failed: {e}"

    async def _test_docker_image(self, image: str) -> Tuple[bool, str]:
        """Test if a Docker image is available locally or can be pulled"""
        try:

            logger.info(f"Checking if image exists locally: {image}")
            check_cmd = [self.docker, "image", "inspect", image]
            process = await asyncio.create_subprocess_exec(
                *check_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=10)

            if process.returncode == 0:
                logger.info(f"Image found locally: {image}")
                return True, f"Image {image} exists locally"

            logger.info(f"Attempting to pull Docker image: {image}")
            pull_cmd = [self.docker, "pull", image]
            process = await asyncio.create_subprocess_exec(
                *pull_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=600
            )  # 10 minutes for pull

            if process.returncode == 0:
                logger.info(f"Successfully pulled image: {image}")
                return True, f"Successfully pulled {image}"
            else:
                error_msg = stderr.decode().strip()
                logger.warning(f"Failed to pull image {image}: {error_msg}")
                return False, f"Pull failed: {error_msg}"

        except asyncio.TimeoutError:
            logger.warning(f"Timeout testing/pulling image: {image}")
            return False, f"Timeout pulling {image}"
        except Exception as e:
            logger.warning(f"Error testing image {image}: {e}")
            return False, f"Error: {str(e)}"

    async def _find_available_image(self, images: list) -> Tuple[str, List[str]]:
        """Find the first available Docker image from a list"""
        errors = []
        for image in images:
            logger.info(f"Testing Docker image: {image}")
            success, message = await self._test_docker_image(image)
            if success:
                logger.info(f"Found available Docker image: {image}")
                return image, errors
            else:
                logger.warning(f"Docker image not available: {image} - {message}")
                errors.append(f"{image}: {message}")

        logger.error(f"No Docker images available from: {images}")
        return images[0], errors

    async def run(self, options: ZapScanOptions) -> Dict:
        if not options.use_docker:
            cli_ok, cli_path = self._local_zap_cli_exists()
            if not cli_ok:
                return self._error("Local ZAP CLI not available", cli_path)
            return await self._run_local_scan(options, cli_path)
        else:
            docker_available, docker_message = await self._check_docker_available()
            if not docker_available:
                # Try local as fallback
                cli_ok, cli_path = self._local_zap_cli_exists()
                if cli_ok:
                    return await self._run_local_scan(options, cli_path)
                return self._error(
                    "Neither Docker nor local ZAP CLI is available.",
                    f"Docker error: {docker_message}; CLI error: {cli_path}",
                )
            return await self._run_docker_scan(options)

    async def _run_local_scan(self, options: ZapScanOptions, cli_path: str) -> Dict:
        temp_dir = Path(tempfile.mkdtemp(prefix="zap_") )
        try:
            report_json = temp_dir / "zap_report.json"
            html_report = temp_dir / "zap_report.html"
            cmd = self._build_local_command(options, report_json, html_report, cli_path, temp_dir)
            logger.info(f"Running local ZAP: {' '.join(shlex.quote(str(c)) for c in cmd)}")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
    # Helper to build command
    def _build_local_command(self, options, report_json, html_report, cli_path, temp_dir):
        if options.scan_type == "baseline":
            # For baseline scans, prefer zap-baseline.py, but if zap.sh is used, we need -cmd flag
            is_zap_sh = cli_path.endswith("zap.sh") or "zap.sh" in cli_path
            if is_zap_sh:
                # zap.sh needs -cmd flag and different syntax - use zap-baseline.py if available
                baseline_py = shutil.which("zap-baseline.py")
                if baseline_py:
                    cli_path = baseline_py
                    cmd = [cli_path, "-t", options.target_url, "-r", str(html_report), "-J", str(report_json), "-I"]
                    is_zap_sh = False  # Now using zap-baseline.py
                else:
                    # Fallback: use zap.sh with automation framework for baseline
                    automation_yaml = temp_dir / "automation_baseline.yaml"
                    self._create_baseline_automation_config(automation_yaml, options.target_url, temp_dir)
                    cmd = [cli_path, "-cmd", "-autorun", str(automation_yaml)]
            else:
                # Using zap-baseline.py or zaproxy - standard syntax
                cmd = [cli_path, "-t", options.target_url, "-r", str(html_report), "-J", str(report_json), "-I"]
            
            if not is_zap_sh:
                # Only add these flags for zap-baseline.py, not zap.sh with automation
                if options.use_ajax_spider:
                    cmd.append("-j")
                if options.fail_on_warn:
                    cmd += ["-w", "/dev/stdout"]
            if options.additional_args:
                cmd += options.additional_args
        elif options.scan_type in ("full", "api"):
            # Use automation.yaml
            automation_yaml = temp_dir / "automation.yaml"
            self._create_automation_config(automation_yaml, options.target_url, temp_dir)
            cmd = ["zap.sh", "-cmd", "-autorun", str(automation_yaml)]
            if options.additional_args:
                cmd += options.additional_args
        else:
            # ajax, future support
            cmd = [cli_path, "-t", options.target_url, "-r", str(html_report), "-J", str(report_json), "-j"]
            if options.additional_args:
                cmd += options.additional_args
        return cmd

    def _create_automation_config(self, yaml_path: Path, target_url: str, output_dir: Path):
        """Create ZAP automation framework config for reliable full scans"""
        report_dir = str(Path(output_dir).resolve())
        config = f"""---
env:
  contexts:
    - name: "Default Context"
      urls:
        - "{target_url}"
      includePaths: []
      excludePaths: []
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: spider
    parameters:
      maxDuration: 5
      maxDepth: 5
      maxChildren: 10
      acceptCookies: true
      handleODataParametersVisited: true

  - type: passiveScan-wait
    parameters:
      maxDuration: 3

  - type: activeScan
    parameters:
      context: "Default Context"
      policy: "Default Policy"
      maxRuleDurationInMins: 3
      maxScanDurationInMins: 10
      threadPerHost: 2
      delayInMs: 0
      handleAntiCSRFTokens: true
      scanHeadersAllRequests: true

  - type: passiveScan-wait
    parameters:
      maxDuration: 3

  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "{report_dir}"
      reportFile: "zap_report.json"
      reportTitle: "ZAP Security Scan"
      reportDescription: "Full security scan"

  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "{report_dir}"
      reportFile: "zap_report.html"
      reportTitle: "ZAP Security Scan"
      reportDescription: "Full security scan"
"""
        with yaml_path.open("w") as f:
            f.write(config)
        logger.info(f"Created automation config: {yaml_path}")

    def _create_api_automation_config(self, yaml_path: Path, target_url: str, output_dir: Path):
        """Create lightweight automation config for API scanning"""
        report_dir = str(Path(output_dir).resolve())
        config = f"""---
env:
  contexts:
    - name: "API Context"
      urls:
        - "{target_url}"
      includePaths: []
      excludePaths: []
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: spider
    parameters:
      maxDuration: 2
      maxDepth: 3
      maxChildren: 5

  - type: passiveScan-wait
    parameters:
      maxDuration: 2

  - type: activeScan
    parameters:
      context: "API Context"
      policy: "API-Minimal"
      maxRuleDurationInMins: 2
      maxScanDurationInMins: 5
      threadPerHost: 4

  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "{report_dir}"
      reportFile: "zap_report.json"

  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "{report_dir}"
      reportFile: "zap_report.html"
"""
        with yaml_path.open("w") as f:
            f.write(config)
        logger.info(f"Created API automation config: {yaml_path}")

    def _create_baseline_automation_config(self, yaml_path: Path, target_url: str, output_dir: Path):
        """Create automation config for baseline scans using zap.sh"""
        report_dir = str(Path(output_dir).resolve())
        config = f"""---
env:
  contexts:
    - name: "Default Context"
      urls:
        - "{target_url}"
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
  - type: spider
    parameters:
      maxDuration: 5
      maxDepth: 5
      maxChildren: 10

  - type: passiveScan-wait
    parameters:
      maxDuration: 3

  - type: report
    parameters:
      template: "traditional-json"
      reportDir: "{report_dir}"
      reportFile: "zap_report.json"

  - type: report
    parameters:
      template: "traditional-html"
      reportDir: "{report_dir}"
      reportFile: "zap_report.html"
"""
        with yaml_path.open("w") as f:
            f.write(config)
        logger.info(f"Created baseline automation config: {yaml_path}")

    def _normalize_findings(self, zap_json: Dict, target: str) -> Dict:
        site_alerts = []
        if isinstance(zap_json, dict):
            sites = zap_json.get("site") or zap_json.get("sites") or []
            if isinstance(sites, dict):
                sites = [sites]
            for site in sites:
                alerts = site.get("alerts") or []
                for a in alerts:
                    site_alerts.append(self._map_alert(a))

            if not site_alerts and "alerts" in zap_json:
                for a in zap_json.get("alerts", []):
                    site_alerts.append(self._map_alert(a))

        severity_counts = {"CRITICAL": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
        for f in site_alerts:
            sev = f.get("severity", "INFO")
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["INFO"] += 1

        return {
            "findings": site_alerts,
            "stats": {
                "total_findings": len(site_alerts),
                "severity_counts": severity_counts,
                "category_counts": {},
                "scan_stats": {},
            },
            "metadata": {"target": target, "scanner": "zap"},
        }

    def _map_alert(self, alert: Dict) -> Dict:
        name = alert.get("alert") or alert.get("name") or "ZAP Alert"
        risk = (alert.get("risk") or alert.get("riskcode") or "info").upper()
        severity = {
            "HIGH": "CRITICAL",
            "MEDIUM": "ERROR",
            "LOW": "WARNING",
            "INFO": "INFO",
            "INFORMATIONAL": "INFO",
        }.get(risk, "INFO")

        cwe = []
        try:
            if alert.get("cweid") not in (None, "0", 0):
                cwe = [f"CWE-{alert.get('cweid')}"]
        except Exception:
            pass

        return {
            "id": name,
            "file": alert.get("url", ""),
            "line_start": None,
            "line_end": None,
            "code_snippet": "",
            "message": alert.get("desc") or alert.get("description") or name,
            "severity": severity,
            "category": alert.get("alertRef") or "web-security",
            "cwe": cwe,
            "owasp": [],
            "fix_recommendations": alert.get("solution", ""),
            "references": [
                r
                for r in (
                    alert.get("reference", "").split(" ")
                    if alert.get("reference")
                    else []
                )
                if r
            ],
        }

    @staticmethod
    def _local_zap_cli_exists() -> Tuple[bool, str]:
        candidates = ["zap-baseline.py", "zap.sh", "zaproxy"]
        for exe in candidates:
            path = shutil.which(exe)
            if path:
                return True, path
        return False, "ZAP CLI not found in PATH. Tried zap-baseline.py, zap.sh, zaproxy"


class ZapScannerWithProgress(ZapScanner):
    """
    Enhanced ZAP scanner with progress tracking - SIMPLIFIED VERSION
    Uses script-based approach instead of complex API management
    """

    def __init__(
        self,
        docker_binary: str = "docker",
        progress_callback: Optional[Callable] = None,
    ):
        super().__init__(docker_binary)
        self.progress_callback = progress_callback

    async def run_with_progress(
        self, options: ZapScanOptions, user_id: str = None, resource_id: str = None
    ) -> Dict:
        """Run ZAP scan with simplified progress tracking"""

        if self.progress_callback:
            self.progress_callback("initializing", 5)

        if not options.use_docker:
            cli_ok, cli_path = self._local_zap_cli_exists()
            if not cli_ok:
                return self._error("Local ZAP CLI not available", cli_path)
            return await self._run_local_scan_with_progress(options, cli_path)
        else:
            docker_available, docker_message = await self._check_docker_available()
            if not docker_available:
                # Try local as fallback
                cli_ok, cli_path = self._local_zap_cli_exists()
                if cli_ok:
                    return await self._run_local_scan_with_progress(options, cli_path)
                return self._error(
                    "Neither Docker nor local ZAP CLI is available.",
                    f"Docker error: {docker_message}; CLI error: {cli_path}",
                )
            return await self._run_docker_scan_with_progress(options)

    async def _run_local_scan_with_progress(self, options: ZapScanOptions, cli_path: str) -> Dict:
        temp_dir = Path(tempfile.mkdtemp(prefix="zap_"))
        try:
            report_json = temp_dir / "zap_report.json"
            html_report_src = temp_dir / "zap_report.html"

            if options.scan_type == "full":
                automation_yaml = temp_dir / "automation.yaml"
                self._create_automation_config(automation_yaml, options.target_url, temp_dir)

            cmd = self._build_local_command(options, report_json, html_report_src, cli_path, temp_dir)
            logger.info(f"Running local ZAP: {' '.join(shlex.quote(str(c)) for c in cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            if self.progress_callback:
                self.progress_callback("scan_started", 20)

            output_lines = []
            last_progress_time = time.time()
            current_stage = "initializing"
            current_progress = 20

            async def read_output():
                nonlocal last_progress_time, current_stage, current_progress
                active_scan_start_time = None
                active_scan_timeout = 900  # 15 minutes max for active scan

                while True:
                    try:
                        line = await asyncio.wait_for(
                            process.stdout.readline(), timeout=30
                        )
                        if not line:
                            break

                        line_text = line.decode("utf-8", errors="ignore").strip()
                        output_lines.append(line_text)
                        logger.info(
                            f"ZAP: {line_text}"
                        )  # Changed to INFO for visibility

                        # Parse progress from automation framework output
                        line_lower = line_text.lower()

                        if "spider" in line_lower and "started" in line_lower:
                            current_stage = "spider_running"
                            current_progress = 30
                            if self.progress_callback:
                                self.progress_callback(current_stage, current_progress)
                            last_progress_time = time.time()

                        elif "spider" in line_lower and (
                            "finished" in line_lower or "found" in line_lower
                        ):
                            current_stage = "spider_completed"
                            current_progress = 45
                            if self.progress_callback:
                                self.progress_callback(current_stage, current_progress)
                            last_progress_time = time.time()

                        elif (
                            "passivescan" in line_lower or "passive scan" in line_lower
                        ):
                            if "started" in line_lower:
                                current_stage = "passive_scan_running"
                                current_progress = 50
                            elif "finished" in line_lower:
                                current_stage = "passive_scan_completed"
                                current_progress = 55
                            if self.progress_callback:
                                self.progress_callback(current_stage, current_progress)
                            last_progress_time = time.time()

                        elif "activescan" in line_lower or "active scan" in line_lower:
                            if "started" in line_lower:
                                active_scan_start_time = time.time()
                                current_stage = "active_scan_running"
                                current_progress = 60
                                if self.progress_callback:
                                    self.progress_callback(
                                        current_stage, current_progress
                                    )
                            elif "finished" in line_lower or "completed" in line_lower:
                                current_stage = "active_scan_completed"
                                current_progress = 85
                                active_scan_start_time = None
                                if self.progress_callback:
                                    self.progress_callback(
                                        current_stage, current_progress
                                    )
                            last_progress_time = time.time()

                        elif "report" in line_lower:
                            current_stage = "generating_report"
                            current_progress = 90
                            if self.progress_callback:
                                self.progress_callback(current_stage, current_progress)
                            last_progress_time = time.time()

                        elif (
                            "automation plan succeeded" in line_lower
                            or "finished" in line_lower
                        ):
                            current_stage = "completed"
                            current_progress = 95
                            if self.progress_callback:
                                self.progress_callback(current_stage, current_progress)
                            last_progress_time = time.time()

                        # Special check: if active scan is running too long
                        if active_scan_start_time:
                            active_scan_elapsed = time.time() - active_scan_start_time
                            if active_scan_elapsed > active_scan_timeout:
                                logger.warning(
                                    f"Active scan exceeded {active_scan_timeout}s, forcing completion"
                                )
                                # Don't kill, just log - let maxScanDurationInMins handle it
                                active_scan_start_time = None

                        # Check for stuck scan (no output at all)
                        if time.time() - last_progress_time > options.progress_timeout:
                            logger.warning(
                                f"No progress for {options.progress_timeout}s"
                            )
                            process.kill()
                            raise TimeoutError("Scan stuck - no output")

                    except asyncio.TimeoutError:
                        if process.returncode is not None:
                            break
                        # Check active scan timeout even during read timeout
                        if active_scan_start_time:
                            active_scan_elapsed = time.time() - active_scan_start_time
                            if active_scan_elapsed > active_scan_timeout:
                                logger.warning(
                                    f"Active scan exceeded timeout during read"
                                )
                                process.kill()
                                raise TimeoutError("Active scan timeout")
                        continue

            try:
                await asyncio.gather(
                    read_output(),
                    asyncio.wait_for(process.wait(), timeout=options.timeout_seconds),
                )

                stderr_output = await process.stderr.read()

                if self.progress_callback:
                    self.progress_callback("processing_results", 90)

                html_report_src = report_json.parent / "zap_report.html"
                persisted_html_path = None
                try:
                    if html_report_src.exists():
                        import uuid
                        durable_dir = Path(tempfile.gettempdir()) / "zap_reports"
                        durable_dir.mkdir(parents=True, exist_ok=True)
                        persisted_html_path = durable_dir / f"zap_report_{uuid.uuid4().hex}.html"
                        shutil.copyfile(str(html_report_src), str(persisted_html_path))
                except Exception:
                    logger.exception("Failed to persist HTML report to durable temp directory (progress)")

                if persisted_html_path and persisted_html_path.exists():
                    html_report_path = str(persisted_html_path.resolve())
                elif html_report_src.exists():
                    html_report_path = str(html_report_src.resolve())
                else:
                    html_report_path = None

                if report_json.exists():
                    with report_json.open("r") as f:
                        report_data = json.load(f)

                    if self.progress_callback:
                        self.progress_callback("completed", 100)

                    data_payload = self._normalize_findings(report_data, options.target_url)
                    if html_report_path:
                        data_payload |= {"html_report_path": html_report_path}
                    return {"success": True, "data": data_payload, "zap_exit_code": process.returncode}
                else:
                    if self.progress_callback:
                        self.progress_callback("completed", 100)

                    data_payload = {
                        "findings": [],
                        "raw_stdout": "\n".join(output_lines[-50:]),
                        "target": options.target_url,
                        "scanner": "zap",
                    }
                    if html_report_path:
                        data_payload["html_report_path"] = html_report_path
                    return {"success": True, "data": data_payload, "zap_exit_code": process.returncode}

            except asyncio.TimeoutError:
                logger.error(f"Scan timed out after {options.timeout_seconds}s")
                process.kill()
                return self._error(
                    "ZAP scan timed out", f"Output:\n{chr(10).join(output_lines[-20:])}"
                )

        finally:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass

