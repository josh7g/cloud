import logging
import ssl
import certifi
import aiohttp
from dataclasses import dataclass, field
import os
import json
import re
import asyncio
import traceback
from typing import Dict, List, Optional, Union

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
