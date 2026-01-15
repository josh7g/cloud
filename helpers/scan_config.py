from dataclasses import dataclass, field
from typing import Dict, List


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
