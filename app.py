from gevent import monkey

monkey.patch_all()

from flask import Flask, request, jsonify
import time
import os
import subprocess
import logging
import hmac
import hashlib
import shutil
import json
import asyncio
from github import Github, GithubIntegration
from dotenv import load_dotenv
from datetime import datetime
from flask_cors import CORS
from models import db, AnalysisResult
from sqlalchemy import or_, text, create_engine
from sqlalchemy.pool import QueuePool
import traceback
import requests
from scanner import SecurityScanner, ScanConfig, scan_repository_handler
from api import api, analysis_bp
import time
from sqlalchemy import event
from progress import progress_bp
from flask_caching import Cache
import redis
from urllib.parse import quote_plus
import logging
from db_utils import create_db_engine
from flask_socketio import SocketIO, emit, join_room, disconnect
from threading import Thread, Lock
from progress_tracking import (
    get_scan_progress,
    update_scan_progress,
    clear_scan_progress,
)
from progress_tracking import get_redis_client
from models import db, AnalysisResult, IgnoredFinding
from azure_devops.azure_devops_api import azure_devops_bp
from v2_api import v2_api_bp
from gitlab_api import gitlab_bp
from zap_api import zap_bp
from sse_progress import sse_bp  # SSE for real-time progress streaming

# from codecommit_api import codecommit_bp
from codecommit.codecommit_api import codecommit_bp

# ============================================================================
# UNIFIED CLOUD SCANNER API - New Architecture
# ============================================================================
from cloud_scanner.unified_api import UnifiedCloudAPI
from cloud_scanner import register_provider

# Import AWS scanner components
from aws_scanner import (
    AwsSecurityScanner,
    scan_aws_account_handler,
    validate_aws_credentials
)

# Configure logging
logging.basicConfig(
    level=logging.INFO if os.getenv("FLASK_ENV") == "production" else logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Session management for WebSockets
session_lock = Lock()
active_sessions = {}


def manage_session(sid, action="add"):
    """Manage active sessions"""
    with session_lock:
        if action == "add":
            active_sessions[sid] = time.time()
        elif action == "remove" and sid in active_sessions:
            del active_sessions[sid]
        elif action == "check":
            return sid in active_sessions


# ... existing code ...


def cleanup_old_sessions():
    """Clean up expired sessions"""
    now = time.time()
    with session_lock:
        expired = [
            sid for sid, timestamp in active_sessions.items() if now - timestamp > 300
        ]  # 5 minutes timeout
        for sid in expired:
            del active_sessions[sid]


def _auto_backfill_workspaces():
    """Automatically backfill workspace IDs if needed"""

    # Check environment variable first (defaults to true)
    auto_backfill = os.getenv("AUTO_BACKFILL_WORKSPACES", "true").lower() == "true"

    if not auto_backfill:
        logger.info("Auto-backfill disabled via AUTO_BACKFILL_WORKSPACES env var")
        return

    try:
        dashboard_url = os.getenv("DASHBOARD_URL")
        if not dashboard_url:
            logger.warning("DASHBOARD_URL not configured, skipping workspace backfill")
            return

        logger.info("Checking if workspace backfill is needed...")

        # Check if backfill is needed
        with db.engine.connect() as conn:
            # Check if workspace_id column exists
            result = conn.execute(
                text(
                    """
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='analysis_results' AND column_name='workspace_id'
            """
                )
            )

            if not result.scalar():
                logger.info("workspace_id column doesn't exist yet, skipping backfill")
                return

            # Count records without workspace_id
            result = conn.execute(
                text(
                    """
                SELECT COUNT(*) 
                FROM analysis_results 
                WHERE workspace_id IS NULL AND user_id IS NOT NULL
            """
                )
            )

            count = result.scalar() or 0

            if count == 0:
                logger.info(
                    "✅ All records already have workspace_id, no backfill needed"
                )
                return

            logger.info(
                f"🔄 Found {count} records needing workspace backfill, starting process..."
            )

        # NOTE: Workspace backfill functionality removed
        # This was part of the old migration system
        # If needed, create a new Alembic migration for workspace backfill
        logger.info(f"🔄 Found {count} records needing workspace backfill")
        logger.info(
            "ℹ️  To backfill workspaces, create a data migration using: python migrate.py create 'backfill workspaces'"
        )

    except Exception as e:
        logger.error(f"Error during auto-backfill check: {str(e)}")
        # Don't crash the app if check fails


def configure_app_db(app, database_url=None):
    """Configure database for Flask app with REDUCED connection pool"""
    engine = create_db_engine(database_url)

    app.config["SQLALCHEMY_DATABASE_URI"] = database_url or engine.url
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
        "pool_size": 2,  # REDUCED from 20 to 2
        "max_overflow": 3,  # REDUCED from 30 to 3
        "pool_timeout": 30,
        "pool_recycle": 300,
        "pool_pre_ping": True,
        "pool_reset_on_return": "commit",  # ADD THIS LINE
        "connect_args": {
            "connect_timeout": 10,
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    }
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ECHO"] = False

    return engine


def check_db_connection():
    try:
        with app.app_context():
            db.session.execute(text("SELECT 1"))
            db.session.commit()
            return True
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        return False
    finally:
        db.session.remove()


def execute_with_retry(operation, max_retries=3, delay=1):
    """Enhanced version with proper cleanup"""

    def run_with_context():
        with app.app_context():
            try:
                return operation()
            finally:
                # Ensure session is properly closed
                db.session.close()

    for attempt in range(max_retries):
        try:
            return run_with_context()
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            logger.warning(
                f"Database operation failed, attempt {attempt + 1} of {max_retries}"
            )
            time.sleep(delay)
            # Force cleanup on retry
            try:
                db.session.rollback()
                db.session.close()
            except:
                pass


def check_and_add_columns():
    try:
        result = db.session.execute(
            text(
                """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='user_id'
        """
            )
        )
        if not result.scalar():
            logger.info("Adding user_id column...")
            db.session.execute(
                text(
                    """
                ALTER TABLE analysis_results 
                ADD COLUMN user_id VARCHAR(255)
            """
                )
            )
            db.session.commit()

        result = db.session.execute(
            text(
                """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='analysis_results' AND column_name='rerank'
        """
            )
        )
        if not result.scalar():
            logger.info("Adding rerank column...")
            db.session.execute(
                text(
                    """
                ALTER TABLE analysis_results 
                ADD COLUMN rerank JSONB
            """
                )
            )
            db.session.commit()

    except Exception as e:
        logger.error(f"Error checking/adding columns: {str(e)}")
        db.session.rollback()


def format_private_key(key_string):
    """
    Format the private key string properly for PyGithub
    """
    if not key_string:
        raise ValueError("Private key is empty")

    if not key_string.startswith("-----BEGIN"):
        parts = key_string.split()
        if len(parts) > 0:
            formatted = "-----BEGIN RSA PRIVATE KEY-----\n"
            for i in range(0, len(parts), 1):
                formatted += parts[i] + "\n"
            formatted += "-----END RSA PRIVATE KEY-----"
            return formatted

    return key_string


def verify_webhook_signature(payload_body, signature_header):
    """Verify that webhook request came from GitHub"""
    if not signature_header:
        return False

    hash_object = hmac.new(
        WEBHOOK_SECRET.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)


# Load environment variables
load_dotenv()

# Create Flask app
app = Flask(__name__)

# Configure CORS to allow all origins
CORS(
    app,
    resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": [
                "Content-Type",
                "Authorization",
                "X-Requested-With",
                "workspace-id",
                "organization-id",
                "accesstoken",
                "accessToken",
            ],
            "supports_credentials": False,
            "expose_headers": ["Content-Type", "Authorization"],
        }
    },
)

# Configure Redis
redis_client = get_redis_client()

# Configure Cache
CACHE_TYPE = os.getenv("CACHE_TYPE", "SimpleCache")
if CACHE_TYPE == "RedisCache":
    cache = Cache(
        app, config={"CACHE_TYPE": "RedisCache", "CACHE_REDIS_URL": redis_client.url}
    )
else:
    cache = Cache(app, config={"CACHE_TYPE": "SimpleCache"})

# Configure SocketIO with Redis for multi-instance support
redis_host = os.getenv("REDIS_HOST", "localhost")
redis_port = int(os.getenv("REDIS_PORT", 6379))
redis_password = os.getenv("REDIS_PASSWORD", None)

socketio_config = {
    "cors_allowed_origins": "*",
    "async_mode": "gevent",
    "ping_timeout": 60,
    "ping_interval": 25,
}

if CACHE_TYPE == "RedisCache":
    socketio_config["message_queue"] = (
        f"redis://:{redis_password}@{redis_host}:{redis_port}/0"
        if redis_password
        else f"redis://{redis_host}:{redis_port}/0"
    )

socketio = SocketIO(app, **socketio_config)

logger.info("SocketIO initialized successfully")


# SocketIO Event Handlers
@socketio.on("connect")
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    manage_session(request.sid, "add")
    emit("connected", {"data": "Connected to progress server"})


@socketio.on("disconnect")
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")
    manage_session(request.sid, "remove")


@socketio.on("subscribe_progress")
def handle_subscribe_progress(data):
    """Handle subscription to progress updates"""
    try:
        user_id = data.get("user_id")
        repo_name = data.get("repo_name")

        if not user_id or not repo_name:
            emit("error", {"message": "Missing user_id or repo_name"})
            return

        room = f"{user_id}:{repo_name}"
        join_room(room)

        logger.info(f"Client {request.sid} subscribed to progress for {room}")

        progress_data = get_scan_progress(user_id, repo_name)
        if progress_data and progress_data.get("stage") != "completed":
            emit("progress_update", progress_data)
        else:
            emit(
                "progress_update",
                {
                    "stage": "not_started",
                    "progress": 0,
                    "message": "No active scan",
                },
            )

    except Exception as e:
        logger.error(f"Error in subscribe_progress: {str(e)}")
        emit("error", {"message": "Failed to subscribe to progress updates"})


# Register existing blueprints
app.register_blueprint(api, url_prefix="/api/v1")
app.register_blueprint(progress_bp, url_prefix="/progress")
app.register_blueprint(analysis_bp, url_prefix="/api/v1")
app.register_blueprint(azure_devops_bp, url_prefix="/api/v1/azure-devops")
app.register_blueprint(v2_api_bp, url_prefix="/api/v2")
app.register_blueprint(gitlab_bp, url_prefix="/api/v1")
app.register_blueprint(codecommit_bp, url_prefix="/api/v1")
app.register_blueprint(zap_bp, url_prefix="/api/v1")
app.register_blueprint(sse_bp, url_prefix="/api/v1")

# ============================================================================
# REGISTER CLOUD PROVIDERS
# ============================================================================

def register_cloud_providers():
    """Register all cloud provider integrations with the unified API"""
    
    logger.info("Registering cloud providers...")
    
    # Register AWS
    try:
        register_provider(
            provider_name='aws',
            scan_handler=scan_aws_account_handler,
            validator=validate_aws_credentials,
            scanner_class=AwsSecurityScanner
        )
        logger.info("✓ AWS provider registered successfully")
    except Exception as e:
        logger.error(f"✗ Failed to register AWS provider: {str(e)}")
    
    # TODO: Register Azure when ready
    # try:
    #     from azure_scanner import (
    #         AzureSecurityScanner,
    #         scan_azure_subscription_handler,
    #         validate_azure_credentials
    #     )
    #     register_provider(
    #         provider_name='azure',
    #         scan_handler=scan_azure_subscription_handler,
    #         validator=validate_azure_credentials,
    #         scanner_class=AzureSecurityScanner
    #     )
    #     logger.info("✓ Azure provider registered successfully")
    # except Exception as e:
    #     logger.error(f"✗ Failed to register Azure provider: {str(e)}")
    
    # TODO: Register GCP when ready
    # try:
    #     from gcp_scanner import (
    #         GcpSecurityScanner,
    #         scan_gcp_project_handler,
    #         validate_gcp_credentials
    #     )
    #     register_provider(
    #         provider_name='gcp',
    #         scan_handler=scan_gcp_project_handler,
    #         validator=validate_gcp_credentials,
    #         scanner_class=GcpSecurityScanner
    #     )
    #     logger.info("✓ GCP provider registered successfully")
    # except Exception as e:
    #     logger.error(f"✗ Failed to register GCP provider: {str(e)}")


# Register cloud providers
register_cloud_providers()

# ============================================================================
# REGISTER UNIFIED CLOUD API
# ============================================================================

# Create unified cloud API instance
unified_cloud_api = UnifiedCloudAPI()

# Register the unified API at /api/v1/cloud
app.register_blueprint(unified_cloud_api.get_blueprint(), url_prefix='/api/v1/cloud')

logger.info("✓ Unified Cloud API registered at /api/v1/cloud")

# ============================================================================
# OPTIONAL: Keep old AWS API for backward compatibility (temporary)
# Uncomment the following lines if you need backward compatibility
# ============================================================================

# from aws_api import aws_bp
# app.register_blueprint(aws_bp, url_prefix='/api/v1/aws')
# logger.warning("⚠ Legacy AWS API active at /api/v1/aws (backward compatibility mode)")


# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Enhanced health check with database status"""
    try:
        # Check database connection
        with app.app_context():
            db.session.execute(text("SELECT 1"))
            db_status = "healthy"
    except Exception as e:
        logger.error(f"Health check DB error: {str(e)}")
        db_status = "unhealthy"

    # Check Redis connection
    try:
        redis_client.ping()
        redis_status = "healthy"
    except Exception as e:
        logger.error(f"Health check Redis error: {str(e)}")
        redis_status = "unhealthy"

    # Get registered cloud providers
    from cloud_scanner.provider_registry import CloudProviderRegistry
    registry = CloudProviderRegistry()
    registered_providers = registry.list_providers()

    overall_status = "healthy" if db_status == "healthy" and redis_status == "healthy" else "degraded"

    return jsonify(
        {
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "services": {
                "database": db_status,
                "redis": redis_status,
                "socketio": "healthy",
            },
            "cloud_providers": {
                "available": registered_providers,
                "count": len(registered_providers)
            },
            "apis": {
                "unified_cloud_api": "/api/v1/cloud",
                "repository_scanner": "/api/v1",
                "azure_devops": "/api/v1/azure-devops",
                "gitlab": "/api/v1",
                "codecommit": "/api/v1",
                "zap": "/api/v1",
            }
        }
    ), (200 if overall_status == "healthy" else 503)


# GitHub webhook endpoint
@app.route("/webhook", methods=["POST"])
def webhook():
    """Handle incoming webhook from GitHub"""
    try:
        signature = request.headers.get("X-Hub-Signature-256")
        if not verify_webhook_signature(request.data, signature):
            logger.warning("Invalid webhook signature")
            return jsonify({"error": "Invalid signature"}), 401

        payload = request.json
        event_type = request.headers.get("X-GitHub-Event")

        logger.info(f"Received webhook event: {event_type}")

        if event_type == "installation":
            action = payload.get("action")
            installation_id = payload.get("installation", {}).get("id")
            logger.info(f"Installation {action}: {installation_id}")

        elif event_type == "push":
            repository = payload.get("repository", {})
            repo_name = repository.get("full_name")
            installation_id = payload.get("installation", {}).get("id")

            logger.info(f"Push event for repository: {repo_name}")

            if installation_id:
                try:
                    token = git_integration.get_access_token(installation_id).token
                    g = Github(token)
                    repo = g.get_repo(repo_name)

                    config = ScanConfig(
                        repository_url=repository.get("clone_url"),
                        branch=payload.get("ref", "main").split("/")[-1],
                        repository_name=repo_name,
                    )

                    logger.info(f"Starting security scan for {repo_name}")

                    def run_scan():
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        result = loop.run_until_complete(
                            scan_repository_handler(config, None)
                        )
                        loop.close()
                        return result

                    scan_thread = Thread(target=run_scan)
                    scan_thread.start()

                except Exception as e:
                    logger.error(f"Error processing push event: {str(e)}")
                    logger.error(traceback.format_exc())

        return jsonify({"status": "success"}), 200

    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": "Internal server error"}), 500


def format_semgrep_results(semgrep_output):
    """Format Semgrep output into a structured response"""
    try:
        if isinstance(semgrep_output, str):
            try:
                semgrep_data = json.loads(semgrep_output)
            except json.JSONDecodeError:
                logger.error("Failed to parse Semgrep output as JSON")
                return {
                    "summary": {
                        "total_files_scanned": 0,
                        "total_findings": 0,
                        "files_scanned": [],
                        "semgrep_version": "unknown",
                        "scan_status": "failed",
                    },
                    "findings": [],
                    "findings_by_severity": {
                        "HIGH": [],
                        "MEDIUM": [],
                        "LOW": [],
                        "WARNING": [],
                        "INFO": [],
                    },
                    "findings_by_category": {},
                    "errors": ["Failed to parse Semgrep output"],
                    "severity_counts": {},
                    "category_counts": {},
                }
        else:
            semgrep_data = semgrep_output

        formatted_response = {
            "summary": {
                "total_files_scanned": len(
                    set(
                        result.get("path", "")
                        for result in semgrep_data.get("results", [])
                    )
                ),
                "total_findings": len(semgrep_data.get("results", [])),
                "files_scanned": list(
                    set(
                        result.get("path", "")
                        for result in semgrep_data.get("results", [])
                    )
                ),
                "semgrep_version": semgrep_data.get("version", "unknown"),
                "scan_status": "completed",
            },
            "findings": [],
            "findings_by_severity": {
                "HIGH": [],
                "MEDIUM": [],
                "LOW": [],
                "WARNING": [],
                "INFO": [],
            },
            "findings_by_category": {},
            "errors": semgrep_data.get("errors", []),
            "severity_counts": {},
            "category_counts": {},
        }

        for finding in semgrep_data.get("results", []):
            try:
                severity = (
                    finding.get("extra", {})
                    .get("severity", "INFO")
                    .upper()
                    .replace("ERROR", "HIGH")
                )

                category = (
                    finding.get("extra", {})
                    .get("metadata", {})
                    .get("category", "uncategorized")
                )

                formatted_finding = {
                    "id": finding.get("check_id", "unknown"),
                    "file": finding.get("path", "unknown"),
                    "line_start": finding.get("start", {}).get("line", 0),
                    "line_end": finding.get("end", {}).get("line", 0),
                    "code_snippet": finding.get("extra", {}).get("lines", ""),
                    "message": finding.get("extra", {}).get("message", ""),
                    "severity": severity,
                    "category": category,
                    "cwe": finding.get("extra", {}).get("metadata", {}).get("cwe", []),
                    "owasp": finding.get("extra", {})
                    .get("metadata", {})
                    .get("owasp", []),
                    "fix_recommendations": {
                        "description": finding.get("extra", {})
                        .get("metadata", {})
                        .get("message", ""),
                        "references": finding.get("extra", {})
                        .get("metadata", {})
                        .get("references", []),
                    },
                }

                formatted_response["findings"].append(formatted_finding)

                if severity not in formatted_response["findings_by_severity"]:
                    formatted_response["findings_by_severity"][severity] = []
                formatted_response["findings_by_severity"][severity].append(
                    formatted_finding
                )

                if category not in formatted_response["findings_by_category"]:
                    formatted_response["findings_by_category"][category] = []
                formatted_response["findings_by_category"][category].append(
                    formatted_finding
                )

            except Exception as e:
                logger.error(f"Error processing finding: {str(e)}")
                formatted_response["errors"].append(
                    f"Error processing finding: {str(e)}"
                )

        formatted_response["severity_counts"] = {
            severity: len(findings)
            for severity, findings in formatted_response["findings_by_severity"].items()
        }

        formatted_response["category_counts"] = {
            category: len(findings)
            for category, findings in formatted_response["findings_by_category"].items()
        }

        return formatted_response

    except Exception as e:
        logger.error(f"Error formatting results: {str(e)}")
        return {
            "summary": {
                "total_files_scanned": 0,
                "total_findings": 0,
                "files_scanned": [],
                "semgrep_version": "unknown",
                "scan_status": "failed",
            },
            "findings": [],
            "findings_by_severity": {
                "HIGH": [],
                "MEDIUM": [],
                "LOW": [],
                "WARNING": [],
                "INFO": [],
            },
            "findings_by_category": {},
            "errors": [f"Failed to format results: {str(e)}"],
            "severity_counts": {},
            "category_counts": {},
        }


# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL")
engine = configure_app_db(app, DATABASE_URL)

# Initialize database
db.init_app(app)

# Create an event loop for async operations
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

# Database initialization (minimal, no Alembic)
with app.app_context():
    try:

        def init_db_minimal():
            """Minimal database initialization that doesn't hold connections"""
            try:
                # Test connection first
                with db.engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                    logger.info("Database connection test successful")

                # Create tables if needed (releases connection immediately)
                db.create_all()
                logger.info("Database tables verified/created")

                # Check columns in separate connection
                with db.engine.connect() as conn:
                    result = conn.execute(
                        text(
                            """
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name='analysis_results' AND column_name='user_id'
                    """
                        )
                    )
                    column_exists = bool(result.scalar())

                    if not column_exists:
                        logger.info("Adding user_id column...")
                        conn.execute(
                            text(
                                """
                            ALTER TABLE analysis_results 
                            ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
                        """
                            )
                        )
                        conn.execute(
                            text(
                                """
                            CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                            ON analysis_results (user_id)
                        """
                            )
                        )
                        conn.commit()

                    result = conn.execute(
                        text(
                            """
                        SELECT column_name 
                        FROM information_schema.columns 
                        WHERE table_name='analysis_results' AND column_name='rerank'
                    """
                        )
                    )
                    rerank_exists = bool(result.scalar())

                    if not rerank_exists:
                        logger.info("Adding rerank column...")
                        conn.execute(
                            text(
                                """
                            ALTER TABLE analysis_results 
                            ADD COLUMN IF NOT EXISTS rerank JSONB
                        """
                            )
                        )
                        conn.commit()

                logger.info("Database initialization completed successfully")

                # Call auto-backfill after initialization
                _auto_backfill_workspaces()

                return True

            except Exception as e:
                logger.error(f"Database initialization error: {str(e)}")
                raise

        # Try initialization with exponential backoff
        max_attempts = 5
        for attempt in range(max_attempts):
            try:
                init_db_minimal()
                logger.info("Database initialization successful")
                break
            except Exception as e:
                if attempt == max_attempts - 1:
                    logger.error(
                        f"Failed to initialize database after {max_attempts} attempts: {str(e)}"
                    )
                    logger.warning(
                        "Starting app without database initialization for emergency recovery"
                    )
                    break
                else:
                    wait_time = 2**attempt
                    logger.warning(
                        f"Database init attempt {attempt + 1} failed, waiting {wait_time}s: {str(e)}"
                    )
                    time.sleep(wait_time)

    except Exception as e:
        logger.error(f"Critical database initialization error: {str(e)}")
        logger.warning("App starting in emergency mode without database")


# Initialize GitHub integration
try:
    APP_ID = os.getenv("GITHUB_APP_ID")
    WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
    PRIVATE_KEY = os.getenv("GITHUB_APP_PRIVATE_KEY")

    if not all([APP_ID, WEBHOOK_SECRET, PRIVATE_KEY]):
        raise ValueError("Missing required environment variables")

    formatted_key = format_private_key(PRIVATE_KEY)
    git_integration = GithubIntegration(
        integration_id=int(APP_ID),
        private_key=formatted_key,
    )
    logger.info("GitHub Integration initialized successfully")
except Exception as e:
    logger.error(f"Configuration error: {str(e)}")
    raise


def create_app():
    """Factory function for Gunicorn"""
    return socketio.run(app, host="0.0.0.0", port=10000)


if __name__ == "__main__":
    # Migrations are handled by init_db_with_alembic() during app context initialization

    port = int(os.getenv("PORT", 10000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True, use_reloader=False)