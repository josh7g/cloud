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
from aws_api import aws_bp
import random
from models import db, AnalysisResult, IgnoredFinding
from azure_devops.azure_devops_api import azure_devops_bp
from v2_api import v2_api_bp
from gitlab_api import gitlab_bp
from zap_api import zap_bp
from sse_progress import sse_bp  # SSE for real-time progress streaming

# from codecommit_api import codecommit_bp
from codecommit.codecommit_api import codecommit_bp

# Unified Cloud Scanner API
from cloud_scanner.unified_api import UnifiedCloudAPI
from cloud_scanner.providers.aws.aws_api import register_aws_provider

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
        column_exists = bool(result.scalar())

        if not column_exists:
            logger.info("Adding user_id column...")
            db.session.execute(
                text(
                    """
                ALTER TABLE analysis_results 
                ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
            """
                )
            )
            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                ON analysis_results (user_id)
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
        rerank_exists = bool(result.scalar())

        if not rerank_exists:
            logger.info("Adding rerank column...")
            db.session.execute(
                text(
                    """
                ALTER TABLE analysis_results 
                ADD COLUMN IF NOT EXISTS rerank JSONB
            """
                )
            )
            db.session.commit()

    except Exception as e:
        logger.error(f"Error checking/adding columns: {str(e)}")
        db.session.rollback()
        raise
    finally:
        db.session.remove()


# Initialize Flask app and Redis
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(
    REDIS_URL,
    decode_responses=True,
    socket_timeout=5,
    socket_connect_timeout=5,
    socket_keepalive=True,
    health_check_interval=30,
    retry_on_timeout=True,
)

# Initialize Redis pub/sub for WebSocket communication
pubsub = redis_client.pubsub(ignore_subscribe_messages=True)

# Initialize Flask app
app = Flask(__name__)
# Configure CORS for all routes including blueprints
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With", "workspace-id", "organization-id", "accesstoken", "accessToken"],
        "max_age": 3600
    }
}, supports_credentials=False)


socketio = SocketIO(
    cors_allowed_origins="*",
    message_queue=REDIS_URL,
    channel="semgrep-scan",
    async_mode="gevent",
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=5 * 1024 * 1024,
    async_handlers=True,
    logger=True,
    engineio_logger=True,
    manage_session=False,
    cookie=None,
)
socketio.init_app(app)

# Initialize cache
cache = Cache(
    config={"CACHE_TYPE": "SimpleCache", "CACHE_DEFAULT_TIMEOUT": 7200}  # 2 hours
)
cache.init_app(app)
app.cache = cache

register_aws_provider()
# register_azure_provider()  
# register_gcp_provider()    

# unified cloud API at /api/v1/cloud/*
unified_cloud_api = UnifiedCloudAPI()
cloud_bp = unified_cloud_api.get_blueprint()
app.register_blueprint(cloud_bp, url_prefix='/api/v1/cloud')

# Register blueprints
app.register_blueprint(progress_bp)
app.register_blueprint(api, name="api_main")
app.register_blueprint(analysis_bp, name="analysis_main")
app.register_blueprint(aws_bp, name="aws_main")  # Keep for backward compatibility
app.register_blueprint(azure_devops_bp, name="azure_devops")
app.register_blueprint(v2_api_bp, name="v2_api")
app.register_blueprint(gitlab_bp, name="gitlab_main")
app.register_blueprint(zap_bp, name="zap_main")
app.register_blueprint(sse_bp, name="sse_main")  # SSE for progress streaming
# app.register_blueprint(codecommit_bp, name="codecommit_main")
app.register_blueprint(codecommit_bp, name="codecommit_main_2")


def redis_listener():
    """
    Enhanced Redis listener with immediate cleanup of completed scan data.
    """
    last_processed = {}
    min_interval = 0.1
    reconnect_delay = 5
    max_reconnect_delay = 30
    connection_attempt = 0

    listener_redis = None
    pubsub = None

    CRITICAL_STAGES = {
        "initializing",
        "error",
        "completed",
        "validation_complete",
        "scan_complete",
        "reset",
    }

    while True:
        try:
            # Initialize or reinitialize Redis connection if needed
            if (
                listener_redis is None
                or pubsub is None
                or not hasattr(pubsub, "connection")
                or pubsub.connection is None
            ):
                connection_attempt += 1
                try:
                    logger.info("Initializing Redis pub/sub connection")
                    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
                    listener_redis = redis.from_url(
                        REDIS_URL,
                        decode_responses=True,
                        socket_timeout=10,
                        socket_connect_timeout=5,
                        socket_keepalive=True,
                        health_check_interval=30,
                        retry_on_timeout=True,
                    )

                    pubsub = listener_redis.pubsub(ignore_subscribe_messages=True)
                    pubsub.subscribe("scan_updates")

                    logger.info("Successfully subscribed to scan_updates channel")

                    connection_attempt = 0
                    reconnect_delay = 5

                    # Purge any old messages
                    while pubsub.get_message(timeout=0.1):
                        pass

                except Exception as e:
                    logger.error(f"Failed to initialize Redis connection: {str(e)}")
                    current_delay = min(
                        max_reconnect_delay,
                        reconnect_delay * (1.5 ** min(connection_attempt - 1, 5)),
                    )
                    logger.info(
                        f"Retrying in {current_delay:.1f} seconds (attempt {connection_attempt})"
                    )
                    time.sleep(current_delay)
                    continue

            try:
                message = pubsub.get_message(timeout=1.0)
            except redis.TimeoutError:
                time.sleep(0.1)
                continue
            except (redis.ConnectionError, ConnectionError) as e:
                logger.error(f"Redis connection error: {str(e)}")
                pubsub = None
                listener_redis = None
                time.sleep(reconnect_delay)
                continue

            if not message:
                if random.random() < 0.01:
                    try:
                        if listener_redis is not None:
                            listener_redis.ping()
                    except Exception as e:
                        logger.error(f"Redis health check failed: {str(e)}")
                        pubsub = None
                        listener_redis = None
                        time.sleep(1)
                time.sleep(0.01)
                continue

            if message and message["type"] == "message":
                try:
                    data = json.loads(message["data"])

                    scan_type = data.get("scan_type", "repository")
                    user_id = data.get("user_id")
                    resource_id = data.get("repo_name")
                    room = data.get("room")
                    progress_data = data.get("data", {})

                    is_completion = data.get("is_completion", False)
                    is_error = data.get("is_error", False)

                    # ENHANCED COMPLETION HANDLING WITH IMMEDIATE CLEANUP
                    if is_completion or is_error:
                        logger.info(
                            f"Processing {'completion' if is_completion else 'error'} message for {room}"
                        )

                        from progress_tracking import get_room_members

                        members = get_room_members(room)

                        # Broadcast to room
                        socketio.emit("progress_update", progress_data, room=room)
                        socketio.emit(
                            "scan_complete",
                            {
                                "status": "completed" if is_completion else "error",
                                "timestamp": int(time.time()),
                            },
                            room=room,
                        )

                        # Send directly to each client
                        for member in members:
                            try:
                                socketio.emit(
                                    "progress_update", progress_data, to=member
                                )
                                socketio.emit(
                                    "scan_complete",
                                    {
                                        "status": (
                                            "completed" if is_completion else "error"
                                        ),
                                        "direct": True,
                                        "timestamp": int(time.time()),
                                    },
                                    to=member,
                                )
                                logger.info(f"Sent direct completion to {member}")
                            except Exception as direct_err:
                                logger.error(
                                    f"Error sending direct message: {str(direct_err)}"
                                )

                            time.sleep(0.05)

                        # IMMEDIATE CLEANUP OF COMPLETED DATA
                        try:
                            cleanup_keys = [
                                f"scan_progress:{user_id}:{resource_id}",
                                f"scan_complete:{user_id}:{resource_id}",
                                f"current_scan:{user_id}:{resource_id}",
                            ]

                            for key in cleanup_keys:
                                listener_redis.delete(key)

                            logger.info(
                                f"Immediately cleaned up completion data for {user_id}:{resource_id}"
                            )

                        except Exception as cleanup_err:
                            logger.error(
                                f"Error in immediate cleanup: {str(cleanup_err)}"
                            )

                        logger.info(
                            f"Processed completion event for {len(members)} clients"
                        )
                    else:
                        # Regular progress update
                        socketio.emit("progress_update", progress_data, room=room)

                except Exception as e:
                    logger.error(f"Error processing message: {str(e)}")

            time.sleep(0.01)

        except Exception as e:
            logger.error(f"Redis listener error: {str(e)}")
            time.sleep(1)


def cleanup_room_after_delay(room, delay_seconds):
    """Clean up a room after a delay with improved approach."""
    socketio.sleep(delay_seconds)
    try:
        # When sending the completion message, use a special identifier
        completion_data = {
            "status": "completed",
            "timestamp": int(time.time()),
            "message_type": "final_completion",  # Add this identifier
        }

        # Send as a PROGRESS_UPDATE instead of a separate event type
        socketio.emit(
            "progress_update",
            {
                "s": "final_complete",
                "p": 100,
                "o": 100,
                "t": int(time.time()),
                "final": True,  # Add this flag
            },
            room=room,
        )

        # Now also send the original event
        socketio.emit("scan_complete", completion_data, room=room)

    except Exception as e:
        logger.error(f"Error during room cleanup: {str(e)}")


@socketio.on_error_default
def error_handler(e):
    """Global error handler with improved logging"""
    logger.error(f"SocketIO error: {str(e)}", exc_info=True)

    # Get the client's socket ID
    try:
        sid = request.sid
        logger.error(f"Error occurred for client {sid}")
    except:
        pass


@socketio.on("connect")
def handle_connect():
    """Handle client connection with reliable session tracking"""
    try:
        sid = request.sid
        # Create a more secure session tracking mechanism
        manage_session(sid, "add")
        cleanup_old_sessions()

        # Log the connection with more detail
        user_agent = request.headers.get("User-Agent", "Unknown")
        transport = getattr(request, "transport", "Unknown")
        logger.info(
            f"Client connected: {sid} | Transport: {transport} | UA: {user_agent[:50]}"
        )

        # Record connection timestamp in Redis
        redis_client = get_redis_client()
        redis_client.hset(f"socket:{sid}", "connected_at", int(time.time()))
        redis_client.expire(f"socket:{sid}", 3600)  # 1 hour expiration

        # Send connection acknowledgment with server timestamp for latency calculation
        emit(
            "connected",
            {
                "status": "connected",
                "sid": sid,
                "server_time": int(time.time() * 1000),  # milliseconds
            },
        )
    except Exception as e:
        logger.error(f"Connection error: {str(e)}", exc_info=True)
        return False


@socketio.on("disconnect")
def handle_disconnect(arg=None):
    """Handle client disconnection with proper cleanup"""
    try:
        sid = request.sid
        if sid:
            # Remove from session management
            manage_session(sid, "remove")

            # Get the client's subscriptions before removing them
            redis_client = get_redis_client()
            subscription_key = f"socket_subscription:{sid}"
            subscription_data = redis_client.hgetall(subscription_key)

            if subscription_data:
                room = subscription_data.get("room")
                logger.info(f"Client {sid} disconnected from room {room}")

                # Clean up subscription data
                from progress_tracking import unregister_socket_subscription

                unregister_socket_subscription(sid)
            else:
                logger.info(f"Client {sid} disconnected (no subscriptions)")

            # Remove connection record
            redis_client.delete(f"socket:{sid}")
    except Exception as e:
        logger.error(f"Disconnection error: {str(e)}", exc_info=True)


@socketio.on("ping_server")
def handle_ping(data=None):
    """Enhanced ping handler with latency tracking"""
    try:
        sid = request.sid
        client_time = data.get("time", 0) if isinstance(data, dict) else 0
        now = int(time.time() * 1000)  # milliseconds

        # Calculate latency if client provided a timestamp
        latency = None
        if client_time > 0:
            latency = now - client_time

        response = {"server_time": now, "sid": sid}

        if latency is not None:
            response["latency"] = latency

            # Log high latency values
            if latency > 500:  # 500ms threshold
                logger.warning(f"High latency ({latency}ms) detected for client {sid}")

        emit("pong_server", response)
    except Exception as e:
        logger.error(f"Ping/pong error: {str(e)}")


@socketio.on("subscribe_to_scan")
def handle_subscribe(data):
    """
    Enhanced repository scan subscription handler that avoids showing completed states.
    """
    try:
        sid = request.sid
        logger.info(f"Repository scan subscription request from {sid}: {data}")

        # Validate session
        if not manage_session(sid, "check"):
            logger.warning(f"Invalid session attempting to subscribe: {sid}")
            emit("error", {"message": "Invalid session"})
            return

        # Validate subscription data
        user_id = data.get("user_id")
        repo_name = data.get("repo_name")

        if not all([user_id, repo_name]):
            logger.warning(f"Invalid repository subscription request: {data}")
            emit("error", {"message": "Invalid subscription parameters"})
            return

        # AGGRESSIVE CLEANUP BEFORE SUBSCRIPTION
        from progress_tracking import aggressively_clear_scan_data

        aggressively_clear_scan_data(user_id, repo_name, "repository")

        # Create room name
        room = f"scan_{user_id}_{repo_name}"

        # Join the room
        join_room(room)
        logger.info(f"Client {sid} subscribed to repository scan room: {room}")

        # Register subscription in Redis
        from progress_tracking import register_socket_subscription

        register_socket_subscription(
            socket_id=sid,
            user_id=user_id,
            resource_id=repo_name,
            scan_type="repository",
        )

        # Send confirmation to client
        emit(
            "room_joined",
            {"room": room, "status": "subscribed", "timestamp": int(time.time())},
        )

        # Check for ACTIVE scan (avoiding completed states)
        from progress_tracking import get_scan_progress

        progress = get_scan_progress(user_id, repo_name)

        if progress:
            # There's an active, ongoing scan
            scan_id = progress.get("scan_id")
            stage = progress.get("stage", "unknown")
            stage_progress = progress.get("stage_progress", 0)
            overall_progress = progress.get("overall_progress", 0)
            timestamp = progress.get("unix_timestamp", int(time.time()))

            ws_data = {
                "s": stage,
                "p": stage_progress,
                "o": overall_progress,
                "t": timestamp,
                "id": scan_id,
            }

            emit("progress_update", ws_data)
            logger.info(
                f"Sent active scan progress to {sid}: {stage} at {overall_progress}%"
            )
        else:
            # No active scan - send waiting state
            emit(
                "scan_waiting",
                {"message": "Ready for scan to start", "timestamp": int(time.time())},
            )
            logger.info(f"No active scan for {repo_name}, client ready for new scan")

    except Exception as e:
        logger.error(f"Repository scan subscription error: {str(e)}", exc_info=True)
        emit("error", {"message": "Subscription failed, please try again"})


@socketio.on("subscribe_to_aws_scan")
def handle_aws_subscribe(data):
    """
    Enhanced AWS scan subscription handler that avoids showing completed states.
    """
    try:
        sid = request.sid
        user_id = data.get("user_id")
        account_id = data.get("account_id")

        if not all([user_id, account_id]):
            emit("error", {"message": "Invalid parameters"})
            return

        # AGGRESSIVE CLEANUP BEFORE SUBSCRIPTION
        from progress_tracking import aggressively_clear_scan_data

        aggressively_clear_scan_data(user_id, account_id, "aws")

        # Join the room
        room = f"aws_scan_{user_id}_{account_id}"
        join_room(room)
        logger.info(f"Client {sid} joined AWS scan room {room}")

        # Register subscription in Redis
        from progress_tracking import register_socket_subscription

        register_socket_subscription(
            socket_id=sid, user_id=user_id, resource_id=account_id, scan_type="aws"
        )

        # Send confirmation
        emit(
            "room_joined",
            {"room": room, "status": "subscribed", "timestamp": int(time.time())},
        )

        # Check for ACTIVE scan (avoiding completed states)
        from progress_tracking import get_scan_progress

        progress = get_scan_progress(user_id, account_id)

        if progress:
            # There's an active, ongoing scan
            try:
                emit(
                    "progress_update",
                    {
                        "s": progress.get("stage", "unknown"),
                        "p": progress.get("stage_progress", 0),
                        "o": progress.get("overall_progress", 0),
                        "t": progress.get("unix_timestamp", int(time.time())),
                        "id": progress.get("scan_id", "unknown"),
                    },
                )
                logger.info(
                    f"Sent current AWS progress to {sid}: {progress.get('stage')} ({progress.get('overall_progress')}%)"
                )
            except Exception as e:
                logger.error(f"Error sending AWS progress: {str(e)}")
        else:
            # No active scan - send waiting state
            emit(
                "scan_waiting",
                {
                    "message": "Ready for AWS scan to start",
                    "timestamp": int(time.time()),
                },
            )
            logger.info(
                f"No active AWS scan for {account_id}, client ready for new scan"
            )

    except Exception as e:
        logger.error(f"AWS subscription error: {str(e)}")
        emit("error", {"message": "AWS subscription failed"})


@socketio.on("subscribe_to_gitlab_scan")
def handle_gitlab_subscribe(data):
    """
    Enhanced GitLab scan subscription handler that avoids showing completed states.
    """
    try:
        sid = request.sid
        user_id = data.get("user_id")
        project_id = data.get("project_id")

        if not all([user_id, project_id]):
            emit("error", {"message": "Invalid parameters"})
            return

        # AGGRESSIVE CLEANUP BEFORE SUBSCRIPTION
        from progress_tracking import aggressively_clear_scan_data

        aggressively_clear_scan_data(user_id, project_id, "gitlab")

        # Join the room
        room = f"gitlab_scan_{user_id}_{project_id}"
        join_room(room)
        logger.info(f"Client {sid} joined GitLab scan room {room}")

        # Register subscription in Redis
        from progress_tracking import register_socket_subscription

        register_socket_subscription(
            socket_id=sid, user_id=user_id, resource_id=project_id, scan_type="gitlab"
        )

        # Send confirmation
        emit(
            "room_joined",
            {"room": room, "status": "subscribed", "timestamp": int(time.time())},
        )

        # Check for ACTIVE scan (avoiding completed states)
        from progress_tracking import get_scan_progress

        progress = get_scan_progress(user_id, project_id)

        if progress:
            # There's an active, ongoing scan
            try:
                emit(
                    "progress_update",
                    {
                        "s": progress.get("stage", "unknown"),
                        "p": progress.get("stage_progress", 0),
                        "o": progress.get("overall_progress", 0),
                        "t": progress.get("unix_timestamp", int(time.time())),
                        "id": progress.get("scan_id", "unknown"),
                    },
                )
                logger.info(
                    f"Sent current GitLab progress to {sid}: {progress.get('stage')} ({progress.get('overall_progress')}%)"
                )
            except Exception as e:
                logger.error(f"Error sending GitLab progress: {str(e)}")
        else:
            # No active scan - send waiting state
            emit(
                "scan_waiting",
                {
                    "message": "Ready for GitLab scan to start",
                    "timestamp": int(time.time()),
                },
            )
            logger.info(
                f"No active GitLab scan for {project_id}, client ready for new scan"
            )

    except Exception as e:
        logger.error(f"GitLab subscription error: {str(e)}")
        emit("error", {"message": "GitLab subscription failed"})


@socketio.on("subscribe_to_zap_scan")
def handle_zap_subscribe(data):
    """
    ZAP scan subscription handler
    """
    try:
        sid = request.sid
        user_id = data.get("user_id")
        target_url = data.get("target_url")

        if not all([user_id, target_url]):
            emit("error", {"message": "Invalid parameters"})
            return

        from zap_scan_tracker import get_zap_scan_progress

        from zap_scan_tracker import zap_tracker

        resource_id = zap_tracker._sanitize_target_id(target_url)
        room = f"zap_scan_{user_id}_{resource_id}"

        join_room(room)
        logger.info(f"Client {sid} joined ZAP scan room {room}")

        from progress_tracking import register_socket_subscription

        register_socket_subscription(
            socket_id=sid, user_id=user_id, resource_id=resource_id, scan_type="zap"
        )

        # Send confirmation
        emit(
            "room_joined",
            {
                "room": room,
                "status": "subscribed",
                "scan_type": "zap",
                "timestamp": int(time.time()),
            },
        )

        progress = get_zap_scan_progress(user_id, target_url)

        if progress:
            try:
                emit(
                    "progress_update",
                    {
                        "s": progress.get(
                            "display_stage", progress.get("stage", "unknown")
                        ),
                        "p": progress.get("stage_progress", 0),
                        "o": progress.get("overall_progress", 0),
                        "t": progress.get("unix_timestamp", int(time.time())),
                        "id": progress.get("scan_id", "unknown"),
                        "scan_type": "zap",
                        "target_url": progress.get("target_url", target_url),
                    },
                )
                logger.info(
                    f"Sent current ZAP progress to {sid}: {progress.get('stage')} ({progress.get('overall_progress')}%)"
                )
            except Exception as e:
                logger.error(f"Error sending ZAP progress: {str(e)}")
        else:
            emit(
                "scan_waiting",
                {
                    "message": "Ready for ZAP scan to start",
                    "scan_type": "zap",
                    "timestamp": int(time.time()),
                },
            )
            logger.info(
                f"No active ZAP scan for {target_url}, client ready for new scan"
            )

    except Exception as e:
        logger.error(f"ZAP subscription error: {str(e)}")
        emit("error", {"message": "ZAP subscription failed"})


def initiate_new_scan(
    user_id: str, resource_id: str, scan_type: str = "repository"
) -> str:
    """
    Helper function to properly initiate a new scan with cleanup and unique ID generation.

    Args:
        user_id: User ID
        resource_id: Resource ID (repo name, account ID, etc.)
        scan_type: Type of scan ('repository', 'aws', 'gitlab')

    Returns:
        str: New scan ID
    """
    try:
        from progress_tracking import start_new_scan, update_scan_progress
        import uuid

        # Start new scan with cleanup and unique ID
        scan_id = start_new_scan(user_id, resource_id, scan_type)

        # Send initial progress update
        update_scan_progress(
            user_id=user_id,
            repo_name=resource_id,
            stage="initializing",
            progress=0,
            scan_type=scan_type,
            scan_id=scan_id,
        )

        logger.info(
            f"Initiated new {scan_type} scan {scan_id} for {user_id}:{resource_id}"
        )
        return scan_id

    except Exception as e:
        logger.error(f"Error initiating new scan: {str(e)}")
        # Return a fallback unique ID
        import uuid

        return f"scan_{int(time.time() * 1000)}_{str(uuid.uuid4())[:8]}"


# Start Redis listener in background
redis_listener_thread = Thread(target=redis_listener, daemon=True)
redis_listener_thread.start()


@app.route("/health")
def health_check():
    try:
        # Test database connection
        with app.app_context():
            db.session.execute(text("SELECT 1"))
            db.session.commit()

        # Test Redis connection
        redis_client.ping()

        return jsonify(
            {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "database": "connected",
                "redis": "connected",
                "database_url": DATABASE_URL is not None,
                "redis_url": REDIS_URL is not None,
                "git_integration": (
                    "initialized"
                    if "git_integration" in globals()
                    else "not initialized"
                ),
            }
        )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return (
            jsonify(
                {
                    "status": "unhealthy",
                    "timestamp": datetime.utcnow().isoformat(),
                    "error": str(e),
                }
            ),
            500,
        )


@app.route("/api/v1/debug/schema", methods=["GET"])
def debug_schema():
    try:
        result = db.session.execute(
            text(
                """
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name='cloud_scans'
            ORDER BY ordinal_position;
        """
            )
        )

        columns = [{"name": row.column_name, "type": row.data_type} for row in result]

        return jsonify({"table": "cloud_scans", "columns": columns})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/v1/debug/add-columns", methods=["POST"])
def add_columns_endpoint():
    try:
        with app.app_context():
            # Check if completed_at column exists
            result = db.session.execute(
                text(
                    """
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='cloud_scans' AND column_name='completed_at'
            """
                )
            )
            completed_at_exists = bool(result.scalar())

            # Check if error column exists
            result = db.session.execute(
                text(
                    """
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='cloud_scans' AND column_name='error'
            """
                )
            )
            error_exists = bool(result.scalar())

            # Add columns if they don't exist
            changes_made = False

            if not completed_at_exists:
                db.session.execute(
                    text(
                        """
                    ALTER TABLE cloud_scans 
                    ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP
                """
                    )
                )
                db.session.commit()
                changes_made = True

            if not error_exists:
                db.session.execute(
                    text(
                        """
                    ALTER TABLE cloud_scans 
                    ADD COLUMN IF NOT EXISTS error TEXT
                """
                    )
                )
                db.session.commit()
                changes_made = True

            # Check schema after changes
            result = db.session.execute(
                text(
                    """
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name='cloud_scans'
                ORDER BY ordinal_position
            """
                )
            )

            columns = [row.column_name for row in result]

            return jsonify(
                {
                    "success": True,
                    "changes_made": changes_made,
                    "before": {
                        "completed_at_exists": completed_at_exists,
                        "error_exists": error_exists,
                    },
                    "after": {
                        "completed_at_exists": "completed_at" in columns,
                        "error_exists": "error" in columns,
                    },
                    "columns": columns,
                }
            )
    except Exception as e:
        return (
            jsonify(
                {"success": False, "error": str(e), "traceback": traceback.format_exc()}
            ),
            500,
        )


@app.route("/emergency/rds-info")
def emergency_rds_info():
    """Check RDS connection limits"""
    try:
        with db.engine.connect() as conn:
            result = conn.execute(
                text(
                    """
                SELECT 
                    setting as max_connections
                FROM pg_settings 
                WHERE name = 'max_connections'
            """
                )
            )
            max_conn = result.scalar()

            result = conn.execute(
                text(
                    """
                SELECT 
                    count(*) as total_connections,
                    count(*) FILTER (WHERE state = 'active') as active,
                    count(*) FILTER (WHERE state = 'idle') as idle,
                    count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction
                FROM pg_stat_activity 
            """
                )
            )

            row = result.fetchone()

            return jsonify(
                {
                    "max_connections": int(max_conn),
                    "current_total": row[0],
                    "active": row[1],
                    "idle": row[2],
                    "idle_in_transaction": row[3],
                    "percentage_used": round((row[0] / int(max_conn)) * 100, 2),
                    "recommendation": (
                        "INCREASE max_connections"
                        if int(max_conn) < 100
                        else "Connection management issue"
                    ),
                }
            )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/emergency/db-status")
def emergency_db_status():
    """Emergency endpoint to check database status"""
    try:
        with db.engine.connect() as conn:
            # Check current connections
            result = conn.execute(
                text(
                    """
                SELECT 
                    count(*) as total_connections,
                    count(*) FILTER (WHERE state = 'active') as active_connections,
                    count(*) FILTER (WHERE state = 'idle') as idle_connections
                FROM pg_stat_activity 
                WHERE datname = current_database()
            """
                )
            )

            row = result.fetchone()

            # Check max connections
            max_conn_result = conn.execute(text("SHOW max_connections"))
            max_connections = max_conn_result.scalar()

            return jsonify(
                {
                    "status": "connected",
                    "total_connections": row[0] if row else 0,
                    "active_connections": row[1] if row else 0,
                    "idle_connections": row[2] if row else 0,
                    "max_connections": max_connections,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            500,
        )


@app.route("/emergency/kill-idle-connections", methods=["POST"])
def emergency_kill_idle_connections():
    """Emergency endpoint to kill idle connections"""
    try:
        with db.engine.connect() as conn:
            # Kill idle connections older than 5 minutes
            result = conn.execute(
                text(
                    """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity 
                WHERE datname = current_database()
                AND state = 'idle'
                AND state_change < now() - interval '5 minutes'
                AND pid != pg_backend_pid()
            """
                )
            )

            killed_count = len(result.fetchall())

            return jsonify(
                {
                    "status": "success",
                    "killed_connections": killed_count,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            500,
        )


def format_private_key(key_data):
    """Format the private key correctly for GitHub integration"""
    try:
        if not key_data:
            raise ValueError("Private key is empty")

        key_data = key_data.strip()

        if "\\n" in key_data:
            parts = key_data.split("\\n")
            key_data = "\n".join(part.strip() for part in parts if part.strip())
        elif "\n" not in key_data:
            key_length = len(key_data)
            if key_length < 64:
                raise ValueError("Key content too short")

            if not key_data.startswith("-----BEGIN"):
                key_data = (
                    "-----BEGIN RSA PRIVATE KEY-----\n"
                    + "\n".join(
                        key_data[i : i + 64] for i in range(0, len(key_data), 64)
                    )
                    + "\n-----END RSA PRIVATE KEY-----"
                )

        if not key_data.startswith("-----BEGIN RSA PRIVATE KEY-----"):
            key_data = "-----BEGIN RSA PRIVATE KEY-----\n" + key_data
        if not key_data.endswith("-----END RSA PRIVATE KEY-----"):
            key_data = key_data + "\n-----END RSA PRIVATE KEY-----"

        lines = key_data.split("\n")
        if len(lines) < 3:
            raise ValueError("Invalid key format - too few lines")

        logger.info("Private key formatted successfully")
        return key_data

    except Exception as e:
        logger.error(f"Error formatting private key: {str(e)}")
        raise ValueError(f"Private key formatting failed: {str(e)}")


def verify_webhook_signature(request_data, signature_header):
    """
    Enhanced webhook signature verification for GitHub webhooks
    """
    try:
        webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")

        logger.info("Starting webhook signature verification")

        if not webhook_secret:
            logger.error("GITHUB_WEBHOOK_SECRET environment variable is not set")
            return False

        if not signature_header:
            logger.error("No X-Hub-Signature-256 header received")
            return False

        if not signature_header.startswith("sha256="):
            logger.error("Signature header doesn't start with sha256=")
            return False

        # Get the raw signature without 'sha256=' prefix
        received_signature = signature_header.replace("sha256=", "")

        # Ensure webhook_secret is bytes
        if isinstance(webhook_secret, str):
            webhook_secret = webhook_secret.strip().encode("utf-8")

        # Ensure request_data is bytes
        if isinstance(request_data, str):
            request_data = request_data.encode("utf-8")

        # Calculate expected signature
        mac = hmac.new(webhook_secret, msg=request_data, digestmod=hashlib.sha256)
        expected_signature = mac.hexdigest()

        # Debug logging
        logger.debug("Signature Details:")
        logger.debug(f"Request Data Length: {len(request_data)} bytes")
        logger.debug(f"Secret Key Length: {len(webhook_secret)} bytes")
        logger.debug(f"Raw Request Data: {request_data[:100]}...")  # First 100 bytes
        logger.debug(f"Received Header: {signature_header}")
        logger.debug(f"Calculated HMAC: sha256={expected_signature}")

        # Use constant time comparison
        is_valid = hmac.compare_digest(expected_signature, received_signature)

        if not is_valid:
            logger.error("Signature mismatch detected")
            logger.error(f"Header format: {signature_header}")
            logger.error(f"Received signature: {received_signature[:10]}...")
            logger.error(f"Expected signature: {expected_signature[:10]}...")

            # Additional debug info
            if os.getenv("FLASK_ENV") != "production":
                logger.debug("Full signature comparison:")
                logger.debug(f"Full received: {received_signature}")
                logger.debug(f"Full expected: {expected_signature}")
        else:
            logger.info("Webhook signature verified successfully")

        return is_valid

    except Exception as e:
        logger.error(f"Signature verification failed: {str(e)}")
        logger.error(traceback.format_exc())
        return False


@app.route("/debug/test-webhook", methods=["POST"])
def test_webhook():
    """Test endpoint to verify webhook signatures"""
    if os.getenv("FLASK_ENV") != "production":
        try:
            webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET")
            raw_data = request.get_data()
            received_signature = request.headers.get("X-Hub-Signature-256")

            # Test with the exact data received
            result = verify_webhook_signature(raw_data, received_signature)

            # Calculate signature for debugging
            mac = hmac.new(
                (
                    webhook_secret.encode("utf-8")
                    if isinstance(webhook_secret, str)
                    else webhook_secret
                ),
                msg=raw_data,
                digestmod=hashlib.sha256,
            )
            expected_signature = f"sha256={mac.hexdigest()}"

            return jsonify(
                {
                    "webhook_secret_configured": bool(webhook_secret),
                    "webhook_secret_length": (
                        len(webhook_secret) if webhook_secret else 0
                    ),
                    "received_signature": received_signature,
                    "expected_signature": expected_signature,
                    "payload_size": len(raw_data),
                    "signatures_match": result,
                    "raw_data_preview": (
                        raw_data.decode("utf-8")[:100] if raw_data else None
                    ),
                }
            )
        except Exception as e:
            return jsonify({"error": str(e)})
    return jsonify({"message": "Not available in production"}), 403


def clean_directory(directory):
    """Safely remove a directory"""
    try:
        if os.path.exists(directory):
            shutil.rmtree(directory)
    except Exception as e:
        logger.error(f"Error cleaning directory {directory}: {str(e)}")


def trigger_semgrep_analysis(repo_url, installation_token, user_id):
    """Run Semgrep analysis with enhanced error handling"""
    clone_dir = None
    repo_name = repo_url.split("github.com/")[-1].replace(".git", "")

    try:
        repo_url_with_auth = (
            f"https://x-access-token:{installation_token}@github.com/{repo_name}.git"
        )
        clone_dir = f"/tmp/semgrep_{repo_name.replace('/', '_')}_{os.getpid()}"

        # Create initial database entry
        analysis = AnalysisResult(
            repository_name=repo_name, user_id=user_id, status="in_progress"
        )
        db.session.add(analysis)
        db.session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}")

        # Clean directory first
        clean_directory(clone_dir)
        logger.info(f"Cloning repository to {clone_dir}")

        # Enhanced clone command with detailed error capture
        try:
            # First verify the repository exists and is accessible
            test_url = f"https://api.github.com/repos/{repo_name}"
            headers = {
                "Authorization": f"Bearer {installation_token}",
                "Accept": "application/vnd.github.v3+json",
            }

            logger.info(f"Verifying repository access: {test_url}")

            response = requests.get(test_url, headers=headers)
            if response.status_code != 200:
                raise ValueError(
                    f"Repository verification failed: {response.status_code} - {response.text}"
                )

            # Clone with more detailed error output
            #  depth=2 to get the current commit and its parent diff support
            clone_result = subprocess.run(
                ["git", "clone", "--depth", "2", repo_url_with_auth, clone_dir],
                capture_output=True,
                text=True,
            )

            if clone_result.returncode != 0:
                error_msg = (
                    f"Git clone failed with return code {clone_result.returncode}\n"
                    f"STDERR: {clone_result.stderr}\n"
                    f"STDOUT: {clone_result.stdout}"
                )
                logger.error(error_msg)
                raise Exception(error_msg)

            logger.info(f"Repository cloned successfully: {repo_name}")

            # Run semgrep analysis
            semgrep_cmd = ["semgrep", "--config=auto", "--json", "."]
            logger.info(f"Running semgrep with command: {' '.join(semgrep_cmd)}")

            semgrep_process = subprocess.run(
                semgrep_cmd, capture_output=True, text=True, check=True, cwd=clone_dir
            )

            try:
                semgrep_output = json.loads(semgrep_process.stdout)
                analysis.status = "completed"
                analysis.results = semgrep_output
                db.session.commit()

                logger.info(f"Semgrep analysis completed successfully for {repo_name}")
                return semgrep_process.stdout

            except json.JSONDecodeError as e:
                error_msg = f"Failed to parse Semgrep output: {str(e)}"
                logger.error(error_msg)
                analysis.status = "failed"
                analysis.error = error_msg
                db.session.commit()
                return None

        except subprocess.CalledProcessError as e:
            error_msg = (
                f"Command '{' '.join(e.cmd)}' failed with return code {e.returncode}\n"
                f"STDERR: {e.stderr}\n"
                f"STDOUT: {e.stdout}"
            )
            logger.error(error_msg)
            if "analysis" in locals():
                analysis.status = "failed"
                analysis.error = error_msg
                db.session.commit()
            raise Exception(error_msg)

    except Exception as e:
        logger.error(f"Analysis error for {repo_name}: {str(e)}")
        if "analysis" in locals():
            analysis.status = "failed"
            analysis.error = str(e)
            db.session.commit()
        return None

    finally:
        if clone_dir:
            clean_directory(clone_dir)


def format_semgrep_results(raw_results):
    """Format Semgrep results for frontend"""
    try:
        # Handle string input
        if isinstance(raw_results, str):
            try:
                results = json.loads(raw_results)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse JSON results: {str(e)}")
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
                    "errors": [f"Failed to parse results: {str(e)}"],
                    "severity_counts": {},
                    "category_counts": {},
                }
        else:
            results = raw_results

        if not isinstance(results, dict):
            raise ValueError(
                f"Invalid results format: expected dict, got {type(results)}"
            )

        formatted_response = {
            "summary": {
                "total_files_scanned": len(results.get("paths", {}).get("scanned", [])),
                "total_findings": len(results.get("results", [])),
                "files_scanned": results.get("paths", {}).get("scanned", []),
                "semgrep_version": results.get("version", "unknown"),
                "scan_status": (
                    "success" if not results.get("errors") else "completed_with_errors"
                ),
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
            "errors": results.get("errors", []),
        }

        for finding in results.get("results", []):
            try:
                severity = finding.get("extra", {}).get("severity", "INFO")
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
