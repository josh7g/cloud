"""
Enhanced progress tracking module with improved WebSocket communication
and aggressive cleanup of completed scan data.
"""

import time
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any
from progress_utils import calculate_overall_progress
import redis
import os
import traceback
import uuid

logger = logging.getLogger(__name__)

# Get Redis client from a centralized location
def get_redis_client():
    """Get or create Redis client singleton"""
    REDIS_URL = os.getenv('REDIS_URL')
    
    if not hasattr(get_redis_client, "client"):
        get_redis_client.client = redis.from_url(
            REDIS_URL,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30,
            retry_on_timeout=True
        )
    
    return get_redis_client.client

def generate_unique_scan_id() -> str:
    """
    Generate a unique scan ID based on timestamp and UUID to ensure no collisions.
    
    Returns:
        str: Unique scan ID
    """
    timestamp = int(time.time() * 1000)  # milliseconds for more uniqueness
    unique_suffix = str(uuid.uuid4())[:8]  # Short UUID suffix
    scan_id = f"scan_{timestamp}_{unique_suffix}"
    
    logger.info(f"Generated unique scan ID: {scan_id}")
    return scan_id

def aggressively_clear_scan_data(user_id: str, resource_id: str, scan_type: str = 'repository') -> None:
    """
    Aggressively clear ALL existing scan data before starting a new scan.
    
    Args:
        user_id: User ID
        resource_id: Resource ID (repo name, account ID, etc.)
        scan_type: Type of scan ('repository', 'aws', 'gitlab')
    """
    try:
        redis_client = get_redis_client()
        
        # Define all possible keys that might exist for this resource
        keys_to_clear = [
            f"scan_progress:{user_id}:{resource_id}",
            f"scan_complete:{user_id}:{resource_id}",
            f"current_scan:{user_id}:{resource_id}",
            f"active_scans:{user_id}",
        ]
        
        # Also clear any scan-specific data by scanning for patterns
        pattern_keys = [
            f"scan_timestamp:*",
            f"scan_history:*",
        ]
        
        # Clear direct keys
        for key in keys_to_clear:
            try:
                redis_client.delete(key)
            except Exception as e:
                logger.warning(f"Error deleting key {key}: {str(e)}")
        
        # Scan and clear pattern-based keys (with safety limit)
        for pattern in pattern_keys:
            try:
                matching_keys = redis_client.keys(pattern)
                if matching_keys:
                    # Safety check: don't delete too many keys at once
                    if len(matching_keys) > 1000:
                        logger.warning(f"Too many keys matching {pattern}, skipping bulk delete")
                        continue
                    
                    for key in matching_keys:
                        redis_client.delete(key)
            except Exception as e:
                logger.warning(f"Error clearing pattern {pattern}: {str(e)}")
        
        # Remove from active scans set
        active_scans_key = f"active_scans:{user_id}"
        redis_client.srem(active_scans_key, f"{scan_type}:{resource_id}")
        
        # Send reset message to any connected clients
        if scan_type == 'aws':
            room = f"aws_scan_{user_id}_{resource_id}"
        elif scan_type == 'gitlab':
            room = f"gitlab_scan_{user_id}_{resource_id}"
        else:
            room = f"scan_{user_id}_{resource_id}"
        
        reset_data = {
            's': 'reset',
            'p': 0,
            'o': 0,
            't': int(time.time()),
            'id': 'clearing'
        }
        
        # Publish reset message
        redis_client.publish(
            'scan_updates',
            json.dumps({
                'user_id': user_id,
                'repo_name': resource_id,
                'data': reset_data,
                'scan_type': 'reset',
                'room': room
            })
        )
        
        logger.info(f"Aggressively cleared all scan data for {user_id}:{resource_id} ({scan_type})")
        
    except Exception as e:
        logger.error(f"Error during aggressive scan data clearing: {str(e)}")
        logger.error(traceback.format_exc())

def update_scan_progress(user_id: str, repo_name: str, stage: str, progress: float, 
                        token: Optional[str] = None, scan_type: str = 'repository',
                        scan_id: Optional[str] = None) -> bool:
    """
    Update scan progress with unique scan IDs and immediate cleanup of completed scans.
    
    Args:
        user_id: User ID
        repo_name: Repository name, project ID, or account ID
        stage: Current stage of the scan
        progress: Progress percentage (0-100)
        token: Optional token
        scan_type: Type of scan ('repository', 'aws', or 'gitlab')
        scan_id: Optional scan ID (will generate unique ID if not provided)
        
    Returns:
        bool: Success status
    """
    try:
        if not all([user_id, repo_name, stage]):
            logger.warning("Invalid progress update parameters")
            return False

        # Generate unique scan ID if not provided
        if not scan_id:
            scan_id = generate_unique_scan_id()
        
        # Create a unique key for this scan
        key = f"scan_progress:{user_id}:{repo_name}"
        
        stage = stage[:50]  # Truncate long stage names
        progress = round(max(0, min(100, progress)))  # Ensure progress is between 0-100
        
        redis_client = get_redis_client()
        
        # Get previous progress data to maintain continuity
        previous_overall = None
        
        try:
            prev_data_str = redis_client.get(key)
            if prev_data_str:
                prev_data = json.loads(prev_data_str)
                previous_overall = prev_data.get('overall_progress', 0)
        except Exception as pe:
            logger.error(f"Error reading previous progress: {str(pe)}")
        
        # Calculate overall progress based on stage progression
        # Early stages move quickly to ~9%, then analyzing does the bulk of work
        stage_weights = {
            'initializing': 0.03,   # 3%
            'validating': 0.03,     # 3%  
            'cloning': 0.03,        # 3%
            'analyzing': 0.74,      # 74% (6-80%)
            'processing': 0.15,     # 15% (80-95%)
            'reranking': 0.02,      # 2%  (95-98%)
            'completed': 1.0,       # 100%
            'error': 1.0            # 100%
        }
        
        # Calculate overall progress
        overall_progress = progress
        
        # Always ensure we don't go backwards (unless it's a new scan)
        if previous_overall is not None and stage not in ['completed', 'error']:
            overall_progress = max(overall_progress, previous_overall)
            
        # For completion and error, always set to 100%
        if stage in ['completed', 'error']:
            overall_progress = 100
            progress = 100
        
        # Store the progress data as JSON
        progress_data = {
            'stage': stage,
            'stage_progress': progress,
            'overall_progress': overall_progress,
            'timestamp': datetime.utcnow().isoformat(),
            'unix_timestamp': int(time.time()),
            'scan_id': scan_id
        }
        
        # Create room name based on scan type
        if scan_type == 'aws':
            room = f"aws_scan_{user_id}_{repo_name}"
        elif scan_type == 'gitlab':
            room = f"gitlab_scan_{user_id}_{repo_name}"
        else:
            room = f"scan_{user_id}_{repo_name}"
        
        # WebSocket data format
        ws_data = {
            's': stage,
            'p': progress,
            'o': overall_progress,
            't': int(time.time()),
            'id': scan_id
        }
        
        # SPECIAL HANDLING FOR COMPLETION WITH IMMEDIATE CLEANUP
        if stage == 'completed':
            # 1. Store completion with VERY short TTL (5 seconds)
            completion_key = f"scan_complete:{user_id}:{repo_name}"
            redis_client.set(completion_key, json.dumps({
                'complete': True,
                'timestamp': int(time.time()),
                'scan_id': scan_id
            }), ex=5)  # 5 seconds TTL
            
            # 2. Store progress data with very short TTL
            redis_client.set(key, json.dumps(progress_data), ex=5)  # 5 seconds TTL
            
            # 3. Send completion event with multiple delivery attempts
            message_data = {
                'user_id': user_id,
                'repo_name': repo_name,
                'data': ws_data,
                'scan_type': scan_type,
                'room': room,
                'is_completion': True
            }
            
            # Send completion message 3 times with delays
            for attempt in range(3):
                redis_client.publish('scan_updates', json.dumps(message_data))
                logger.info(f"Completion delivery attempt {attempt + 1}/3: User={user_id}, Repo={repo_name}")
                if attempt < 2:  # Don't sleep after last attempt
                    time.sleep(0.2)
            
            # 4. Publish to dedicated completion channel
            redis_client.publish('scan_completions', json.dumps({
                'user_id': user_id,
                'repo_name': repo_name,
                'room': room,
                'scan_id': scan_id,
                'timestamp': int(time.time())
            }))
            
            # 5. Schedule immediate cleanup (asynchronous)
            def cleanup_completed_scan():
                time.sleep(5)  # Wait for TTL to expire
                try:
                    # Delete any remaining traces
                    redis_client.delete(key)
                    redis_client.delete(completion_key)
                    redis_client.delete(f"scan_timestamp:{scan_id}")
                    redis_client.delete(f"scan_history:{scan_id}")
                    logger.info(f"Cleaned up completed scan data for {scan_id}")
                except Exception as e:
                    logger.error(f"Error in cleanup: {str(e)}")
            
            # Start cleanup in background (you might want to use a proper task queue)
            import threading
            cleanup_thread = threading.Thread(target=cleanup_completed_scan, daemon=True)
            cleanup_thread.start()
            
            return True
            
        elif stage == 'error':
            # Similar handling for error state with immediate cleanup
            completion_key = f"scan_complete:{user_id}:{repo_name}"
            redis_client.set(completion_key, json.dumps({
                'error': True,
                'timestamp': int(time.time()),
                'scan_id': scan_id
            }), ex=5)  # 5 seconds TTL
            
            redis_client.set(key, json.dumps(progress_data), ex=5)  # 5 seconds TTL
            
            # Send error event with multiple attempts
            message_data = {
                'user_id': user_id,
                'repo_name': repo_name,
                'data': ws_data,
                'scan_type': scan_type,
                'room': room,
                'is_error': True
            }
            
            # Send twice with delay
            redis_client.publish('scan_updates', json.dumps(message_data))
            time.sleep(0.2)
            redis_client.publish('scan_updates', json.dumps(message_data))
            
            return True
        else:
            # Regular progress update with longer TTL
            redis_client.set(key, json.dumps(progress_data), ex=300)  # 5 minutes TTL
            
            # Store scan history for debugging
            history_key = f"scan_history:{scan_id}"
            redis_client.rpush(history_key, json.dumps({
                'timestamp': int(time.time()),
                'stage': stage,
                'progress': progress,
                'overall': overall_progress
            }))
            redis_client.expire(history_key, 300)  # 5 minutes expiration
            
            # Publish the update
            message_data = {
                'user_id': user_id,
                'repo_name': repo_name,
                'data': ws_data,
                'scan_type': scan_type,
                'room': room
            }
            
            redis_client.publish('scan_updates', json.dumps(message_data))
            logger.info(f"Progress update: User={user_id}, Repo={repo_name}, Stage={stage}, " 
                        f"Progress={progress}%, Overall={overall_progress}%")
            
            return True
        
    except Exception as e:
        logger.error(f"Error updating progress: {str(e)}")
        logger.error(traceback.format_exc())
        return False

def get_scan_progress(user_id: str, repo_name: str) -> Optional[dict]:
    """
    Get current scan progress, specifically avoiding completed states for new subscriptions.
    
    Args:
        user_id: User ID
        repo_name: Repository name or account ID
        
    Returns:
        Optional[dict]: Progress data (None if completed or not found)
    """
    try:
        key = f"scan_progress:{user_id}:{repo_name}"
        redis_client = get_redis_client()
        
        # Get progress data
        progress_data_str = redis_client.get(key)
        if not progress_data_str:
            return None
            
        progress_data = json.loads(progress_data_str)
        
        # SPECIFICALLY AVOID RETURNING COMPLETED STATES
        stage = progress_data.get('stage', '')
        if stage in ['completed', 'error']:
            logger.info(f"Ignoring completed/error state for subscription: {user_id}:{repo_name}")
            return None
        
        # Only return if it's an active, ongoing scan
        scan_id = progress_data.get('scan_id')
        if scan_id:
            # Check if scan is recent (within last 10 minutes)
            scan_timestamp = progress_data.get('unix_timestamp', 0)
            current_time = int(time.time())
            
            if current_time - scan_timestamp > 600:  # 10 minutes
                logger.info(f"Scan too old, not returning: {user_id}:{repo_name}")
                return None
        
        return progress_data
        
    except Exception as e:
        logger.error(f"Error getting progress: {str(e)}")
        return None

def clear_scan_progress(user_id: str, repo_name: str, scan_type: str = 'repository') -> bool:
    """
    Clear scan progress and aggressively clean all related data.
    
    Args:
        user_id: User ID
        repo_name: Repository name or account ID
        scan_type: Type of scan
        
    Returns:
        bool: Success status
    """
    try:
        if not all([user_id, repo_name]):
            logger.warning("Invalid parameters for clearing scan progress")
            return False
        
        # Use the aggressive cleanup function
        aggressively_clear_scan_data(user_id, repo_name, scan_type)
        
        return True
    except Exception as e:
        logger.error(f"Error clearing scan progress: {str(e)}")
        return False

def start_new_scan(user_id: str, resource_id: str, scan_type: str = 'repository') -> str:
    """
    Start a new scan with proper cleanup and unique ID generation.
    
    Args:
        user_id: User ID
        resource_id: Resource ID (repo name, account ID, etc.)
        scan_type: Type of scan ('repository', 'aws', 'gitlab')
        
    Returns:
        str: New scan ID
    """
    try:
        # Step 1: Aggressively clear all existing data
        aggressively_clear_scan_data(user_id, resource_id, scan_type)
        
        # Step 2: Generate new unique scan ID
        scan_id = generate_unique_scan_id()
        
        # Step 3: Store the new scan ID mapping
        redis_client = get_redis_client()
        scan_key = f"current_scan:{user_id}:{resource_id}"
        redis_client.set(scan_key, scan_id, ex=3600)  # 1 hour expiration
        
        # Step 4: Store scan timestamp
        redis_client.set(f"scan_timestamp:{scan_id}", int(time.time()), ex=3600)
        
        # Step 5: Add to active scans
        active_scans_key = f"active_scans:{user_id}"
        redis_client.sadd(active_scans_key, f"{scan_type}:{resource_id}")
        redis_client.expire(active_scans_key, 3600)
        
        logger.info(f"Started new scan {scan_id} for {user_id}:{resource_id} ({scan_type})")
        return scan_id
        
    except Exception as e:
        logger.error(f"Error starting new scan: {str(e)}")
        return generate_unique_scan_id()  # Fallback

def register_socket_subscription(socket_id: str, user_id: str, resource_id: str, 
                               scan_type: str = 'repository') -> bool:
    """
    Register a socket subscription in Redis for reliability.
    
    Args:
        socket_id: Socket ID
        user_id: User ID
        resource_id: Resource ID (repo name or account ID)
        scan_type: Type of scan ('repository', 'aws', or 'gitlab')
        
    Returns:
        bool: Success status
    """
    try:
        if scan_type == 'aws':
            room = f"aws_scan_{user_id}_{resource_id}"
        elif scan_type == 'gitlab':
            room = f"gitlab_scan_{user_id}_{resource_id}"
        else:
            room = f"scan_{user_id}_{resource_id}"
            
        redis_client = get_redis_client()
        
        # Store subscription data with 1-hour expiration
        subscription_key = f"socket_subscription:{socket_id}"
        redis_client.hmset(subscription_key, {
            'user_id': user_id,
            'resource_id': resource_id,
            'room': room,
            'scan_type': scan_type,
            'timestamp': int(time.time())
        })
        redis_client.expire(subscription_key, 3600)
        
        # Also track all sockets in a room
        room_key = f"room_members:{room}"
        redis_client.sadd(room_key, socket_id)
        redis_client.expire(room_key, 3600)
        
        logger.info(f"Registered socket {socket_id} subscription to {room}")
        return True
    except Exception as e:
        logger.error(f"Error registering socket subscription: {str(e)}")
        return False

def unregister_socket_subscription(socket_id: str) -> bool:
    """
    Unregister a socket subscription from Redis.
    
    Args:
        socket_id: Socket ID
        
    Returns:
        bool: Success status
    """
    try:
        redis_client = get_redis_client()
        
        # Get subscription data
        subscription_key = f"socket_subscription:{socket_id}"
        subscription = redis_client.hgetall(subscription_key)
        
        if subscription:
            # Get room
            room = subscription.get('room')
            
            if room:
                # Remove from room members
                room_key = f"room_members:{room}"
                redis_client.srem(room_key, socket_id)
                
            # Delete subscription
            redis_client.delete(subscription_key)
            
            logger.info(f"Unregistered socket {socket_id} subscription")
            return True
            
        return False
    except Exception as e:
        logger.error(f"Error unregistering socket subscription: {str(e)}")
        return False

def get_room_members(room: str) -> list:
    """
    Get all socket IDs that are members of a room.
    
    Args:
        room: Room name
        
    Returns:
        list: Socket IDs
    """
    try:
        redis_client = get_redis_client()
        room_key = f"room_members:{room}"
        members = redis_client.smembers(room_key)
        
        return list(members)
    except Exception as e:
        logger.error(f"Error getting room members: {str(e)}")
        return []