"""
Server-Sent Events (SSE) Progress Streaming
Replacement for WebSocket-based progress tracking
"""
from flask import Blueprint, Response, stream_with_context
import json
import logging
import time
from progress_tracking import get_redis_client

logger = logging.getLogger(__name__)

sse_bp = Blueprint("sse", __name__, url_prefix="/api/v1/sse")


def format_sse_message(data: dict) -> str:
    """Format data as SSE message"""
    return f"data: {json.dumps(data)}\n\n"


@sse_bp.route("/scan/<user_id>/<repo_name>")
def stream_scan_progress(user_id, repo_name):
    """
    Stream scan progress updates using Server-Sent Events.
    
    Each scan gets its own dedicated stream that automatically closes
    when the scan completes or errors.
    
    Usage from frontend:
        const eventSource = new EventSource(`/api/v1/sse/scan/${userId}/${repoName}`);
        eventSource.onmessage = (event) => {
            const progress = JSON.parse(event.data);
            updateProgressBar(progress.o); // overall progress
        };
    """
    @stream_with_context
    def generate():
        redis_client = None
        pubsub = None
        
        try:
            # Connect to Redis
            redis_client = get_redis_client()
            pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
            
            # Subscribe to this specific scan's channel
            channel = f'scan_progress_{user_id}_{repo_name}'
            pubsub.subscribe('scan_updates')
            
            logger.info(f"SSE stream started for {user_id}/{repo_name}")
            
            # Send initial connection message
            yield format_sse_message({
                'type': 'connected',
                'user_id': user_id,
                'repo_name': repo_name,
                'timestamp': int(time.time())
            })
            
            # Listen for updates
            while True:
                message = pubsub.get_message(timeout=30.0)
                
                if message and message['type'] == 'message':
                    try:
                        data = json.loads(message['data'])
                        
                        # Only send if this message is for this scan
                        msg_user_id = data.get('user_id')
                        msg_repo = data.get('repo_name')
                        
                        if msg_user_id == user_id and msg_repo == repo_name:
                            progress_data = data.get('data', {})
                            stage = progress_data.get('s', '')
                            
                            # Send the progress update
                            yield format_sse_message(progress_data)
                            
                            # Close stream if scan completed or errored
                            if stage in ['completed', 'error']:
                                logger.info(f"SSE stream ending for {user_id}/{repo_name} - {stage}")
                                yield format_sse_message({
                                    'type': 'stream_end',
                                    'reason': stage
                                })
                                break
                    
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse message: {e}")
                        continue
                
                elif message is None:
                    # Send keepalive every 30 seconds
                    yield ": keepalive\n\n"
        
        except GeneratorExit:
            logger.info(f"SSE client disconnected: {user_id}/{repo_name}")
        
        except Exception as e:
            logger.error(f"SSE stream error for {user_id}/{repo_name}: {e}")
            yield format_sse_message({
                'type': 'error',
                'message': 'Stream error occurred'
            })
        
        finally:
            # Cleanup
            if pubsub:
                try:
                    pubsub.unsubscribe()
                    pubsub.close()
                except Exception as e:
                    logger.error(f"Error closing pubsub: {e}")
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # Disable Nginx buffering
            'Connection': 'keep-alive'
        }
    )


@sse_bp.route("/aws/<user_id>/<account_id>")
def stream_aws_scan_progress(user_id, account_id):
    """Stream AWS scan progress"""
    @stream_with_context
    def generate():
        redis_client = None
        pubsub = None
        
        try:
            redis_client = get_redis_client()
            pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe('scan_updates')
            
            logger.info(f"SSE stream started for AWS scan {user_id}/{account_id}")
            
            yield format_sse_message({
                'type': 'connected',
                'user_id': user_id,
                'account_id': account_id,
                'timestamp': int(time.time())
            })
            
            while True:
                message = pubsub.get_message(timeout=30.0)
                
                if message and message['type'] == 'message':
                    try:
                        data = json.loads(message['data'])
                        
                        if (data.get('user_id') == user_id and 
                            data.get('repo_name') == account_id and
                            data.get('scan_type') == 'aws'):
                            
                            progress_data = data.get('data', {})
                            stage = progress_data.get('s', '')
                            
                            yield format_sse_message(progress_data)
                            
                            if stage in ['completed', 'error']:
                                logger.info(f"AWS SSE stream ending for {user_id}/{account_id}")
                                yield format_sse_message({
                                    'type': 'stream_end',
                                    'reason': stage
                                })
                                break
                    
                    except json.JSONDecodeError:
                        continue
                
                elif message is None:
                    yield ": keepalive\n\n"
        
        except GeneratorExit:
            logger.info(f"AWS SSE client disconnected: {user_id}/{account_id}")
        
        except Exception as e:
            logger.error(f"AWS SSE stream error: {e}")
        
        finally:
            if pubsub:
                try:
                    pubsub.unsubscribe()
                    pubsub.close()
                except:
                    pass
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@sse_bp.route("/gitlab/<user_id>/<project_id>")
def stream_gitlab_scan_progress(user_id, project_id):
    """Stream GitLab scan progress"""
    @stream_with_context
    def generate():
        redis_client = None
        pubsub = None
        
        try:
            redis_client = get_redis_client()
            pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe('scan_updates')
            
            logger.info(f"SSE stream started for GitLab scan {user_id}/{project_id}")
            
            yield format_sse_message({
                'type': 'connected',
                'user_id': user_id,
                'project_id': project_id,
                'timestamp': int(time.time())
            })
            
            while True:
                message = pubsub.get_message(timeout=30.0)
                
                if message and message['type'] == 'message':
                    try:
                        data = json.loads(message['data'])
                        
                        if (data.get('user_id') == user_id and 
                            data.get('repo_name') == project_id and
                            data.get('scan_type') == 'gitlab'):
                            
                            progress_data = data.get('data', {})
                            stage = progress_data.get('s', '')
                            
                            yield format_sse_message(progress_data)
                            
                            if stage in ['completed', 'error']:
                                logger.info(f"GitLab SSE stream ending for {user_id}/{project_id}")
                                yield format_sse_message({
                                    'type': 'stream_end',
                                    'reason': stage
                                })
                                break
                    
                    except json.JSONDecodeError:
                        continue
                
                elif message is None:
                    yield ": keepalive\n\n"
        
        except GeneratorExit:
            logger.info(f"GitLab SSE client disconnected: {user_id}/{project_id}")
        
        except Exception as e:
            logger.error(f"GitLab SSE stream error: {e}")
        
        finally:
            if pubsub:
                try:
                    pubsub.unsubscribe()
                    pubsub.close()
                except:
                    pass
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


@sse_bp.route("/zap/<user_id>/<target_url_hash>")
def stream_zap_scan_progress(user_id, target_url_hash):
    """Stream ZAP scan progress"""
    @stream_with_context
    def generate():
        redis_client = None
        pubsub = None
        
        try:
            redis_client = get_redis_client()
            pubsub = redis_client.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe('scan_updates')
            
            logger.info(f"SSE stream started for ZAP scan {user_id}/{target_url_hash}")
            
            yield format_sse_message({
                'type': 'connected',
                'user_id': user_id,
                'target': target_url_hash,
                'timestamp': int(time.time())
            })
            
            while True:
                message = pubsub.get_message(timeout=30.0)
                
                if message and message['type'] == 'message':
                    try:
                        data = json.loads(message['data'])
                        
                        if (data.get('user_id') == user_id and 
                            data.get('repo_name') == target_url_hash and
                            data.get('scan_type') == 'zap'):
                            
                            progress_data = data.get('data', {})
                            stage = progress_data.get('s', '')
                            
                            yield format_sse_message(progress_data)
                            
                            if stage in ['completed', 'error']:
                                logger.info(f"ZAP SSE stream ending for {user_id}/{target_url_hash}")
                                yield format_sse_message({
                                    'type': 'stream_end',
                                    'reason': stage
                                })
                                break
                    
                    except json.JSONDecodeError:
                        continue
                
                elif message is None:
                    yield ": keepalive\n\n"
        
        except GeneratorExit:
            logger.info(f"ZAP SSE client disconnected: {user_id}/{target_url_hash}")
        
        except Exception as e:
            logger.error(f"ZAP SSE stream error: {e}")
        
        finally:
            if pubsub:
                try:
                    pubsub.unsubscribe()
                    pubsub.close()
                except:
                    pass
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )