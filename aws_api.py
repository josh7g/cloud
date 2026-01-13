from flask import Blueprint, jsonify, request
from sqlalchemy import func, desc, create_engine
from sqlalchemy.orm import sessionmaker
from models import db, CloudScan
from datetime import datetime
import logging
import asyncio
import threading
import traceback
from aws_scanner import scan_aws_account_handler, AwsCredentialValidator
from db_utils import create_db_engine
from collections import defaultdict
from sqlalchemy import text
import json
import os
import subprocess
import boto3
from botocore.exceptions import ClientError
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


 


# ============================================================================
# INPUT SANITIZATION - Security helper functions
# ============================================================================

def sanitize_string_input(value, max_length=500, allow_special=False):
    """Sanitize string input to prevent injection attacks"""
    if not isinstance(value, str):
        return value
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    value = value.replace('\x00', '')
    if not allow_special:
        dangerous_chars = ['<', '>', '"', "'", '\\', ';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']
        for char in dangerous_chars:
            value = value.replace(char, '')
    return value


def sanitize_request_data(data):
    """Recursively sanitize all string values in request data"""
    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            allow_special = key in ['code_snippet', 'reason', 'description', 'message', 'fix_description', 'target']
            if isinstance(value, str):
                sanitized[key] = sanitize_string_input(value, allow_special=allow_special)
            elif isinstance(value, dict):
                sanitized[key] = sanitize_request_data(value)
            elif isinstance(value, list):
                sanitized[key] = [sanitize_request_data(item) if isinstance(item, (dict, str)) else item for item in value]
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, str):
        return sanitize_string_input(data)
    else:
        return data

# ============================================================================

def create_api_engine():
    """Create database engine using individual DB environment variables"""
    import os
    
    # Get database credentials from environment
    db_host = os.getenv('DB_HOST')  
    db_name = os.getenv('DB_NAME')  
    db_port = os.getenv('DB_PORT', '5432')  
    db_username = os.getenv('DB_USERNAME')  
    db_password = os.getenv('DB_PASSWORD')  
    
    # Validate all required variables are present
    missing_vars = []
    if not db_host:
        missing_vars.append('DB_HOST')
    if not db_name:
        missing_vars.append('DB_NAME')
    if not db_username:
        missing_vars.append('DB_USERNAME')
    if not db_password:
        missing_vars.append('DB_PASSWORD')
    
    if missing_vars:
        logger.error(f"Missing database environment variables: {missing_vars}")
        raise ValueError(f"Missing required database variables: {', '.join(missing_vars)}")
    
    # Construct the PostgreSQL connection URL
    database_url = f"postgresql://{db_username}:{db_password}@{db_host}:{db_port}/{db_name}"
    
    # Log success (without exposing password)
    logger.info(f"Database URL constructed: postgresql://{db_username}:***@{db_host}:{db_port}/{db_name}")
    
    return create_engine(
        database_url,
        pool_size=2,              # Small pool for API
        max_overflow=1,           # Limited overflow
        pool_timeout=60,          # Longer timeout
        pool_recycle=300,
        pool_pre_ping=True,
        pool_reset_on_return='rollback'
    )


# Create Blueprint
aws_bp = Blueprint('aws', __name__, url_prefix='/api/v1/aws')

def get_app_credentials():
    """
    Get the application's own AWS credentials from environment variables
    """
    credentials = {
        'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
        'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
        'aws_session_token': os.getenv('AWS_SESSION_TOKEN')  # Optional for STS tokens
    }
    
    if not credentials['aws_access_key_id'] or not credentials['aws_secret_access_key']:
        raise ValueError("Application AWS credentials not configured. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.")
    
    return credentials


@aws_bp.route('/scan', methods=['POST'])
def trigger_aws_scan():
    """Trigger an AWS CIS benchmark scan using either direct credentials OR role assumption"""
    # Get data from POST request body
    request_data = request.get_json()
    if not request_data:
        return jsonify({
            'success': False,
            'error': {'message': 'Request body is required'}
        }), 400
    
    # Get required parameters
    
    # Sanitize input data
    request_data = sanitize_request_data(request_data)
    user_id = request_data.get('user_id')
    user_id = request_data.get('user_id')
    credentials = request_data.get('credentials', {})
    role_arn = request_data.get('role_arn')
    account_id = request_data.get('account_id')
    session_name = request_data.get('session_name', 'SecurityScan')
    external_id = request_data.get('external_id')
    aws_cloudname = request_data.get('aws_cloudname')
    worksheet_number = request_data.get('worksheet_number', 1)
    
    # Validate required parameters
    if not user_id:
        return jsonify({
            'success': False,
            'error': {
                'message': 'user_id is required',
                'code': 'INVALID_PARAMETERS'
            }
        }), 400
    
    # Validate worksheet_number
    if not isinstance(worksheet_number, int) or worksheet_number < 1:
        return jsonify({
            'success': False,
            'error': {
                'message': 'worksheet_number must be a positive integer',
                'code': 'INVALID_WORKSHEET_NUMBER'
            }
        }), 400
    
    # Determine which method to use: direct credentials OR role assumption
    use_direct_credentials = bool(credentials.get('aws_access_key_id') and credentials.get('aws_secret_access_key'))
    use_role_assumption = bool(role_arn)
    
    # Must use exactly one method
    if use_direct_credentials and use_role_assumption:
        return jsonify({
            'success': False,
            'error': {
                'message': 'Please provide either direct credentials OR role_arn, not both',
                'code': 'CONFLICTING_AUTH_METHODS'
            }
        }), 400
    
    if not use_direct_credentials and not use_role_assumption:
        return jsonify({
            'success': False,
            'error': {
                'message': 'Either credentials (aws_access_key_id, aws_secret_access_key) OR role_arn must be provided',
                'code': 'NO_AUTH_METHOD'
            }
        }), 400
    
    # Handle Direct Credentials Method
    if use_direct_credentials:
        logger.info("Using direct credentials method")
        
        # Validate required credentials
        required_creds = ['aws_access_key_id', 'aws_secret_access_key']
        missing_creds = [cred for cred in required_creds if not credentials.get(cred)]
        if missing_creds:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'Missing required AWS credentials: {", ".join(missing_creds)}',
                    'code': 'INVALID_CREDENTIALS'
                }
            }), 400
        
        # Derive account_id if not provided
        if not account_id:
            try:
                session = boto3.Session(
                    aws_access_key_id=credentials.get('aws_access_key_id', '').strip(),
                    aws_secret_access_key=credentials.get('aws_secret_access_key', '').strip(),
                    aws_session_token=credentials.get('aws_session_token', '').strip() or None
                )
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                account_id = identity.get("Account")
                logger.info(f"Derived AWS account ID: {account_id}")
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': f'Could not determine AWS account ID: {str(e)}',
                        'code': 'CREDENTIAL_ERROR'
                    }
                }), 400
        
        # Set up for direct credentials
        scan_credentials = credentials
        role_config = None
        auth_method = "direct_credentials"
    
    # Handle Role Assumption Method
    else:  # use_role_assumption
        logger.info(f"Using role assumption method for role: {role_arn}")
        
        # Validate role ARN format
        if not role_arn.startswith('arn:aws:iam::') or ':role/' not in role_arn:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Invalid role ARN format',
                    'code': 'INVALID_ROLE_ARN'
                }
            }), 400
        
        # Get application's own credentials
        try:
            app_credentials = get_app_credentials()
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'APP_CREDENTIALS_ERROR'
                }
            }), 500
        
        # Extract account_id from role ARN if not provided
        if not account_id:
            try:
                account_id = role_arn.split(':')[4]
                logger.info(f"Extracted account ID from role ARN: {account_id}")
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Could not extract account ID from role ARN',
                        'code': 'INVALID_ROLE_ARN'
                    }
                }), 400
        
        # Build role config
        role_config = {
            'role_arn': role_arn,
            'session_name': session_name
        }
        
        if external_id:
            role_config['external_id'] = external_id
        
        # Set up for role assumption
        scan_credentials = app_credentials
        auth_method = "role_assumption"
    
    # Create database session
    engine = None
    db_session = None
    analysis = None
    
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Create analysis record with new fields
        analysis = CloudScan(
            user_id=user_id,
            cloud_provider='aws',
            account_id=account_id,
            cloudname=aws_cloudname,
            worksheet_number=worksheet_number,
            status='queued' 
        )
        db_session.add(analysis)
        db_session.commit()
        logger.info(f"Created analysis record with ID: {analysis.id}, cloudname: {aws_cloudname}, worksheet: {worksheet_number}")
        
        # Start scan in background thread
        def run_scan_in_background():
            # Set credentials based on auth method
            if auth_method == "direct_credentials":
                # Use user-provided credentials
                os.environ['AWS_ACCESS_KEY_ID'] = scan_credentials.get('aws_access_key_id', '').strip()
                os.environ['AWS_SECRET_ACCESS_KEY'] = scan_credentials.get('aws_secret_access_key', '').strip()
                if scan_credentials.get('aws_session_token'):
                    os.environ['AWS_SESSION_TOKEN'] = scan_credentials.get('aws_session_token', '').strip()
            else:
                # Use app credentials for role assumption
                os.environ['AWS_ACCESS_KEY_ID'] = scan_credentials.get('aws_access_key_id')
                os.environ['AWS_SECRET_ACCESS_KEY'] = scan_credentials.get('aws_secret_access_key')
                if scan_credentials.get('aws_session_token'):
                    os.environ['AWS_SESSION_TOKEN'] = scan_credentials.get('aws_session_token')
                
            try:
                # Update AWS connection configuration
                result = subprocess.run(['/bin/bash', '/home/steampipe/scripts/update_aws_connection.sh'], 
                                      check=False, capture_output=True, text=True)
                logger.info(f"Connection configuration update result: {result.returncode}")
                if result.stdout:
                    logger.info(f"Connection update output: {result.stdout}")
                if result.stderr:
                    logger.warning(f"Connection update stderr: {result.stderr}")
                
                # Update status to in_progress
                analysis.status = 'in_progress'
                db_session.commit()
                
                # Run scan with appropriate parameters including aws_cloudname
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                results = loop.run_until_complete(scan_aws_account_handler(
                    user_id=user_id,
                    account_id=account_id,
                    credentials=scan_credentials,
                    db_session=db_session,
                    scan_record=analysis,
                    role_config=role_config,
                    aws_cloudname=aws_cloudname
                ))
                loop.close()
            except Exception as e:
                # Handle errors
                logger.error(f"Background scan error: {str(e)}")
                analysis.status = 'error'
                analysis.error = str(e)
                db_session.commit()
        
        # Start the background thread
        thread = threading.Thread(target=run_scan_in_background)
        thread.daemon = True
        thread.start()
        
        # Return response based on auth method
        response_data = {
            'success': True,
            'message': 'AWS CIS benchmark scan queued successfully',
            'scan_id': analysis.id,
            'status': 'queued',
            'account_id': account_id,
            'auth_method': auth_method,
            'worksheet_number': worksheet_number
        }
        
        # Add cloudname to response if provided
        if aws_cloudname:
            response_data['aws_cloudname'] = aws_cloudname
        
        # Add role-specific info if using role assumption
        if auth_method == "role_assumption":
            response_data['assumed_role_arn'] = role_arn
        
        return jsonify(response_data), 202  
        
    except Exception as e:
        logger.error(f"Scan initialization error: {str(e)}")
        logger.error(traceback.format_exc())
        
        if analysis and db_session:
            try:
                analysis.status = 'error'
                analysis.error = str(e)
                db_session.commit()
            except Exception as commit_error:
                logger.error(f"Failed to update analysis status: {str(commit_error)}")
                db_session.rollback()
        
        return jsonify({
            'success': False,
            'error': {
                'message': str(e),
                'code': 'SCAN_ERROR'
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<user_id>/list', methods=['GET'])
def list_user_scans(user_id):
    """Get a paginated list of AWS CIS benchmark scans for a user"""
    engine = None
    db_session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Get query parameters with defaults
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 30))))
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Validate sort parameters
        valid_sort_fields = ['created_at', 'account_id', 'status', 'completed_at', 'cloudname', 'worksheet_number']
        if sort_by not in valid_sort_fields:
            sort_by = 'created_at'
            
        valid_sort_orders = ['asc', 'desc']
        if sort_order not in valid_sort_orders:
            sort_order = 'desc'
            
        # Build query
        query = db_session.query(CloudScan).filter(
            CloudScan.user_id == user_id
        )
        
        # Apply sorting
        if sort_order == 'asc':
            query = query.order_by(getattr(CloudScan, sort_by).asc())
        else:
            query = query.order_by(getattr(CloudScan, sort_by).desc())
        
        # Count total scans
        total_scans = query.count()
        
        # Apply pagination
        scans = query.limit(per_page).offset((page - 1) * per_page).all()
        
        # Format response
        scan_list = []
        for scan in scans:
            findings = scan.findings or {}
            stats = findings.get('stats', {})
            
            # Calculate the correct total_findings 
            if 'failed_findings' in stats and 'pass_findings' in stats and 'warning_findings' in stats and 'skip_findings' in stats:
                total_findings = (
                    stats.get('failed_findings', 0) + 
                    stats.get('pass_findings', 0) + 
                    stats.get('warning_findings', 0) + 
                    stats.get('skip_findings', 0)
                )
                # Update the total_findings to the correct sum
                stats['total_findings'] = total_findings
            
            scan_data = {
                'id': scan.id,
                'account_id': scan.account_id,
                'cloud_provider': scan.cloud_provider,
                'cloudname': scan.cloudname,
                'worksheet_number': scan.worksheet_number,
                'status': scan.status,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'summary': {
                    'total_findings': stats.get('total_findings', 0),
                    'failed_findings': stats.get('failed_findings', 0),
                    'warning_findings': stats.get('warning_findings', 0),
                    'pass_findings': stats.get('pass_findings', 0),
                    'severity_counts': stats.get('severity_counts', {})
                } if stats else None,
                'error': scan.error
            }
            
            scan_list.append(scan_data)
            
        # Build pagination info
        total_pages = (total_scans + per_page - 1) // per_page if total_scans > 0 else 1
        
        pagination = {
            'current_page': page,
            'per_page': per_page,
            'total_items': total_scans,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_prev': page > 1
        }
        
        return jsonify({
            'success': True,
            'data': {
                'scans': scan_list,
                'pagination': pagination,
                'user_id': user_id,
                'benchmark': 'CIS AWS Foundations Benchmark v1.4'
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting user scans: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@aws_bp.route('/scans/<user_id>', methods=['GET'])
def get_user_scans(user_id):
    """Get all AWS CIS benchmark scans for a user with optional account filtering"""
    engine = None
    db_session = None
    try:
        # Get query parameters for filtering
        account_id = request.args.get('account_id')
        cloudname = request.args.get('cloudname')
        worksheet_number = request.args.get('worksheet_number')
        page = max(1, int(request.args.get('page', 1)))
        per_page = min(100, max(1, int(request.args.get('limit', 30))))
        
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Build query with user_id
        query = db_session.query(CloudScan).filter(
            CloudScan.user_id == user_id
        )
        
        # Add filters if provided
        if account_id:
            query = query.filter(CloudScan.account_id == account_id)
        if cloudname:
            query = query.filter(CloudScan.cloudname == cloudname)
        if worksheet_number:
            query = query.filter(CloudScan.worksheet_number == int(worksheet_number))
            
        # Apply sorting
        query = query.order_by(desc(CloudScan.created_at))
        
        # Count total
        total_scans = query.count()
        
        # Apply pagination
        scans = query.limit(per_page).offset((page - 1) * per_page).all()
        
        # Format response
        scan_list = []
        for scan in scans:
            findings = scan.findings or {}
            stats = findings.get('stats', {})
            
            # Calculate the correct total_findings 
            if 'failed_findings' in stats and 'pass_findings' in stats and 'warning_findings' in stats and 'skip_findings' in stats:
                total_findings = (
                    stats.get('failed_findings', 0) + 
                    stats.get('pass_findings', 0) + 
                    stats.get('warning_findings', 0) + 
                    stats.get('skip_findings', 0)
                )
                # Update the total_findings to the correct sum
                stats['total_findings'] = total_findings
            
            scan_data = {
                'id': scan.id,
                'account_id': scan.account_id,
                'cloud_provider': scan.cloud_provider,
                'cloudname': scan.cloudname,
                'worksheet_number': scan.worksheet_number,
                'status': scan.status,
                'created_at': scan.created_at.isoformat(),
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'summary': {
                    'total_findings': stats.get('total_findings', 0),
                    'failed_findings': stats.get('failed_findings', 0),
                    'warning_findings': stats.get('warning_findings', 0),
                    'pass_findings': stats.get('pass_findings', 0),
                    'severity_counts': stats.get('severity_counts', {})
                } if stats else None,
                'error': scan.error
            }
            
            scan_list.append(scan_data)
            
        return jsonify({
            'success': True,
            'data': {
                'benchmark': 'CIS AWS Foundations Benchmark v1.4',
                'scans': scan_list,
                'pagination': {
                    'current_page': page,
                    'per_page': per_page,
                    'total_items': total_scans,
                    'total_pages': (total_scans + per_page - 1) // per_page
                },
                'filters': {
                    'account_id': account_id if account_id else None,
                    'cloudname': cloudname if cloudname else None,
                    'worksheet_number': int(worksheet_number) if worksheet_number else None
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting user scans: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()


@aws_bp.route('/scans/<scan_id>/result', methods=['GET'])
def get_scan_result(scan_id):
    engine = None
    db_session = None
    try:
        # Create database session with direct connection to avoid stale data
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Use a raw SQL query to bypass any caching issues
        raw_query = text("""
            SELECT id, user_id, cloud_provider, account_id, cloudname, worksheet_number, status, 
                   created_at, completed_at, findings, error 
            FROM cloud_scans 
            WHERE id = :scan_id
        """)
        
        result = db_session.execute(raw_query, {'scan_id': scan_id}).fetchone()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Scan not found',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
        
        # Convert result to dictionary
        column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'cloudname', 'worksheet_number', 
                        'status', 'created_at', 'completed_at', 'findings', 'error']
        scan_dict = dict(zip(column_names, result))
        
        # Log detailed diagnostics
        logger.info(f"Scan {scan_id} status: {scan_dict.get('status')}")
        logger.info(f"Scan {scan_id} has findings: {bool(scan_dict.get('findings'))}")
        logger.info(f"Scan {scan_id} completed_at: {scan_dict.get('completed_at')}")
        
        # Check if scan is actually completed based on multiple indicators
        is_actually_completed = (
            scan_dict.get('status') == 'completed' or 
            (scan_dict.get('completed_at') is not None and 
             scan_dict.get('findings') is not None and
             len(scan_dict.get('findings', {}).get('findings', [])) > 0)
        )
        
        # If the scan is actually completed but status doesn't show it,
        # update the status first
        if is_actually_completed and scan_dict.get('status') != 'completed':
            logger.info(f"Scan {scan_id} appears complete but status is {scan_dict.get('status')} - fixing")
            update_query = text("""
                UPDATE cloud_scans
                SET status = 'completed'
                WHERE id = :scan_id
            """)
            db_session.execute(update_query, {'scan_id': scan_id})
            db_session.commit()
            scan_dict['status'] = 'completed'
        
        # If scan is completed, return full findings
        if is_actually_completed:
            findings_data = scan_dict.get('findings', {})
            
            # Ensure we have severity counts for all severity levels
            if 'stats' in findings_data:
                stats = findings_data['stats']
                
                # Calculate the correct total_findings
                if 'failed_findings' in stats and 'pass_findings' in stats and 'warning_findings' in stats and 'skip_findings' in stats:
                    total_findings = (
                        stats.get('failed_findings', 0) + 
                        stats.get('pass_findings', 0) + 
                        stats.get('warning_findings', 0) + 
                        stats.get('skip_findings', 0)
                    )
                    # Update the total_findings to the correct sum
                    stats['total_findings'] = total_findings
                    
                    # Double-check that the severity counts sum matches the total
                    severity_total = sum(stats.get('severity_counts', {}).values())
                    if severity_total != total_findings:
                        logger.warning(f"Severity counts sum ({severity_total}) doesn't match total findings ({total_findings})")
            
            return jsonify({
                'success': True,
                'data': {
                    'id': scan_dict.get('id'),
                    'account_id': scan_dict.get('account_id'),
                    'cloud_provider': scan_dict.get('cloud_provider'),
                    'cloudname': scan_dict.get('cloudname'),
                    'worksheet_number': scan_dict.get('worksheet_number'),
                    'status': 'completed',
                    'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                    'completed_at': scan_dict.get('completed_at').isoformat() if scan_dict.get('completed_at') else None,
                    'findings': findings_data
                }
            })
        
        # If not completed, return in-progress status
        return jsonify({
            'success': True,
            'data': {
                'id': scan_dict.get('id'),
                'account_id': scan_dict.get('account_id'),
                'cloud_provider': scan_dict.get('cloud_provider'),
                'cloudname': scan_dict.get('cloudname'),
                'worksheet_number': scan_dict.get('worksheet_number'),
                'status': scan_dict.get('status', 'in_progress'),
                'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                'message': 'Scan is still in progress',
                'error': scan_dict.get('error')
            }
        })
    
    except Exception as e:
        logger.error(f"Error retrieving scan result: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to retrieve scan result',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a specific AWS CIS benchmark scan"""
    engine = None
    db_session = None
    try:
        # Get user_id from query parameter
        user_id = request.args.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': {'message': 'user_id is required'}
            }), 400
            
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Get the scan record
        scan = db_session.query(CloudScan).filter(
            CloudScan.id == scan_id,
            CloudScan.user_id == user_id
        ).first()
        
        if not scan:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Scan not found',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
            
        # Delete the scan
        db_session.delete(scan)
        db_session.commit()
        
        return jsonify({
            'success': True,
            'message': 'CIS benchmark scan deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/security/summary/<user_id>', methods=['GET'])
def get_security_summary(user_id):
    """Get CIS benchmark security summary across all AWS accounts for a user"""
    engine = None
    db_session = None
    try:
        # Create engine using the new function
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Get all completed scans for this user
        scans = db_session.query(CloudScan).filter(
            CloudScan.user_id == user_id,
            CloudScan.status == 'completed',
            CloudScan.findings.isnot(None)
        ).order_by(
            desc(CloudScan.created_at)
        ).all()
        
        if not scans:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'No completed CIS benchmark scans found',
                    'code': 'NO_SCANS_FOUND'
                }
            }), 404
            
        # Get latest scan per account/cloudname/worksheet combination
        latest_scans = {}
        for scan in scans:
            # Create unique key for account+cloudname+worksheet combination
            key = f"{scan.account_id}_{scan.cloudname or 'default'}_{scan.worksheet_number}"
            if key not in latest_scans:
                latest_scans[key] = scan
        
        # Compile statistics
        total_findings = 0
        total_failed = 0
        total_warning = 0
        total_passed = 0
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        scan_summaries = {}
        latest_scan_time = None
        
        for key, scan in latest_scans.items():
            findings = scan.findings or {}
            stats = findings.get('stats', {})
            
            # Count findings
            scan_total = stats.get('total_findings', 0)
            scan_failed = stats.get('failed_findings', 0)
            scan_warning = stats.get('warning_findings', 0)
            scan_passed = stats.get('pass_findings', 0)
            
            total_findings += scan_total
            total_failed += scan_failed
            total_warning += scan_warning
            total_passed += scan_passed
            
            # Aggregate severity counts
            for severity, count in stats.get('severity_counts', {}).items():
                severity_counts[severity] += count
                
            # Aggregate category counts
            for category, count in stats.get('category_counts', {}).items():
                category_counts[category] += count
            
            # Build scan summary
            scan_summaries[key] = {
                'scan_id': scan.id,
                'account_id': scan.account_id,
                'cloudname': scan.cloudname,
                'worksheet_number': scan.worksheet_number,
                'last_scan_time': scan.completed_at.isoformat() if scan.completed_at else None,
                'findings': {
                    'total': scan_total,
                    'failed': scan_failed,
                    'warning': scan_warning,
                    'passed': scan_passed
                },
                'severity_counts': stats.get('severity_counts', {}),
                'cis_compliance_percentage': _calculate_compliance_percentage(stats)
            }
            
            # Track latest scan time
            if scan.completed_at:
                if not latest_scan_time or scan.completed_at > latest_scan_time:
                    latest_scan_time = scan.completed_at
        
        # Calculate overall compliance percentage
        overall_compliance = 0
        if total_findings > 0:
            overall_compliance = round((total_passed / total_findings) * 100, 1)
        
        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'benchmark': 'CIS AWS Foundations Benchmark v1.4',
                'summary': {
                    'total_scans': len(latest_scans),
                    'total_findings': total_findings,
                    'failed_findings': total_failed,
                    'warning_findings': total_warning,
                    'passed_findings': total_passed,
                    'severity_counts': dict(severity_counts),
                    'category_counts': dict(category_counts),
                    'last_scan_time': latest_scan_time.isoformat() if latest_scan_time else None,
                    'overall_compliance_percentage': overall_compliance
                },
                'scans': scan_summaries
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting security summary: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/validate-credentials', methods=['POST'])
def validate_aws_credentials():
    """
    Validate AWS credentials (for direct credential method)
    
    Expected JSON payload:
    {
        "aws_access_key_id": "...",
        "aws_secret_access_key": "...",
        "aws_session_token": "..." (optional),
        "account_id": "123456789012" (optional)
    }
    """
    # Get credentials from request
    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': {
                'message': 'Request body is required',
                'code': 'INVALID_REQUEST'
            }
        }), 400
    
    # Extract credentials
    
    # Sanitize input data
    data = sanitize_request_data(data)
    credentials = {
        'aws_access_key_id': data.get('aws_access_key_id'),
        'aws_secret_access_key': data.get('aws_secret_access_key'),
        'aws_session_token': data.get('aws_session_token')
    }
    
    # Validate required credentials
    required_creds = ['aws_access_key_id', 'aws_secret_access_key']
    missing_creds = [cred for cred in required_creds if not credentials.get(cred)]
    if missing_creds:
        return jsonify({
            'success': False,
            'error': {
                'message': f'Missing required credentials: {", ".join(missing_creds)}',
                'code': 'MISSING_CREDENTIALS'
            }
        }), 400
    
    account_id = data.get('account_id')

    try:
        # Use standard validation (no role assumption)
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            validator = AwsCredentialValidator()
            validation_results = loop.run_until_complete(
                validator.validate_credentials(credentials, account_id)
            )
        finally:
            loop.close()

        if not validation_results.get("valid", False):
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Authentication failed',
                    'details': validation_results.get("errors", [])
                }
            }), 401

        # Return success response
        return jsonify({
            'success': True,
            'data': {
                'account_id': validation_results['account_id'],
                'caller_identity': validation_results['caller_identity'],
                'regions_accessible': validation_results['regions_accessible'],
                'services_accessible': validation_results['services_accessible']
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Unexpected credential validation error: {str(e)}")
        logger.error(traceback.format_exc())
        
        return jsonify({
            'success': False,
            'error': {
                'message': 'Unexpected error during credential validation',
                'code': 'VALIDATION_ERROR',
                'details': str(e)
            }
        }), 500

@aws_bp.route('/validate-role', methods=['POST'])
def validate_role_assumption():
   """
   Validate that the application can assume the user's role
   
   Expected JSON payload:
   {
       "role_arn": "arn:aws:iam::123456789012:role/SecurityAuditRole",
       "session_name": "ValidationTest" (optional),
       "external_id": "unique-external-id" (optional)
   }
   """
   engine = None
   db_session = None
   
   try:
       # Get role info from request
       data = request.get_json()
       if not data:
           return jsonify({
               'success': False,
               'error': {
                   'message': 'Request body is required',
                   'code': 'INVALID_REQUEST'
               }
           }), 400
       
       
       # Sanitize input data
       data = sanitize_request_data(data)
       role_arn = data.get('role_arn')
       role_arn = data.get('role_arn')
       session_name = data.get('session_name', 'ValidationTest')
       external_id = data.get('external_id')
       
       if not role_arn:
           return jsonify({
               'success': False,
               'error': {
                   'message': 'role_arn is required',
                   'code': 'MISSING_ROLE_ARN'
               }
           }), 400
       
       # Validate role ARN format
       if not role_arn.startswith('arn:aws:iam::') or ':role/' not in role_arn:
           return jsonify({
               'success': False,
               'error': {
                   'message': 'Invalid role ARN format',
                   'code': 'INVALID_ROLE_ARN'
               }
           }), 400

       # Get application's own credentials
       app_credentials = get_app_credentials()
       
       # Extract account ID from role ARN
       account_id = role_arn.split(':')[4]
       
       # Build role config
       role_config = {
           'role_arn': role_arn,
           'session_name': session_name
       }
       
       if external_id:
           role_config['external_id'] = external_id
       
       # Test role assumption
       loop = asyncio.new_event_loop()
       asyncio.set_event_loop(loop)
       
       try:
           validator = AwsCredentialValidator()
           validation_results = loop.run_until_complete(
               validator.validate_credentials_with_role(app_credentials, account_id, role_config)
           )
       finally:
           loop.close()

       if not validation_results.get("valid", False):
           return jsonify({
               'success': False,
               'error': {
                   'message': 'Role assumption failed',
                   'details': validation_results.get("errors", [])
               }
           }), 401

       # Return success response
       return jsonify({
           'success': True,
           'data': {
               'account_id': validation_results['account_id'],
               'caller_identity': validation_results['caller_identity'],
               'regions_accessible': validation_results['regions_accessible'],
               'services_accessible': validation_results['services_accessible'],
               'role_assumed': validation_results.get('role_assumed', False),
               'assumed_role_arn': validation_results.get('assumed_role_arn')
           }
       }), 200
       
   except ValueError as e:
       return jsonify({
           'success': False,
           'error': {
               'message': str(e),
               'code': 'APP_CREDENTIALS_ERROR'
           }
       }), 500
   except Exception as e:
       logger.error(f"Unexpected role validation error: {str(e)}")
       logger.error(traceback.format_exc())
       
       return jsonify({
           'success': False,
           'error': {
               'message': 'Unexpected error during role validation',
               'code': 'VALIDATION_ERROR',
               'details': str(e)
           }
       }), 500
   finally:
       if db_session:
           db_session.close()
       if engine:
           engine.dispose()



@aws_bp.route('/scans/<scan_id>/reranked', methods=['GET'])
def get_reranked_aws_findings(scan_id):
    """Get reranked AWS security findings for a specific scan"""
    engine = None
    db_session = None
    try:
        # Create database session
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Use a raw SQL query for more reliable data retrieval
        raw_query = text("""
            SELECT id, user_id, cloud_provider, account_id, cloudname, worksheet_number, status, 
                   created_at, completed_at, findings, rerank 
            FROM cloud_scans 
            WHERE id = :scan_id
        """)
        
        result = db_session.execute(raw_query, {'scan_id': scan_id}).fetchone()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Scan not found',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
        
        # Convert result to dictionary
        column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'cloudname', 'worksheet_number',
                        'status', 'created_at', 'completed_at', 'findings', 'rerank']
        scan_dict = dict(zip(column_names, result))
        
        # Check if we have reranked findings
        rerank_data = scan_dict.get('rerank')
        
        # Log diagnostics
        logger.info(f"Retrieved rerank data for scan {scan_id}: " + 
                    f"{'present' if rerank_data else 'missing'}")
        
        if rerank_data is None or (isinstance(rerank_data, list) and len(rerank_data) == 0):
            # Try a fallback - use the original findings if available
            if scan_dict.get('findings') and 'findings' in scan_dict.get('findings', {}):
                findings_array = scan_dict.get('findings', {}).get('findings', [])
                logger.info(f"Using {len(findings_array)} original findings as fallback")
                
                return jsonify({
                    'success': True,
                    'data': {
                        'scan_id': scan_dict.get('id'),
                        'account_id': scan_dict.get('account_id'),
                        'cloudname': scan_dict.get('cloudname'),
                        'worksheet_number': scan_dict.get('worksheet_number'),
                        'findings': findings_array,
                        'note': 'Using original findings as reranked results are not available'
                    }
                })
            else:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No reranked results available',
                        'code': 'NO_RERANK_RESULTS'
                    }
                }), 404
        
        # Return the reranked findings
        return jsonify({
            'success': True,
            'data': {
                'scan_id': scan_dict.get('id'),
                'account_id': scan_dict.get('account_id'),
                'cloudname': scan_dict.get('cloudname'),
                'worksheet_number': scan_dict.get('worksheet_number'),
                'findings': rerank_data
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting reranked AWS findings: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

# Helper function referenced in security summary
def _calculate_compliance_percentage(stats):
    """Calculate CIS compliance percentage based on findings stats"""
    total_findings = stats.get('total_findings', 0)
    passed_findings = stats.get('pass_findings', 0)
    
    if total_findings == 0:
        return 0.0
        
    return round((passed_findings / total_findings) * 100, 1)

@aws_bp.route('/scans/<user_id>/debug', methods=['GET'])
def debug_user_scans(user_id):
    """Debug endpoint to see all scans and their metadata structure"""
    engine = None
    db_session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        raw_query = text("""
            SELECT id, account_id, cloudname, worksheet_number, status, created_at, 
                   findings->'metadata' as metadata,
                   CASE 
                       WHEN findings->'metadata'->>'aws_cloudname' IS NOT NULL 
                       THEN findings->'metadata'->>'aws_cloudname'
                       WHEN findings->'metadata'->'rag_analysis'->>'cloudname' IS NOT NULL 
                       THEN findings->'metadata'->'rag_analysis'->>'cloudname'
                       ELSE 'NOT_FOUND'
                   END as found_cloudname
            FROM cloud_scans 
            WHERE user_id = :user_id 
            ORDER BY created_at DESC
            LIMIT 10
        """)
        
        results = db_session.execute(raw_query, {'user_id': user_id}).fetchall()
        
        scans_info = []
        for row in results:
            scans_info.append({
                'id': row[0],
                'account_id': row[1],
                'cloudname': row[2],
                'worksheet_number': row[3],
                'status': row[4],
                'created_at': row[5].isoformat() if row[5] else None,
                'metadata': row[6],
                'found_cloudname': row[7]
            })
        
        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'scans': scans_info
            }
        })
        
    except Exception as e:
        logger.error(f"Debug endpoint error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<user_id>/cloudname/<cloudname>/result', methods=['GET'])
def get_scan_result_by_cloudname(user_id, cloudname):
    """Get the most recent scan result for a user by cloudname (defaults to worksheet 1)"""
    engine = None
    db_session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Query by cloudname, defaulting to most recent worksheet
        raw_query = text("""
            SELECT id, user_id, cloud_provider, account_id, cloudname, worksheet_number, status, 
                   created_at, completed_at, findings, error 
            FROM cloud_scans 
            WHERE user_id = :user_id 
            AND cloudname = :cloudname
            ORDER BY created_at DESC
            LIMIT 1
        """)
        
        result = db_session.execute(raw_query, {
            'user_id': user_id, 
            'cloudname': cloudname
        }).fetchone()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'No scan found for cloudname: {cloudname}',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
        
        # Convert result to dictionary
        column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'cloudname', 
                        'worksheet_number', 'status', 'created_at', 'completed_at', 'findings', 'error']
        scan_dict = dict(zip(column_names, result))
        
        logger.info(f"Found scan {scan_dict.get('id')} for cloudname {cloudname}")
        
        # Check if scan is completed
        is_actually_completed = (
            scan_dict.get('status') == 'completed' or 
            (scan_dict.get('completed_at') is not None and 
             scan_dict.get('findings') is not None and
             len(scan_dict.get('findings', {}).get('findings', [])) > 0)
        )
        
        if is_actually_completed and scan_dict.get('status') != 'completed':
            logger.info(f"Fixing status for scan {scan_dict.get('id')}")
            update_query = text("UPDATE cloud_scans SET status = 'completed' WHERE id = :scan_id")
            db_session.execute(update_query, {'scan_id': scan_dict.get('id')})
            db_session.commit()
            scan_dict['status'] = 'completed'
        
        if is_actually_completed:
            findings_data = scan_dict.get('findings', {})
            
            # Fix total_findings calculation
            if 'stats' in findings_data:
                stats = findings_data['stats']
                if all(key in stats for key in ['failed_findings', 'pass_findings', 'warning_findings', 'skip_findings']):
                    total_findings = (
                        stats.get('failed_findings', 0) + 
                        stats.get('pass_findings', 0) + 
                        stats.get('warning_findings', 0) + 
                        stats.get('skip_findings', 0)
                    )
                    stats['total_findings'] = total_findings
            
            return jsonify({
                'success': True,
                'data': {
                    'id': scan_dict.get('id'),
                    'account_id': scan_dict.get('account_id'),
                    'cloud_provider': scan_dict.get('cloud_provider'),
                    'cloudname': cloudname,
                    'worksheet_number': scan_dict.get('worksheet_number'),
                    'status': 'completed',
                    'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                    'completed_at': scan_dict.get('completed_at').isoformat() if scan_dict.get('completed_at') else None,
                    'findings': findings_data
                }
            })
        
        return jsonify({
            'success': True,
            'data': {
                'id': scan_dict.get('id'),
                'account_id': scan_dict.get('account_id'),
                'cloud_provider': scan_dict.get('cloud_provider'),
                'cloudname': cloudname,
                'worksheet_number': scan_dict.get('worksheet_number'),
                'status': scan_dict.get('status', 'in_progress'),
                'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                'message': 'Scan is still in progress',
                'error': scan_dict.get('error')
            }
        })
    
    except Exception as e:
        logger.error(f"Error retrieving scan result by cloudname: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to retrieve scan result',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<user_id>/cloudname/<cloudname>/reranked', methods=['GET'])
def get_reranked_aws_findings_by_cloudname(user_id, cloudname):
    """Get reranked AWS security findings by cloudname (most recent scan)"""
    engine = None
    db_session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        raw_query = text("""
            SELECT id, user_id, cloud_provider, account_id, cloudname, worksheet_number, status, 
                   created_at, completed_at, findings, rerank 
            FROM cloud_scans 
            WHERE user_id = :user_id 
            AND cloudname = :cloudname
            ORDER BY created_at DESC
            LIMIT 1
        """)
        
        result = db_session.execute(raw_query, {
            'user_id': user_id,
            'cloudname': cloudname
        }).fetchone()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'No scan found for cloudname: {cloudname}',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
        
        column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'cloudname', 
                        'worksheet_number', 'status', 'created_at', 'completed_at', 'findings', 'rerank']
        scan_dict = dict(zip(column_names, result))
        
        rerank_data = scan_dict.get('rerank')
        
        if rerank_data is None or (isinstance(rerank_data, list) and len(rerank_data) == 0):
            if scan_dict.get('findings') and 'findings' in scan_dict.get('findings', {}):
                findings_array = scan_dict.get('findings', {}).get('findings', [])
                return jsonify({
                    'success': True,
                    'data': {
                        'scan_id': scan_dict.get('id'),
                        'account_id': scan_dict.get('account_id'),
                        'cloudname': cloudname,
                        'worksheet_number': scan_dict.get('worksheet_number'),
                        'findings': findings_array,
                        'note': 'Using original findings as reranked results are not available'
                    }
                })
            else:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No reranked results available',
                        'code': 'NO_RERANK_RESULTS'
                    }
                }), 404
        
        return jsonify({
            'success': True,
            'data': {
                'scan_id': scan_dict.get('id'),
                'account_id': scan_dict.get('account_id'),
                'cloudname': cloudname,
                'worksheet_number': scan_dict.get('worksheet_number'),
                'findings': rerank_data
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting reranked findings by cloudname: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<user_id>/cloudname/<cloudname>/worksheet/<int:worksheet_number>/reranked', methods=['GET'])
def get_reranked_aws_findings_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number):
    """Get reranked AWS security findings by cloudname and worksheet number"""
    engine = None
    db_session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        raw_query = text("""
            SELECT id, user_id, cloud_provider, account_id, cloudname, worksheet_number, status, 
                   created_at, completed_at, findings, rerank 
            FROM cloud_scans 
            WHERE user_id = :user_id 
            AND cloudname = :cloudname 
            AND worksheet_number = :worksheet_number
            ORDER BY created_at DESC
            LIMIT 1
        """)
        
        result = db_session.execute(raw_query, {
            'user_id': user_id,
            'cloudname': cloudname,
            'worksheet_number': worksheet_number
        }).fetchone()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'No scan found for cloudname: {cloudname}, worksheet: {worksheet_number}',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
        
        column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'cloudname', 
                        'worksheet_number', 'status', 'created_at', 'completed_at', 'findings', 'rerank']
        scan_dict = dict(zip(column_names, result))
        
        rerank_data = scan_dict.get('rerank')
        
        if rerank_data is None or (isinstance(rerank_data, list) and len(rerank_data) == 0):
            if scan_dict.get('findings') and 'findings' in scan_dict.get('findings', {}):
                findings_array = scan_dict.get('findings', {}).get('findings', [])
                return jsonify({
                    'success': True,
                    'data': {
                        'scan_id': scan_dict.get('id'),
                        'account_id': scan_dict.get('account_id'),
                        'cloudname': cloudname,
                        'worksheet_number': worksheet_number,
                        'findings': findings_array,
                        'note': 'Using original findings as reranked results are not available'
                    }
                })
            else:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'No reranked results available',
                        'code': 'NO_RERANK_RESULTS'
                    }
                }), 404
        
        return jsonify({
            'success': True,
            'data': {
                'scan_id': scan_dict.get('id'),
                'account_id': scan_dict.get('account_id'),
                'cloudname': cloudname,
                'worksheet_number': worksheet_number,
                'findings': rerank_data
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting reranked findings by cloudname and worksheet: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<user_id>/cloudname/<cloudname>/worksheets', methods=['GET'])
def list_worksheets_for_cloudname(user_id, cloudname):
    """List all worksheet numbers for a specific user and cloudname"""
    engine = None
    db_session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        raw_query = text("""
            SELECT worksheet_number, COUNT(*) as scan_count, MAX(created_at) as latest_scan,
                   MAX(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as has_completed_scan
            FROM cloud_scans 
            WHERE user_id = :user_id 
            AND cloudname = :cloudname
            GROUP BY worksheet_number
            ORDER BY worksheet_number
        """)
        
        results = db_session.execute(raw_query, {
            'user_id': user_id,
            'cloudname': cloudname
        }).fetchall()
        
        if not results:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'No worksheets found for cloudname: {cloudname}',
                    'code': 'NO_WORKSHEETS_FOUND'
                }
            }), 404
        
        worksheets = []
        for row in results:
            worksheets.append({
                'worksheet_number': row[0],
                'scan_count': row[1],
                'latest_scan': row[2].isoformat() if row[2] else None,
                'has_completed_scan': bool(row[3])
            })
        
        return jsonify({
            'success': True,
            'data': {
                'user_id': user_id,
                'cloudname': cloudname,
                'worksheets': worksheets,
                'total_worksheets': len(worksheets)
            }
        })
        
    except Exception as e:
        logger.error(f"Error listing worksheets: {str(e)}")
        return jsonify({
            'success': False,
            'error': {
                'message': 'Internal server error',
                'code': 'INTERNAL_ERROR',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()

@aws_bp.route('/scans/<user_id>/cloudname/<cloudname>/worksheet/<int:worksheet_number>/result', methods=['GET'])
def get_scan_result_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number):
    """Get the most recent scan result for a user by cloudname and worksheet number"""
    engine = None
    db_session = None
    try:
        engine = create_api_engine()
        Session = sessionmaker(bind=engine)
        db_session = Session()
        
        # Query by cloudname and worksheet_number specifically
        raw_query = text("""
            SELECT id, user_id, cloud_provider, account_id, cloudname, worksheet_number, status, 
                   created_at, completed_at, findings, error 
            FROM cloud_scans 
            WHERE user_id = :user_id 
            AND cloudname = :cloudname 
            AND worksheet_number = :worksheet_number
            ORDER BY created_at DESC
            LIMIT 1
        """)
        
        result = db_session.execute(raw_query, {
            'user_id': user_id, 
            'cloudname': cloudname,
            'worksheet_number': worksheet_number
        }).fetchone()
        
        if not result:
            return jsonify({
                'success': False,
                'error': {
                    'message': f'No scan found for cloudname: {cloudname}, worksheet: {worksheet_number}',
                    'code': 'SCAN_NOT_FOUND'
                }
            }), 404
        
        # Convert result to dictionary
        column_names = ['id', 'user_id', 'cloud_provider', 'account_id', 'cloudname', 
                        'worksheet_number', 'status', 'created_at', 'completed_at', 'findings', 'error']
        scan_dict = dict(zip(column_names, result))
        
        logger.info(f"Found scan {scan_dict.get('id')} for cloudname {cloudname}, worksheet {worksheet_number}")
        
        # Check if scan is completed
        is_actually_completed = (
            scan_dict.get('status') == 'completed' or 
            (scan_dict.get('completed_at') is not None and 
             scan_dict.get('findings') is not None and
             len(scan_dict.get('findings', {}).get('findings', [])) > 0)
        )
        
        if is_actually_completed and scan_dict.get('status') != 'completed':
            logger.info(f"Fixing status for scan {scan_dict.get('id')}")
            update_query = text("UPDATE cloud_scans SET status = 'completed' WHERE id = :scan_id")
            db_session.execute(update_query, {'scan_id': scan_dict.get('id')})
            db_session.commit()
            scan_dict['status'] = 'completed'
        
        if is_actually_completed:
            findings_data = scan_dict.get('findings', {})
            
            # Fix total_findings calculation
            if 'stats' in findings_data:
                stats = findings_data['stats']
                if all(key in stats for key in ['failed_findings', 'pass_findings', 'warning_findings', 'skip_findings']):
                    total_findings = (
                        stats.get('failed_findings', 0) + 
                        stats.get('pass_findings', 0) + 
                        stats.get('warning_findings', 0) + 
                        stats.get('skip_findings', 0)
                    )
                    stats['total_findings'] = total_findings
            
            return jsonify({
                'success': True,
                'data': {
                    'id': scan_dict.get('id'),
                    'account_id': scan_dict.get('account_id'),
                    'cloud_provider': scan_dict.get('cloud_provider'),
                    'cloudname': cloudname,
                    'worksheet_number': worksheet_number,
                    'status': 'completed',
                    'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                    'completed_at': scan_dict.get('completed_at').isoformat() if scan_dict.get('completed_at') else None,
                    'findings': findings_data
                }
            })
        
        return jsonify({
            'success': True,
            'data': {
                'id': scan_dict.get('id'),
                'account_id': scan_dict.get('account_id'),
                'cloud_provider': scan_dict.get('cloud_provider'),
                'cloudname': cloudname,
                'worksheet_number': worksheet_number,
                'status': scan_dict.get('status', 'in_progress'),
                'created_at': scan_dict.get('created_at').isoformat() if scan_dict.get('created_at') else None,
                'message': 'Scan is still in progress',
                'error': scan_dict.get('error')
            }
        })
    
    except Exception as e:
        logger.error(f"Error retrieving scan result by cloudname and worksheet: {str(e)}", exc_info=True)
        return jsonify({
            'success': False,
            'error': {
                'message': 'Failed to retrieve scan result',
                'details': str(e)
            }
        }), 500
    finally:
        if db_session:
            db_session.close()
        if engine:
            engine.dispose()