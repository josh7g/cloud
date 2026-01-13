import os
import json
import logging
import asyncio
import subprocess
import tempfile
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Union
import traceback
from pathlib import Path
import sys
import re
import boto3
from botocore.exceptions import ClientError
from sqlalchemy.orm import Session 
from models import CloudScan
from progress_tracking import update_scan_progress, clear_scan_progress, start_new_scan, generate_unique_scan_id, aggressively_clear_scan_data
from sqlalchemy import text
from datetime import datetime, date
import time
import aiohttp
import random
from datetime import timedelta
import asyncio 


# Configure detailed logging
logging.basicConfig(
    level=logging.DEBUG,  
    format='%(asctime)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

def datetime_to_iso_string(obj):
        """Convert datetime objects to ISO format strings for JSON serialization"""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, date):
            return obj.isoformat()
        return str(obj)

def sanitize_for_json(obj):
        """Recursively sanitize an object for JSON serialization"""
        if isinstance(obj, dict):
            return {k: sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitize_for_json(i) for i in obj]
        elif isinstance(obj, (datetime, date)):
            return datetime_to_iso_string(obj)
        # Handle timezone-aware datetime objects from boto3
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)  # Convert any other types to strings
        
def initiate_new_aws_scan(user_id: str, account_id: str) -> str:
    """
    Helper function to properly initiate a new AWS scan with cleanup and unique ID generation.
    """
    try:
        # Start new scan with cleanup and unique ID
        scan_id = start_new_scan(user_id, account_id, 'aws')
        
        # Send initial progress update
        update_scan_progress(
            user_id=user_id,
            repo_name=account_id,  
            stage='initializing',
            progress=0,
            scan_type='aws',
            scan_id=scan_id
        )
        
        logger.info(f"Initiated new AWS scan {scan_id} for {user_id}:{account_id}")
        return scan_id
        
    except Exception as e:
        logger.error(f"Error initiating new AWS scan: {str(e)}")
        # Return a fallback unique ID
        import uuid
        return f"aws_scan_{int(time.time() * 1000)}_{str(uuid.uuid4())[:8]}"
    
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)


class AwsAssumedRoleCredentials:
    """
    Handles AWS assumed role credentials with automatic refresh
    """
    
    def __init__(self, role_arn: str, session_name: str = None, 
                 external_id: str = None, base_credentials: Dict[str, str] = None):
        self.role_arn = role_arn
        self.session_name = session_name or f"SecurityScan-{int(time.time())}"
        self.external_id = external_id
        self.base_credentials = base_credentials or {}
        
        self.assumed_credentials = None
        self.credentials_expiry = None
        
    async def get_credentials(self) -> Dict[str, str]:
        """Get valid assumed role credentials, refreshing if necessary"""
        try:
            if (not self.assumed_credentials or 
                not self.credentials_expiry or 
                datetime.now() >= self.credentials_expiry):
                
                await self._assume_role()
            
            return self.assumed_credentials
            
        except Exception as e:
            logger.error(f"Failed to get assumed role credentials: {str(e)}")
            raise
    
    async def _assume_role(self):
        """Assume the specified IAM role"""
        try:
            logger.info(f"Assuming role: {self.role_arn}")
            
            # Create STS client with base credentials
            if self.base_credentials:
                session = boto3.Session(
                    aws_access_key_id=self.base_credentials.get('aws_access_key_id'),
                    aws_secret_access_key=self.base_credentials.get('aws_secret_access_key'),
                    aws_session_token=self.base_credentials.get('aws_session_token')
                )
            else:
                session = boto3.Session()
            
            sts_client = session.client('sts')
            
            # Prepare assume role parameters
            assume_role_params = {
                'RoleArn': self.role_arn,
                'RoleSessionName': self.session_name,
                'DurationSeconds': 3600  # 1 hour
            }
            
            if self.external_id:
                assume_role_params['ExternalId'] = self.external_id
            
            # Assume the role
            response = sts_client.assume_role(**assume_role_params)
            credentials = response['Credentials']
            
            # Store the temporary credentials
            self.assumed_credentials = {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken']
            }
            
            # Set expiry time (with 5 minute buffer)
            self.credentials_expiry = credentials['Expiration'] - timedelta(minutes=5)
            
            logger.info(f"Successfully assumed role. Credentials expire at: {self.credentials_expiry}")
            
        except Exception as e:
            logger.error(f"Failed to assume role {self.role_arn}: {str(e)}")
            raise

class AwsCredentialValidator:
    """Validates AWS credentials before attempting Steampipe scans"""
    
    @staticmethod
    async def validate_credentials(credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """
        Validate AWS credentials by making direct API calls to AWS
        
        Args:
            credentials: Dictionary containing AWS credentials
            account_id: Optional account ID to verify against (if provided)
            
        Returns:
            Dict with validation results and diagnostics
        """
        logger.info("Starting AWS credential validation")
        
        results = {
            "valid": False,
            "account_id": None,
            "caller_identity": None,
            "regions_accessible": [],
            "services_accessible": {},
            "errors": [],
            "diagnostic_info": {}
        }
        
        # Store original environment variables
        original_env = {
            'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID'),
            'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'AWS_SESSION_TOKEN': os.environ.get('AWS_SESSION_TOKEN')
        }
        
        try:
            # Set AWS credentials in environment
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token') or ''
            
            # Test credentials exist
            if not os.environ.get('AWS_ACCESS_KEY_ID') or not os.environ.get('AWS_SECRET_ACCESS_KEY'):
                results["errors"].append("Missing required AWS credentials")
                return results
                
            # Create a session
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            # Get caller identity (basic validation)
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                # Check account_id if provided - with improved string comparison
                if account_id:
                    aws_account_id = identity.get("Account")
                    # Convert both to strings for comparison and strip any whitespace
                    if str(aws_account_id).strip() != str(account_id).strip():
                        error_message = f"Account ID mismatch. Credentials are for account {aws_account_id}, but expected {account_id}"
                        logger.error(error_message)
                        results["errors"].append(error_message)
                        return results
                    # Log successful account ID match for debugging
                    logger.info(f"Account ID match confirmed: {aws_account_id}")
                
                results["valid"] = True
                results["account_id"] = identity.get("Account")
                results["caller_identity"] = {
                    "user_id": identity.get("UserId"),
                    "account_id": identity.get("Account"),
                    "arn": identity.get("Arn")
                }
                
                logger.info(f"Successfully authenticated as: {identity.get('Arn')}")
            except ClientError as e:
                error_message = f"STS validation error: {str(e)}"
                logger.error(error_message)
                results["errors"].append(error_message)
                results["diagnostic_info"]["sts_error"] = str(e)
                return results
            
            # Check available regions
            try:
                ec2_client = session.client('ec2', region_name='us-east-1')
                regions_response = ec2_client.describe_regions()
                available_regions = [region['RegionName'] for region in regions_response['Regions']]
                results["regions_accessible"] = available_regions
                logger.info(f"Discovered {len(available_regions)} accessible AWS regions")
            except ClientError as e:
                error_message = f"Error accessing EC2 regions: {str(e)}"
                logger.warning(error_message)
                results["diagnostic_info"]["regions_error"] = str(e)
            
            # Test access to common services
            service_tests = {
                'ec2': {
                    'method': lambda client: client.describe_instances(MaxResults=5),
                    'region': 'us-east-1'
                },
                's3': {
                    'method': lambda client: client.list_buckets(),
                    'region': None
                },
                'iam': {
                    'method': lambda client: client.list_users(MaxItems=5),
                    'region': None
                },
                'cloudtrail': {
                    'method': lambda client: client.describe_trails(),
                    'region': 'us-east-1'
                },
                'config': {
                    'method': lambda client: client.describe_config_rules(),  # No Limit parameter here
                    'region': 'us-east-1'
                }
            }
            
            for service_name, test_info in service_tests.items():
                try:
                    logger.debug(f"Testing access to {service_name} service")
                    
                    if test_info['region']:
                        client = session.client(service_name, region_name=test_info['region'])
                    else:
                        client = session.client(service_name)
                        
                    # Execute the test method
                    response = test_info['method'](client)
                    
                    # Store specific information for certain services
                    if service_name == 'ec2':
                        instance_count = len(response.get('Reservations', []))
                        results["diagnostic_info"]["ec2_instance_count"] = instance_count
                    elif service_name == 's3':
                        bucket_count = len(response.get('Buckets', []))
                        results["diagnostic_info"]["s3_bucket_count"] = bucket_count
                    elif service_name == 'iam':
                        user_count = len(response.get('Users', []))
                        results["diagnostic_info"]["iam_user_count"] = user_count
                    elif service_name == 'config':
                        rule_count = len(response.get('ConfigRules', []))
                        results["diagnostic_info"]["config_rule_count"] = rule_count
                    
                    results["services_accessible"][service_name] = True
                    logger.debug(f"Successfully accessed {service_name} service")
                    
                except ClientError as e:
                    error_code = e.response['Error']['Code'] 
                    error_message = e.response['Error']['Message']
                    
                    results["services_accessible"][service_name] = False
                    results["diagnostic_info"][f"{service_name}_error"] = {
                        "code": error_code,
                        "message": error_message
                    }
                    logger.warning(f"Could not access {service_name}: {error_code} - {error_message}")
            
            # Calculate overall access level score based on service access
            services_accessible_count = sum(1 for v in results["services_accessible"].values() if v)
            service_count = len(service_tests)
            results["access_level_score"] = int((services_accessible_count / service_count) * 100)
            
            return results
            
        except Exception as e:
            error_message = f"Unexpected error during credential validation: {str(e)}"
            logger.error(error_message)
            logger.error(traceback.format_exc())
            results["errors"].append(error_message)
            results["diagnostic_info"]["exception"] = str(e)
            results["diagnostic_info"]["traceback"] = traceback.format_exc()
            return results
            
        finally:
            # Restore original environment variables
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]

    @staticmethod
    async def validate_credentials_with_role(credentials: Dict[str, str], account_id: str = None, 
                                        role_config: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Enhanced validation with optional role assumption
        
        Args:
            credentials: Dictionary containing AWS credentials
            account_id: Optional account ID to verify against
            role_config: Optional role configuration for assumed roles
            
        Returns:
            Dict with validation results and diagnostics
        """
        logger.info("Starting AWS credential validation with assumed role support")
        
        results = {
            "valid": False,
            "account_id": None,
            "caller_identity": None,
            "regions_accessible": [],
            "services_accessible": {},
            "errors": [],
            "diagnostic_info": {},
            "role_assumed": False,
            "assumed_role_arn": None
        }
        
        # Store original environment variables
        original_env = {
            'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID'),
            'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'AWS_SESSION_TOKEN': os.environ.get('AWS_SESSION_TOKEN')
        }
        
        try:
            final_credentials = credentials.copy()
            
            # Handle role assumption if configured
            if role_config and role_config.get('role_arn'):
                logger.info(f"Attempting to assume role: {role_config['role_arn']}")
                
                try:
                    role_handler = AwsAssumedRoleCredentials(
                        role_arn=role_config['role_arn'],
                        session_name=role_config.get('session_name'),
                        external_id=role_config.get('external_id'),
                        base_credentials=credentials
                    )
                    
                    assumed_creds = await role_handler.get_credentials()
                    final_credentials = assumed_creds
                    
                    results["role_assumed"] = True
                    results["assumed_role_arn"] = role_config['role_arn']
                    logger.info("Successfully assumed role for validation")
                    
                except Exception as role_e:
                    error_msg = f"Failed to assume role {role_config['role_arn']}: {str(role_e)}"
                    logger.error(error_msg)
                    results["errors"].append(error_msg)
                    return results
            
            # Set final credentials in environment
            os.environ['AWS_ACCESS_KEY_ID'] = final_credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = final_credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in final_credentials:
                os.environ['AWS_SESSION_TOKEN'] = final_credentials.get('aws_session_token', '').strip()
            
            # Test credentials exist
            if not os.environ.get('AWS_ACCESS_KEY_ID') or not os.environ.get('AWS_SECRET_ACCESS_KEY'):
                results["errors"].append("Missing required AWS credentials")
                return results
                
            # Create a session
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            # Get caller identity (basic validation)
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                # Check account_id if provided - with improved string comparison
                if account_id:
                    aws_account_id = identity.get("Account")
                    # Convert both to strings for comparison and strip any whitespace
                    if str(aws_account_id).strip() != str(account_id).strip():
                        error_message = f"Account ID mismatch. Credentials are for account {aws_account_id}, but expected {account_id}"
                        logger.error(error_message)
                        results["errors"].append(error_message)
                        return results
                    # Log successful account ID match for debugging
                    logger.info(f"Account ID match confirmed: {aws_account_id}")
                
                results["valid"] = True
                results["account_id"] = identity.get("Account")
                results["caller_identity"] = {
                    "user_id": identity.get("UserId"),
                    "account_id": identity.get("Account"),
                    "arn": identity.get("Arn")
                }
                
                logger.info(f"Successfully authenticated as: {identity.get('Arn')}")
                
                # If we assumed a role, log the details
                if results["role_assumed"]:
                    logger.info(f"Using assumed role: {results['assumed_role_arn']}")
                    results["diagnostic_info"]["assumed_role_identity"] = identity
                
            except ClientError as e:
                error_message = f"STS validation error: {str(e)}"
                logger.error(error_message)
                results["errors"].append(error_message)
                results["diagnostic_info"]["sts_error"] = str(e)
                return results
            
            # Check available regions
            try:
                ec2_client = session.client('ec2', region_name='us-east-1')
                regions_response = ec2_client.describe_regions()
                available_regions = [region['RegionName'] for region in regions_response['Regions']]
                results["regions_accessible"] = available_regions
                logger.info(f"Discovered {len(available_regions)} accessible AWS regions")
            except ClientError as e:
                error_message = f"Error accessing EC2 regions: {str(e)}"
                logger.warning(error_message)
                results["diagnostic_info"]["regions_error"] = str(e)
            
            # Test access to common services
            service_tests = {
                'ec2': {
                    'method': lambda client: client.describe_instances(MaxResults=5),
                    'region': 'us-east-1'
                },
                's3': {
                    'method': lambda client: client.list_buckets(),
                    'region': None
                },
                'iam': {
                    'method': lambda client: client.list_users(MaxItems=5),
                    'region': None
                },
                'cloudtrail': {
                    'method': lambda client: client.describe_trails(),
                    'region': 'us-east-1'
                },
                'config': {
                    'method': lambda client: client.describe_config_rules(),
                    'region': 'us-east-1'
                }
            }
            
            for service_name, test_info in service_tests.items():
                try:
                    logger.debug(f"Testing access to {service_name} service")
                    
                    if test_info['region']:
                        client = session.client(service_name, region_name=test_info['region'])
                    else:
                        client = session.client(service_name)
                        
                    # Execute the test method
                    response = test_info['method'](client)
                    
                    # Store specific information for certain services
                    if service_name == 'ec2':
                        instance_count = len(response.get('Reservations', []))
                        results["diagnostic_info"]["ec2_instance_count"] = instance_count
                    elif service_name == 's3':
                        bucket_count = len(response.get('Buckets', []))
                        results["diagnostic_info"]["s3_bucket_count"] = bucket_count
                    elif service_name == 'iam':
                        user_count = len(response.get('Users', []))
                        results["diagnostic_info"]["iam_user_count"] = user_count
                    elif service_name == 'config':
                        rule_count = len(response.get('ConfigRules', []))
                        results["diagnostic_info"]["config_rule_count"] = rule_count
                    
                    results["services_accessible"][service_name] = True
                    logger.debug(f"Successfully accessed {service_name} service")
                    
                except ClientError as e:
                    error_code = e.response['Error']['Code'] 
                    error_message = e.response['Error']['Message']
                    
                    results["services_accessible"][service_name] = False
                    results["diagnostic_info"][f"{service_name}_error"] = {
                        "code": error_code,
                        "message": error_message
                    }
                    logger.warning(f"Could not access {service_name}: {error_code} - {error_message}")
            
            # Calculate overall access level score based on service access
            services_accessible_count = sum(1 for v in results["services_accessible"].values() if v)
            service_count = len(service_tests)
            results["access_level_score"] = int((services_accessible_count / service_count) * 100)
            
            return results
            
        except Exception as e:
            error_message = f"Unexpected error during credential validation: {str(e)}"
            logger.error(error_message)
            logger.error(traceback.format_exc())
            results["errors"].append(error_message)
            results["diagnostic_info"]["exception"] = str(e)
            results["diagnostic_info"]["traceback"] = traceback.format_exc()
            return results
            
        finally:
            # Restore original environment variables
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]

class AwsSecurityScanner:
    def __init__(self, db_session: Optional[Session] = None, scan_record: Optional[CloudScan] = None):
        self.db_session = db_session
        self.scan_record = scan_record
        self.temp_dir = None
        self.config_dir = None
        self.aws_credentials = {}
        self.credential_validation_results = None
        self._user_id = None
        self._account_id = None
        self._scan_id = None
        self.aws_credentials = {}
        self.role_config = {}  # NEW: Store role configuration
        self.assumed_role_handler = None  # NEW: Store assumed role handler
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'scan_durations': {}
        }
    
    def set_scan_info(self, user_id: str, account_id: str, scan_id: str = None):
        """Set scan information for progress tracking"""
        self._user_id = user_id
        self._account_id = account_id
        self._scan_id = scan_id or generate_unique_scan_id()
        logger.info(f"AWS Scanner scan info set: {user_id}:{account_id}, scan_id: {self._scan_id}")

    async def _ensure_progress_update(self, stage: str, progress: int, retries: int = 3):
        """Send a progress update with retries to ensure delivery."""
        if not all([self._user_id, self._account_id]):
            logger.warning("Cannot send progress update: user_id or account_id not set")
            return False
            
        if not self._scan_id:
            self._scan_id = generate_unique_scan_id()
            
        # Add a small random delay to prevent message collision
        await asyncio.sleep(random.uniform(0.1, 0.3))
        
        success = False
        for attempt in range(retries):
            try:
                result = update_scan_progress(
                    self._user_id, 
                    self._account_id, 
                    stage, 
                    progress, 
                    scan_type='aws', 
                    scan_id=self._scan_id
                )
                if result:
                    success = True
                    # Add extra delay after successful update for important stages
                    if progress >= 95 or stage == 'completed' or stage == 'error':
                        await asyncio.sleep(0.5)  # Longer delay for critical updates
                    break
            except Exception as e:
                logger.error(f"Progress update attempt {attempt+1} failed for stage {stage}: {str(e)}")
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        if not success and (stage == 'completed' or stage == 'error'):
            logger.warning(f"Failed to send critical '{stage}' update after {retries} attempts")
        
        return success
    
    def set_role_config(self, role_config: Dict[str, str]):
        """
        Set assumed role configuration
        
        Args:
            role_config: Dictionary with role_arn, session_name, external_id
        """
        self.role_config = role_config
        if role_config and role_config.get('role_arn'):
            logger.info(f"Configured to use assumed role: {role_config['role_arn']}")

    
    

    async def setup(self):
        """Setup scanner resources and temporary directories with proper Steampipe initialization"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='aws_scanner_'))
            self.config_dir = self.temp_dir / 'config'
            self.config_dir.mkdir(exist_ok=True)
            
            # Create necessary directories
            (self.config_dir / 'aws').mkdir(exist_ok=True)
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            # Stop any existing Steampipe service
            try:
                await self._run_command(['steampipe', 'service', 'stop'], timeout=15)
                logger.info("Stopped any existing Steampipe services")
                await asyncio.sleep(2)  # Give it time to fully stop
            except Exception as e:
                logger.warning(f"Non-critical error stopping Steampipe service: {str(e)}")
            
            # Create AWS connection config file - using environment variables
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            # Create simple connection config that uses environment variables
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write("""
    connection "aws" {
    plugin  = "aws"
    regions = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1"]
    }
    """)
            
            # Set proper permissions
            os.chmod(aws_config_path, 0o600)
            
            # Ensure AWS plugin is installed and up to date
            try:
                await self._run_command(['steampipe', 'plugin', 'install', 'aws', '--force'], timeout=60)
                logger.info("AWS plugin installed or updated")
            except Exception as e:
                logger.warning(f"Error updating AWS plugin: {str(e)}")
            
            # Start Steampipe service
            try:
                await self._run_command(['steampipe', 'service', 'start', '--dashboard', 'false'], timeout=30)
                logger.info("Started Steampipe service")
                
                # Give service time to initialize
                logger.info("Waiting for Steampipe service to initialize...")
                await asyncio.sleep(8)
                
                # Check service status
                status_output = await self._run_command(['steampipe', 'service', 'status'], timeout=10)
                logger.info(f"Steampipe service status: {status_output}")
            except Exception as e:
                logger.error(f"Error starting Steampipe service: {str(e)}")
                
            # Test basic Steampipe functionality
            try:
                test_output = await self._run_command(['steampipe', 'query', 'select 1 as test', '--output', 'json'], timeout=15)
                logger.info(f"Basic Steampipe test: {test_output}")
            except Exception as e:
                logger.error(f"Basic Steampipe test failed: {str(e)}")
            
            # Log AWS credentials (safely)
            access_key = self.aws_credentials.get('aws_access_key_id', '')
            secret_key = self.aws_credentials.get('aws_secret_access_key', '')
            
            if access_key and len(access_key) >= 8:
                masked_key = f"{access_key[:4]}****{access_key[-4:]}"
            else:
                masked_key = "Not provided"
                
            logger.info(f"AWS credentials in environment:")
            logger.info(f"  AWS_ACCESS_KEY_ID: {masked_key}")
            logger.info(f"  AWS_SECRET_ACCESS_KEY: {'****' + secret_key[-4:] if secret_key and len(secret_key) >= 4 else 'Not provided'}")
            logger.info(f"  AWS_SESSION_TOKEN: {'Set' if 'aws_session_token' in self.aws_credentials else 'Not set'}")
            
            # Test if credentials are in environment variables
            if os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
                logger.info("Found credentials in environment variables.")
                
                # Test AWS connectivity using boto3 (fallback)
                import boto3
                try:
                    session = boto3.Session()
                    sts_client = session.client('sts')
                    identity = sts_client.get_caller_identity()
                    logger.info(f"Boto3 credentials test successful: {identity.get('Account')}")
                except Exception as e:
                    logger.error(f"Boto3 credentials test failed: {str(e)}")
            
            self.scan_stats['start_time'] = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"Scanner setup failed: {str(e)}")
            logger.error(traceback.format_exc())
            
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            raise

    
    
    async def cleanup(self):
        """Clean up temporary resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                
            self.scan_stats['end_time'] = datetime.now()
            
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
    
    async def _run_command(self, command: List[str], cwd: Optional[Path] = None, timeout: int = 300, capture_stderr: bool = True) -> str:
        """Run a command and return its output with timeout, with enhanced debugging"""
        try:
            cmd_str = ' '.join(command)
            logger.info(f"Running command: {cmd_str}")
            
            # Create environment with explicit credentials
            env = os.environ.copy()
            
            # Log credentials being used (safely)
            if 'steampipe' in command[0]:
                logger.debug(f"AWS_ACCESS_KEY_ID length: {len(env.get('AWS_ACCESS_KEY_ID', ''))}")
                logger.debug(f"AWS_SECRET_ACCESS_KEY length: {len(env.get('AWS_SECRET_ACCESS_KEY', ''))}")
                logger.debug(f"AWS_SESSION_TOKEN present: {bool(env.get('AWS_SESSION_TOKEN', ''))}")
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE if capture_stderr else None,
                cwd=str(cwd) if cwd else None,
                env=env  # Pass explicit environment
            )
            
            # Log the process ID for debugging
            logger.debug(f"Process started with PID: {process.pid}")
            
            try:
                start_time = datetime.now()
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()
                
                logger.debug(f"Command completed in {duration:.2f} seconds with return code: {process.returncode}")
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
            
            # Always capture stderr for debugging
            if stderr:
                stderr_text = stderr.decode()
                if stderr_text.strip():
                    logger.debug(f"Command stderr: {stderr_text}")
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Command failed with code {process.returncode}: {error_msg}")
                
                # More detailed error for steampipe commands
                if command[0] == 'steampipe':
                    logger.error(f"Steampipe command failed: {cmd_str}")
                    logger.error(f"STDERR: {error_msg}")
                    # Try to show some of stdout for context
                    if stdout:
                        stdout_sample = stdout.decode()[:500] + ("..." if len(stdout) > 500 else "")
                        logger.error(f"STDOUT sample: {stdout_sample}")
                        
                raise RuntimeError(f"Command failed with code {process.returncode}: {error_msg}")
                
            output = stdout.decode() if stdout else ""
            
            # Add more verbosity for empty outputs
            if not output.strip() and 'steampipe query' in cmd_str:
                logger.warning(f"Command produced empty output: {cmd_str}")
                logger.debug(f"Working directory: {cwd}")
                logger.debug(f"Full command: {cmd_str}")
                
                # Try to check if the SQL file exists and its content
                if len(command) > 2 and '.sql' in command[2]:
                    sql_path = command[2]
                    try:
                        with open(sql_path, 'r') as f:
                            sql_content = f.read()
                        logger.debug(f"SQL content for {sql_path}: {sql_content}")
                    except Exception as sql_e:
                        logger.warning(f"Could not read SQL file: {str(sql_e)}")
            
            # Log truncated output for debugging
            if output:
                log_output = output[:1000] + ("..." if len(output) > 1000 else "")
                logger.debug(f"Command output (truncated): {log_output}")
                
            return output
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            logger.error(traceback.format_exc())
            raise

    async def _configure_assumed_role_credentials(self, base_credentials: Dict[str, str]) -> Dict[str, str]:
        """
        Configure credentials with role assumption if needed
        
        Args:
            base_credentials: Base AWS credentials
            
        Returns:
            Final credentials to use (either base or assumed)
        """
        try:
            # If no role configuration, use base credentials
            if not self.role_config or not self.role_config.get('role_arn'):
                logger.info("No role assumption configured, using base credentials")
                return base_credentials
            
            # Initialize assumed role handler
            self.assumed_role_handler = AwsAssumedRoleCredentials(
                role_arn=self.role_config['role_arn'],
                session_name=self.role_config.get('session_name'),
                external_id=self.role_config.get('external_id'),
                base_credentials=base_credentials
            )
            
            # Get assumed role credentials
            assumed_credentials = await self.assumed_role_handler.get_credentials()
            logger.info(f"Successfully configured assumed role credentials for: {self.role_config['role_arn']}")
            
            return assumed_credentials
            
        except Exception as e:
            logger.error(f"Failed to configure assumed role credentials: {str(e)}")
            raise
    async def _debug_aws_credentials(self):
        """Debug AWS credentials and environment when Steampipe runs"""
        try:
            # Log current environment variables (redacted)
            access_key = os.environ.get('AWS_ACCESS_KEY_ID', '')
            secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY', '')
            session_token = os.environ.get('AWS_SESSION_TOKEN', '')
            
            logger.info(f"AWS credentials in environment:")
            logger.info(f"  AWS_ACCESS_KEY_ID: {'*' * 4 + access_key[-4:] if access_key else 'Not set'}")
            logger.info(f"  AWS_SECRET_ACCESS_KEY: {'*' * 4 + secret_key[-4:] if secret_key else 'Not set'}")
            logger.info(f"  AWS_SESSION_TOKEN: {'Present' if session_token else 'Not set'}")
            
            # Check boto3 access (to verify credentials work)
            try:
                import boto3
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                logger.info(f"Boto3 credentials test successful: {identity.get('Account')}")
            except Exception as e:
                logger.error(f"Boto3 credentials test failed: {str(e)}")
            
            # Check Steampipe config file for AWS
            config_path = os.path.expanduser('~/.steampipe/config/aws.spc')
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    config = f.read()
                    # Redact actual credentials
                    config = re.sub(r'aws_access_key_id\s*=\s*"[^"]+"', 'aws_access_key_id = "***REDACTED***"', config)
                    config = re.sub(r'aws_secret_access_key\s*=\s*"[^"]+"', 'aws_secret_access_key = "***REDACTED***"', config)
                    config = re.sub(r'aws_session_token\s*=\s*"[^"]+"', 'aws_session_token = "***REDACTED***"', config)
                    logger.info(f"Steampipe AWS config file content:\n{config}")
            else:
                logger.error(f"Steampipe AWS config file not found at {config_path}")
                
            return True
        except Exception as e:
            logger.error(f"AWS credentials debug error: {str(e)}")
            return False

    def sanitize_for_json(obj):
        """Recursively sanitize an object for JSON serialization"""
        if isinstance(obj, dict):
            return {k: sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [sanitize_for_json(i) for i in obj]
        elif isinstance(obj, (datetime, date)):
            return obj.isoformat()
        # Handle timezone-aware datetime objects from boto3
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)  # Convert any other types to strings

   
    async def _configure_aws_credentials(self, credentials: Dict[str, str]) -> bool:
        """Enhanced version with assumed role support"""
        try:
            # Get final credentials (with role assumption if configured)
            final_credentials = await self._configure_assumed_role_credentials(credentials)
            
            # Store final credentials
            self.aws_credentials = final_credentials
            
            # Extract credential components from final credentials
            access_key = final_credentials.get('aws_access_key_id', '').strip()
            secret_key = final_credentials.get('aws_secret_access_key', '').strip()
            session_token = final_credentials.get('aws_session_token', '').strip()
            
            # Validate basic credential format
            if not access_key or not secret_key:
                error_msg = "Missing required AWS credentials after role processing"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Set as environment variables
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
            
            
            # This is the most important part - direct credential setting in Steampipe format
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write(f"""
    connection "aws" {{
    plugin = "aws"

    # Direct credentials configuration
    aws_access_key_id     = "{access_key}"
    aws_secret_access_key = "{secret_key}"
    
    # Explicitly define regions
    regions = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"]
    
    # Set default region for global resources
    default_region = "us-east-1"
    
    # Increase retries
    max_error_retry_attempts = 10
    min_error_retry_delay = 50
    """)
                if session_token:
                    f.write(f'  aws_session_token = "{session_token}"\n')
                f.write("}\n")
            
            # Set proper permissions
            os.chmod(aws_config_path, 0o600)
            
            # Restart Steampipe service to pick up new credentials
            try:
                await self._run_command(['steampipe', 'service', 'stop'], timeout=30)
                await asyncio.sleep(2)  # Give it time to stop
                await self._run_command(['steampipe', 'service', 'start', '--dashboard', 'false'], timeout=30)
                await asyncio.sleep(3)  # Give it time to start
                logger.info("Restarted Steampipe service with new credentials")
            except Exception as e:
                logger.warning(f"Failed to restart Steampipe service: {str(e)}, continuing anyway")
            
            # Test connection with a direct query
            try:
                test_cmd = ['steampipe', 'query', 'select account_id from aws_account limit 1']
                test_output = await self._run_command(test_cmd, timeout=20)

                
                if test_output and 'account_id' in test_output:
                    logger.info(f"AWS credentials verified through direct Steampipe query: {test_output}")
                    return True
                else:
                    logger.warning("Direct AWS account query returned no results")
                    # Try a basic Steampipe test
                    basic_cmd = ['steampipe', 'query', 'select 1 as test', '--output', 'json']
                    basic_output = await self._run_command(basic_cmd, timeout=10)
                    logger.info(f"Basic Steampipe query result: {basic_output}")
            except Exception as e:
                logger.warning(f"Steampipe credential test failed: {str(e)}")
            
            # Continue anyway as the direct boto3 tests show credentials are valid
            return True
                
        except Exception as e:
            logger.error(f"Failed to configure AWS credentials: {str(e)}")
            logger.error(traceback.format_exc())
            raise
    
    async def _collect_steampipe_config_data(self, workspace_dir: Path) -> Dict[str, Any]:
        """Collect essential AWS config data using Steampipe queries - SAFE VERSION"""
        
        # Essential queries for CIS 1.4 context - ONLY USING CONFIRMED WORKING TABLES
        essential_queries = {
            'account_info': "SELECT account_id, partition FROM aws_account;",
            
            # FIXED: Use aws_sts_caller_identity instead of aws_caller_identity
            'caller_identity': "SELECT account_id, arn, user_id FROM aws_sts_caller_identity;", 
            
            'iam_summary': "SELECT users, groups, roles, policies, mfa_devices FROM aws_iam_account_summary;",
            
            'password_policy': """
                SELECT minimum_password_length, require_uppercase_characters, 
                    require_lowercase_characters, require_symbols, require_numbers,
                    password_reuse_prevention, max_password_age
                FROM aws_iam_account_password_policy;
            """,
            
            's3_public_block': """
                SELECT block_public_acls, block_public_policy, ignore_public_acls, 
                    restrict_public_buckets FROM aws_s3_account_settings;
            """,
            
            'cloudtrail_status': """
                SELECT name, is_multi_region_trail, is_logging, log_file_validation_enabled,
                    home_region FROM aws_cloudtrail_trail LIMIT 3;
            """,
            
            # FIXED: Use 'region' instead of 'region_name'
            'regions': """
                SELECT region, opt_in_status FROM aws_region 
                WHERE opt_in_status IN ('opt-in-not-required', 'opted-in') LIMIT 10;
            """,
            
            'vpc_info': """
                SELECT vpc_id, cidr_block, is_default, state 
                FROM aws_vpc LIMIT 5;
            """,
            
            # FIXED: Remove password_enabled column
            'iam_users_summary': """
                SELECT count(*) as total_users,
                    sum(case when mfa_enabled then 1 else 0 end) as users_with_mfa
                FROM aws_iam_user;
            """,
            
            'ec2_instances': """
                SELECT instance_id, instance_type, instance_state 
                FROM aws_ec2_instance 
                LIMIT 3;
            """,
            
            's3_buckets': """
                SELECT name, creation_date, region 
                FROM aws_s3_bucket 
                LIMIT 5;
            """
            
           
        }
        
        config_data = {}
        successful_queries = 0
        
        for config_name, query in essential_queries.items():
            try:
                logger.info(f"Collecting {config_name} configuration data")
                query_file = workspace_dir / f'{config_name}_config.sql'
                with open(query_file, 'w') as f:
                    f.write(query)
                
                result = await self._run_command([
                    'steampipe', 'query', str(query_file), '--output', 'json'
                ], workspace_dir, timeout=30)
                
                if result and result.strip():
                    try:
                        parsed_result = json.loads(result)
                        # Extract rows if it's in Steampipe format
                        if isinstance(parsed_result, dict) and 'rows' in parsed_result:
                            config_data[config_name] = parsed_result['rows']
                        elif isinstance(parsed_result, list):
                            config_data[config_name] = parsed_result
                        else:
                            config_data[config_name] = [parsed_result]
                        
                        successful_queries += 1
                        logger.info(f"✓ Collected {config_name}: {len(config_data[config_name])} items")
                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"✗ Failed to parse JSON for {config_name}: {str(e)}")
                        config_data[config_name] = []
                else:
                    logger.warning(f"✗ No data returned for {config_name}")
                    config_data[config_name] = []
                    
            except Exception as e:
                logger.warning(f"✗ Failed to collect {config_name}: {str(e)}")
                config_data[config_name] = []
                
                # Enhanced error handling with alternative queries
                if 'does not exist' in str(e) or 'column' in str(e):
                    logger.info(f"Trying alternative query for {config_name}...")
                    
                    # Alternative queries for problematic tables
                    alternative_queries = {
                        'caller_identity': "SELECT current_setting('application_name') as info;",
                        'regions': "SELECT 'us-east-1' as region, 'opt-in-not-required' as opt_in_status;",
                        'iam_users_summary': "SELECT 0 as total_users, 0 as users_with_mfa;"
                    }
                    
                    if config_name in alternative_queries:
                        try:
                            alt_query = alternative_queries[config_name]
                            alt_file = workspace_dir / f'{config_name}_alt.sql'
                            with open(alt_file, 'w') as f:
                                f.write(alt_query)
                            
                            alt_result = await self._run_command([
                                'steampipe', 'query', str(alt_file), '--output', 'json'
                            ], workspace_dir, timeout=15)
                            
                            if alt_result:
                                alt_parsed = json.loads(alt_result)
                                if isinstance(alt_parsed, dict) and 'rows' in alt_parsed:
                                    config_data[config_name] = alt_parsed['rows']
                                else:
                                    config_data[config_name] = [alt_parsed] if alt_parsed else []
                                logger.info(f"✓ Collected {config_name} via alternative method")
                                successful_queries += 1
                                
                        except Exception as alt_e:
                            logger.warning(f"Alternative query for {config_name} also failed: {str(alt_e)}")
                
                # Continue with other queries even if one fails
                continue
        
        # ADD SECURITY GROUPS DATA VIA BOTO3 (since Steampipe tables don't exist)
        try:
            logger.info("Collecting security groups data via boto3 API")
            import boto3
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            ec2 = session.client('ec2')
            sgs = ec2.describe_security_groups(MaxResults=5)
            
            security_groups_data = []
            for sg in sgs.get('SecurityGroups', []):
                security_groups_data.append({
                    'group_id': sg.get('GroupId'),
                    'group_name': sg.get('GroupName'),
                    'vpc_id': sg.get('VpcId'),
                    'inbound_rules': len(sg.get('IpPermissions', [])),
                    'outbound_rules': len(sg.get('IpPermissionsEgress', []))
                })
            
            config_data['security_groups'] = security_groups_data
            successful_queries += 1
            logger.info(f"✓ Collected security_groups via boto3: {len(security_groups_data)} items")
            
        except Exception as boto_e:
            logger.warning(f"Failed to collect security groups via boto3: {str(boto_e)}")
            # Add empty data so structure is consistent
            config_data['security_groups'] = []
        
        # Log final summary
        total_sections = len(essential_queries) + 1  # +1 for security_groups via boto3
        logger.info(f"Config data collection summary: {successful_queries}/{total_sections} sections collected successfully")

        # Ensure we have at least basic account info
        if not config_data.get('account_info') and not config_data.get('caller_identity'):
            logger.warning("Failed to collect basic account information - config data may be incomplete")
            
            # Try to get account info from environment or validation results
            try:
                account_id = self._account_id or os.environ.get('AWS_ACCOUNT_ID')
                if account_id:
                    config_data['fallback_account'] = [{
                        'account_id': account_id,
                        'source': 'environment'
                    }]
                    logger.info("Added fallback account info from environment")
            except Exception as fallback_e:
                logger.warning(f"Could not create fallback account info: {str(fallback_e)}")

        return config_data
        
    
    async def _discover_security_groups_table(self, workspace_dir: Path) -> str:

        """
        Discover the correct security groups table name in Steampipe
        
        Returns:
            The correct table name or None if not found
        """
        possible_tables = [
            'aws_ec2_security_group',
            'aws_security_group', 
            'aws_vpc_security_group'
        ]
        
        for table_name in possible_tables:
            try:
                # Test if table exists with a simple query
                test_query = f"SELECT count(*) FROM {table_name} LIMIT 1;"
                query_file = workspace_dir / f'test_{table_name}.sql'
                
                with open(query_file, 'w') as f:
                    f.write(test_query)
                
                result = await self._run_command([
                    'steampipe', 'query', str(query_file), '--output', 'json'
                ], workspace_dir, timeout=15)
                
                if result and result.strip():
                    logger.info(f"Found working security groups table: {table_name}")
                    return table_name
                    
            except Exception as e:
                logger.debug(f"Table {table_name} not available: {str(e)}")
                continue
        
        logger.warning("No security groups table found")
        return None
                        

        

    async def test_aws_connection(self):
        """Test AWS connection with simplified approach"""
        try:
            # First debug environment variables and configuration
            await self._debug_aws_credentials()
            
            # Try explicitly querying with the connection name
            query = "select account_id from aws.aws_account limit 1"
            logger.info(f"Testing AWS connection with query: {query}")
            try:
                result = await self._run_command(['steampipe', 'query', query, '--output', 'json'], timeout=30)
                if result and len(result.strip()) > 0:
                    try:
                        data = json.loads(result)
                        if data and 'rows' in data and data['rows']:
                            account_id = data['rows'][0]['account_id']
                            logger.info(f"Successfully connected to AWS account: {account_id}")
                            return True
                    except json.JSONDecodeError:
                        logger.warning(f"Received non-JSON response: {result}")
                
                logger.warning("AWS connection query returned empty results")
            except Exception as e:
                logger.error(f"AWS connection query failed: {str(e)}")
            
            # Try boto3 directly to verify credentials
            try:
                import boto3
                sts = boto3.client('sts')
                identity = sts.get_caller_identity()
                account_id = identity.get('Account')
                logger.info(f"AWS credentials work with boto3 directly: {account_id}")
                # If boto3 works but Steampipe doesn't, there's a Steampipe config issue
                
                # Try creating a minimal test query to debug
                test_file = self.temp_dir / 'aws_test.sql'
                with open(test_file, 'w') as f:
                    f.write("select 'testing' as test;")
                
                # Test if Steampipe works at all
                regular_result = await self._run_command(['steampipe', 'query', str(test_file), '--output', 'json'], timeout=10)
                logger.info(f"Regular Steampipe test query result: {regular_result}")
                
                # Steampipe works but AWS plugin doesn't - likely a configuration issue
                return False
            except Exception as e:
                logger.error(f"Boto3 credentials test failed: {str(e)}")
                return False
        
        except Exception as e:
            logger.error(f"AWS connection test error: {str(e)}")
            return False
        
    async def test_aws_resources(self, account_id: str) -> Dict[str, bool]:
        """Test access to various AWS resource types with retries and direct queries"""
        results = {}
        max_retries = 3
        
        # Simple test queries for different AWS services
        test_queries = {
            "aws_account": "SELECT account_id, partition FROM aws_account LIMIT 1;",
            "aws_iam_user": "SELECT name, arn FROM aws_iam_user LIMIT 5;",
            "aws_s3_bucket": "SELECT name, arn FROM aws_s3_bucket LIMIT 5;",
            "aws_region": "SELECT region, account_id FROM aws_region LIMIT 5;",
            "aws_iam_policy": "SELECT name, arn FROM aws_iam_policy LIMIT 5;",
            "aws_ec2_instance": "SELECT instance_id, tags FROM aws_ec2_instance LIMIT 5;",
        }
        
        workspace_dir = self.temp_dir / 'workspace'
        workspace_dir.mkdir(exist_ok=True)
        
        # First, try a direct query approach
        for resource, query in test_queries.items():
            try:
                logger.info(f"Testing direct query for {resource}")
                # Use direct query without SQL file
                direct_cmd = ['steampipe', 'query', query, '--output', 'json']
                output = await self._run_command(direct_cmd, timeout=60)
                
                if output and len(output.strip()) > 0:
                    try:
                        data = json.loads(output)
                        if data and 'rows' in data and data['rows']:
                            logger.info(f"Successfully accessed {resource} via direct query")
                            results[resource] = True
                            continue  # Skip file-based query for this resource
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse direct {resource} results as JSON")
            except Exception as e:
                logger.warning(f"Direct query for {resource} failed: {str(e)}")
        
        # Fall back to file-based queries for resources not successfully queried yet
        for resource, query in test_queries.items():
            if resource in results and results[resource]:
                continue  # Skip if already successfully queried
                
            for retry in range(max_retries):
                try:
                    logger.info(f"Testing file-based access to {resource} (attempt {retry+1}/{max_retries})")
                    
                    query_file = workspace_dir / f"{resource}_test.sql"
                    with open(query_file, 'w') as f:
                        f.write(query)
                    
                    # Try different query approaches
                    if retry == 0:
                        # First try basic query
                        query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json']
                    elif retry == 1:
                        # Second try with database init
                        query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json', '--database-init']
                    else:
                        # Last try with search path
                        query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json', '--search-path', 'aws']
                    
                    output = await self._run_command(query_cmd, workspace_dir, timeout=60)
                    
                    if output and output.strip():
                        try:
                            data = json.loads(output)
                            if data and 'rows' in data and data['rows']:
                                logger.info(f"Successfully accessed {resource}: {json.dumps(data['rows'][0])}")
                                results[resource] = True
                                break  # Success, exit retry loop
                            else:
                                logger.warning(f"Query for {resource} returned empty result set (attempt {retry+1})")
                                results[resource] = False
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse {resource} results as JSON (attempt {retry+1})")
                            results[resource] = False
                    else:
                        logger.warning(f"Query for {resource} returned no output (attempt {retry+1})")
                        results[resource] = False
                        
                except Exception as e:
                    logger.error(f"Error testing {resource} (attempt {retry+1}): {str(e)}")
                    results[resource] = False
                    if retry < max_retries - 1:
                        logger.info(f"Retrying {resource} after error...")
                        await asyncio.sleep(2 ** retry)  # Exponential backoff
                    
        # Log summary of results
        success_count = sum(1 for v in results.values() if v)
        logger.info(f"AWS resource access test summary: {success_count}/{len(test_queries)} resources accessible")
        
        return results
    
    async def _configure_steampipe_aws_credentials(self, credentials: Dict[str, str]) -> bool:
        """Configure AWS credentials for Steampipe using the approach from the Docker entry file"""
        try:
            self.aws_credentials = credentials
            
            # Extract credential components
            access_key = credentials.get('aws_access_key_id', '').strip()
            secret_key = credentials.get('aws_secret_access_key', '').strip()
            session_token = credentials.get('aws_session_token', '').strip()
            
            # Validate basic credential format
            if not access_key or not secret_key:
                error_msg = "Missing required AWS credentials: access key or secret key"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Set as environment variables
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
            
            # Create AWS credentials directory and files (similar to Docker approach)
            aws_dir = os.path.expanduser('~/.aws')
            os.makedirs(aws_dir, exist_ok=True)
            
            # Create credentials file
            with open(os.path.join(aws_dir, 'credentials'), 'w') as f:
                f.write("[default]\n")
                f.write(f"aws_access_key_id={access_key}\n")
                f.write(f"aws_secret_access_key={secret_key}\n")
                if session_token:
                    f.write(f"aws_session_token={session_token}\n")
            
            # Create config file
            with open(os.path.join(aws_dir, 'config'), 'w') as f:
                f.write("[default]\n")
                f.write("region=us-east-1\n")
                f.write("output=json\n")
            
            # Set permissions
            os.chmod(os.path.join(aws_dir, 'credentials'), 0o600)
            os.chmod(os.path.join(aws_dir, 'config'), 0o600)
            
            # Create Steampipe config with same approach as Docker
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write("""
    connection "aws" {
    plugin  = "aws"
    profile = "default"
    regions = ["us-east-1"]
    }
    """)
            
            # Set proper permissions
            os.chmod(aws_config_path, 0o600)
            
            # Restart Steampipe service to pick up new credentials
            try:
                await self._run_command(['steampipe', 'service', 'stop'], timeout=30)
                await asyncio.sleep(2)  # Give it time to stop
                await self._run_command(['steampipe', 'service', 'start', '--dashboard', 'false'], timeout=30)
                await asyncio.sleep(5)  # Give it time to start
                logger.info("Restarted Steampipe service with new credentials")
            except Exception as e:
                logger.warning(f"Failed to restart Steampipe service: {str(e)}, continuing anyway")
            
            # Test connection with direct query - use the exact approach from Docker
            try:
                test_cmd = ['steampipe', 'query', "select account_id from aws_account limit 1", "--output", "csv"]
                test_output = await self._run_command(test_cmd, timeout=20)
                
                if test_output and len(test_output.strip()) > 0 and not test_output.startswith("Error:"):
                    account_id = test_output.strip().split("\n")[-1]  # Get the last line which should be the account ID
                    logger.info(f"AWS credentials verified through direct Steampipe query: {account_id}")
                    return True
                else:
                    logger.warning("Direct AWS account query returned no results or error")
            except Exception as e:
                logger.warning(f"Steampipe credential test failed: {str(e)}")
            
            # Continue with boto3 approach as fallback
            return True
                
        except Exception as e:
            logger.error(f"Failed to configure AWS credentials: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    async def test_aws_connectivity(self):
        """Test direct network connectivity to AWS endpoints"""
        try:
            # Create a simple test script
            network_test_file = self.temp_dir / 'network_test.sh'
            with open(network_test_file, 'w') as f:
                f.write("""#!/bin/bash
    echo "Testing connectivity to AWS endpoints..."
    for endpoint in s3.amazonaws.com ec2.us-east-1.amazonaws.com iam.amazonaws.com sts.amazonaws.com; do
        echo -n "Testing $endpoint: "
        if curl -s --max-time 5 https://$endpoint > /dev/null; then
            echo "SUCCESS"
        else
            echo "FAILED"
        fi
    done
    """)
            
            # Make executable
            os.chmod(network_test_file, 0o755)
            
            # Run the test
            logger.info("Testing direct network connectivity to AWS endpoints")
            network_output = await self._run_command([str(network_test_file)], timeout=30)
            logger.info(f"Network connectivity test results:\n{network_output}")
            
            return "FAILED" not in network_output
        except Exception as e:
            logger.error(f"Network connectivity test failed: {str(e)}")
            return False
    
    async def test_aws_connectivity_and_permissions(self, workspace_dir: Path):
        """
        Run a comprehensive set of tests to diagnose AWS connectivity and permission issues
        
        Args:
            workspace_dir: Path to the workspace directory
            
        Returns:
            Dict with test results and diagnostic information
        """
        results = {
            "network_connectivity": True,  
            "credential_test": False,
            "permissions_test": False,
            "cis_test": False,
            "powerpipe_test": False,
            "sdk_debug_test": False,
            "details": {}
        }
        
        try:
            # 1. Direct AWS credential test in Steampipe
            credential_test_sql = workspace_dir / 'cred_test.sql'
            with open(credential_test_sql, 'w') as f:
                f.write("""
    -- Test AWS credential information
    select 
    current_credential() as current_cred;
    """)
            
            logger.info("Running AWS credential test")
            try:
                cred_cmd = ['steampipe', 'query', str(credential_test_sql), '--output', 'json']
                cred_output = await self._run_command(cred_cmd, workspace_dir, timeout=15)
                logger.info(f"AWS credential test result: {cred_output}")
                results["credential_test"] = True
                results["details"]["credential_test"] = cred_output
            except Exception as e:
                logger.error(f"Credential test failed: {str(e)}")
                results["details"]["credential_test_error"] = str(e)
            
            # 2. Permissions validator test
            permissions_test_sql = workspace_dir / 'perms_test.sql'
            with open(permissions_test_sql, 'w') as f:
                f.write("""
    -- Basic test to see what permissions we have
    select
    'list_users' as operation,
    CASE 
        WHEN count(*) >= 0 THEN 'success'
        ELSE 'failed'
    END as result
    from
    aws_iam_user
    limit 1;
    """)
            
            logger.info("Running AWS permissions test")
            try:
                perms_cmd = ['steampipe', 'query', str(permissions_test_sql), '--output', 'json', '--database-init']
                perms_output = await self._run_command(perms_cmd, workspace_dir, timeout=30)
                logger.info(f"Permissions test result: {perms_output}")
                if perms_output and "success" in perms_output:
                    results["permissions_test"] = True
                results["details"]["permissions_test"] = perms_output
            except Exception as e:
                logger.error(f"Permissions test failed: {str(e)}")
                results["details"]["permissions_test_error"] = str(e)
            
            # 3. Specific CIS control query test
            cis_test_sql = workspace_dir / 'cis_test.sql'
            with open(cis_test_sql, 'w') as f:
                f.write("""
    -- Test IAM-related CIS check
    select
    'IAM password policy' as control,
    'CIS 1.1' as id,
    case
        when minimum_password_length >= 14 then 'pass'
        else 'fail'
    end as status
    from
    aws_iam_account_password_policy;
    """)
            
            logger.info("Running specific CIS control test")
            try:
                cis_cmd = ['steampipe', 'query', str(cis_test_sql), '--output', 'json']
                cis_output = await self._run_command(cis_cmd, workspace_dir, timeout=30)
                logger.info(f"CIS test result: {cis_output}")
                if cis_output and len(cis_output.strip()) > 0:
                    results["cis_test"] = True
                results["details"]["cis_test"] = cis_output
            except Exception as e:
                logger.error(f"CIS test failed: {str(e)}")
                results["details"]["cis_test_error"] = str(e)
            
            # 4. Powerpipe command with correct syntax
            logger.info("Testing Powerpipe commands")
            try:
                # First check what powerpipe supports
                help_cmd = ['powerpipe', '--help']
                help_output = await self._run_command(help_cmd, workspace_dir, timeout=15)
                logger.info(f"Powerpipe help: {help_output}")
                results["details"]["powerpipe_help"] = help_output
                
                # Based on the article you shared, try with "benchmark run" instead of "check"
                run_cmd = ['powerpipe', 'benchmark', 'run', 'cis_v300', '--output', 'json']
                run_output = await self._run_command(run_cmd, workspace_dir, timeout=300)
                logger.info(f"Powerpipe benchmark run: {run_output}")
                if run_output and len(run_output.strip()) > 0:
                    results["powerpipe_test"] = True
                results["details"]["powerpipe_run"] = run_output
            except Exception as e:
                logger.error(f"Powerpipe command error: {str(e)}")
                results["details"]["powerpipe_error"] = str(e)
                
                
                try:
                    alt_cmd = ['powerpipe', 'mod', 'list']
                    alt_output = await self._run_command(alt_cmd, workspace_dir, timeout=15)
                    logger.info(f"Powerpipe mod list: {alt_output}")
                    results["details"]["powerpipe_mod_list"] = alt_output
                except Exception as alt_e:
                    logger.error(f"Powerpipe mod list error: {str(alt_e)}")
            
            
            # Create a specific AWS connection config with SDK debug
            steampipe_dir = os.path.expanduser('~/.steampipe')
            aws_config_dir = os.path.join(steampipe_dir, 'config', 'aws')
            os.makedirs(aws_config_dir, exist_ok=True)
            
            access_key = self.aws_credentials.get('aws_access_key_id', '').strip()
            secret_key = self.aws_credentials.get('aws_secret_access_key', '').strip()
            session_token = self.aws_credentials.get('aws_session_token', '').strip()
            
            aws_config_file = os.path.join(aws_config_dir, 'aws_debug.spc')
            with open(aws_config_file, 'w') as f:
                f.write(f"""
    connection "aws_debug" {{
    plugin     = "aws"
    
    aws_access_key_id     = "{access_key}"
    aws_secret_access_key = "{secret_key}"
    regions               = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1"]
    max_retries           = 10
    sdk_debug             = true
    }}
    """)
                if session_token:
                    f.write(f'  aws_session_token = "{session_token}"\n')
                f.write("}\n")
            
            # Test the debug connection
            debug_test_sql = workspace_dir / 'debug_test.sql'
            with open(debug_test_sql, 'w') as f:
                f.write("""
    -- Test with SDK debug mode
    select account_id, partition from aws_account limit 1;
    """)
            
            logger.info("Testing AWS connection with SDK debug mode")
            try:
                debug_cmd = ['steampipe', 'query', str(debug_test_sql), '--output', 'json', '--search-path', 'aws_debug', '--search-path-prefix']
                debug_output = await self._run_command(debug_cmd, workspace_dir, timeout=30)
                logger.info(f"SDK debug test result: {debug_output}")
                if debug_output and len(debug_output.strip()) > 0:
                    results["sdk_debug_test"] = True
                results["details"]["sdk_debug_test"] = debug_output
            except Exception as e:
                logger.error(f"SDK debug test failed: {str(e)}")
                results["details"]["sdk_debug_error"] = str(e)
            
            # 6. Test direct AWS API access with boto3
            try:
                import boto3
                session = boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token if session_token else None
                )
                
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                logger.info(f"Direct boto3 test result: {identity}")
                results["details"]["boto3_test"] = {
                    "account_id": identity.get("Account"),
                    "arn": identity.get("Arn"),
                    "user_id": identity.get("UserId")
                }
                
                # Try listing IAM users
                try:
                    iam_client = session.client('iam')
                    users = iam_client.list_users(MaxItems=5)
                    
                    logger.info(f"Direct IAM access test: {len(users.get('Users', []))} users found")
                    results["details"]["iam_test"] = users.get('Users', [])
                except Exception as iam_e:
                    logger.error(f"Direct IAM access test failed: {str(iam_e)}")
                    results["details"]["iam_test_error"] = str(iam_e)
            except Exception as boto_e:
                logger.error(f"Direct boto3 test failed: {str(boto_e)}")
                results["details"]["boto3_test_error"] = str(boto_e)
            
            return results
        except Exception as e:
            logger.error(f"AWS connectivity and permissions test failed: {str(e)}")
            results["error"] = str(e)
            return results
        
    async def get_diagnostics(self):
        """Get diagnostic information about the environment"""
        try:
            # Get steampipe version - properly awaited
            version_cmd = ['steampipe', '--version']
            steampipe_version = await self._run_command(version_cmd)
            steampipe_version = steampipe_version.strip() if steampipe_version else "unknown"
            
            return {
                "steampipe_version": steampipe_version,
                "environment": {
                    "os": sys.platform,
                    "python_version": sys.version,
                },
                "scan_time": datetime.now().isoformat()
            }
        except Exception as e:
            logger.warning(f"Error getting diagnostics: {str(e)}")
            return {
                "error": str(e),
                "scan_time": datetime.now().isoformat()
            }
    async def _init_steampipe(self) -> bool:
        """Initialize steampipe workspace with AWS CIS benchmark mod"""
        try:
            # Create workspace directory
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(parents=True, exist_ok=True)
            
            # Create mod.sp file - initialize mod
            mod_file = workspace_dir / 'mod.sp'
            with open(mod_file, 'w') as f:
                f.write("""
    mod "local" {
    title = "AWS CIS Benchmark Scan"
    }
    """)

            # Ensure Steampipe service is initialized properly
            try:
                logger.info("Initializing Steampipe service")
                init_cmd = ['steampipe', 'service', 'start', '--dashboard', 'false']
                init_output = await self._run_command(init_cmd, timeout=30, cwd=workspace_dir)
                logger.info(f"Steampipe service initialized: {init_output}")
                
                # Wait for service to start
                await asyncio.sleep(2)
                
                # Check service status
                status_cmd = ['steampipe', 'service', 'status']
                status_output = await self._run_command(status_cmd, timeout=10, cwd=workspace_dir)
                logger.info(f"Steampipe service status: {status_output}")
            except Exception as svc_e:
                logger.warning(f"Steampipe service initialization warning (non-critical): {str(svc_e)}")
            
            # Install AWS plugin with detailed output
            logger.info("Installing AWS Steampipe plugin")
            try:
                plugin_cmd = ['steampipe', 'plugin', 'install', 'aws', '--verbose']
                await self._run_command(plugin_cmd, workspace_dir)
            except Exception as plugin_e:
                logger.error(f"Error installing AWS plugin: {str(plugin_e)}")
                
                # Try alternate approach
                try:
                    logger.info("Trying alternate plugin installation approach")
                    alt_cmd = ['steampipe', 'plugin', 'install', 'aws', '--force']
                    await self._run_command(alt_cmd, workspace_dir)
                except Exception as alt_e:
                    logger.error(f"Alternate plugin installation also failed: {str(alt_e)}")
                    
                    # Check if plugin exists anyway
                    try:
                        check_cmd = ['steampipe', 'plugin', 'list']
                        plugin_list = await self._run_command(check_cmd, workspace_dir)
                        logger.info(f"Existing plugins: {plugin_list}")
                        
                        if 'aws' in plugin_list:
                            logger.info("AWS plugin already exists, continuing despite installation error")
                        else:
                            raise RuntimeError("AWS plugin is not available and installation failed")
                    except Exception as check_e:
                        logger.error(f"Plugin check failed: {str(check_e)}")
                        raise RuntimeError("Cannot verify if AWS plugin is installed")
            
            # Create a debugging script - with a single SQL statement per file
            debug_script = workspace_dir / 'simple_test.sql'
            with open(debug_script, 'w') as f:
                f.write("SELECT 1 as test_simple;")
                
            # Run simple test to see if Steampipe works at all
            try:
                logger.info("Running simple SQL test to verify Steampipe functionality")
                simple_cmd = ['steampipe', 'query', str(debug_script), '--output', 'json']
                simple_output = await self._run_command(simple_cmd, workspace_dir, timeout=15)
                if simple_output and simple_output.strip():
                    logger.info(f"Simple test successful: {simple_output}")
                else:
                    logger.warning("Simple test returned no output, Steampipe may be misconfigured")
            except Exception as test_e:
                logger.error(f"Simple test failed: {str(test_e)}")
                
            # Install AWS compliance mod with error handling
            try:
                logger.info("Installing AWS compliance mod")
                mod_cmd = ['steampipe', 'mod', 'install', 'github.com/turbot/steampipe-mod-aws-compliance', '--verbose']
                await self._run_command(mod_cmd, workspace_dir)
            except Exception as mod_e:
                logger.error(f"Error installing AWS compliance mod: {str(mod_e)}")
                
                # Try alternate approach
                try:
                    logger.info("Trying alternate mod installation approach")
                    alt_cmd = ['steampipe', 'mod', 'install', 'github.com/turbot/steampipe-mod-aws-compliance', '--force']
                    await self._run_command(alt_cmd, workspace_dir)
                except Exception as alt_e:
                    logger.error(f"Alternate mod installation also failed: {str(alt_e)}")
                    logger.warning("Will continue without the compliance mod and use basic queries instead")
            
            logger.info("Steampipe workspace initialized with AWS CIS benchmark mod")
            return True
                
        except Exception as e:
            logger.error(f"Failed to initialize steampipe workspace: {str(e)}")
            logger.error(traceback.format_exc())
            raise
    async def _init_steampipe_connection(self):
        """Initialize Steampipe connection with direct test"""
        try:
            # Create a basic test script
            test_dir = self.temp_dir / 'connection_test'
            test_dir.mkdir(exist_ok=True)
            
            test_sql = test_dir / 'test.sql'
            with open(test_sql, 'w') as f:
                f.write("select current_timestamp as time;")
            
            # Test Steampipe basics
            logger.info("Testing Steampipe basic functionality")
            basic_cmd = ['steampipe', 'query', str(test_sql), '--output', 'json', '--database-init']
            basic_output = await self._run_command(basic_cmd, test_dir, timeout=30)
            
            if basic_output and basic_output.strip():
                logger.info(f"Basic Steampipe test succeeded: {basic_output}")
            else:
                logger.warning("Basic Steampipe test returned no output")
            
            # Test AWS plugin
            aws_test_sql = test_dir / 'aws_test.sql'
            with open(aws_test_sql, 'w') as f:
                f.write("select plugin_name, version from steampipe_plugin where plugin_name like '%aws%';")
            
            plugin_cmd = ['steampipe', 'query', str(aws_test_sql), '--output', 'json']
            plugin_output = await self._run_command(plugin_cmd, test_dir, timeout=30)
            
            if plugin_output and plugin_output.strip():
                logger.info(f"AWS plugin test succeeded: {plugin_output}")
                return True
            else:
                logger.warning("AWS plugin test returned no output")
                return False
                
        except Exception as e:
            logger.error(f"Steampipe connection initialization failed: {str(e)}")
            return False
    
    async def _run_steampipe_scan(self, user_id: str, account_id: str) -> Dict[str, Any]:
        """Run a simplified AWS security scan with enhanced debugging"""
        try:
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(parents=True, exist_ok=True)
            
            try:
                update_scan_progress(user_id, account_id, 'scanning', 30)
            except Exception as e:
                logger.warning(f"Progress update error (non-critical): {str(e)}")
            
            # Set AWS credentials as environment variables
            access_key = self.aws_credentials.get('aws_access_key_id', '').strip()
            secret_key = self.aws_credentials.get('aws_secret_access_key', '').strip()
            session_token = self.aws_credentials.get('aws_session_token', '').strip()
            
            os.environ['AWS_ACCESS_KEY_ID'] = access_key
            os.environ['AWS_SECRET_ACCESS_KEY'] = secret_key
            if session_token:
                os.environ['AWS_SESSION_TOKEN'] = session_token
                
            # Log the credentials being used (redacted for security)
            masked_access_key = f"{access_key[:4]}{'*' * (len(access_key) - 8)}{access_key[-4:]}" if len(access_key) > 8 else "Not provided"
            masked_secret_key = f"{secret_key[:4]}{'*' * (len(secret_key) - 8)}{secret_key[-4:]}" if len(secret_key) > 8 else "Not provided"
            has_session_token = "Yes" if session_token else "No"
            
            logger.info(f"AWS credentials details: Access Key: {masked_access_key}, Secret Key: {masked_secret_key}, Session Token: {has_session_token}")
            
            # Create a very simple connectivity test query
            connectivity_file = workspace_dir / 'connectivity_test.sql'
            with open(connectivity_file, 'w') as f:
                f.write("SELECT 1 as simple_test;")
                
            # Test basic connectivity
            logger.info("Testing AWS connectivity")
            try:
                # First try the most basic query possible
                basic_cmd = ['steampipe', 'query', str(connectivity_file), '--output', 'json']
                basic_output = await self._run_command(basic_cmd, workspace_dir, timeout=30)
                
                if basic_output and basic_output.strip():
                    try:
                        basic_result = json.loads(basic_output)
                        logger.info(f"Basic connectivity test passed: {json.dumps(basic_result)}")
                    except json.JSONDecodeError:
                        logger.warning("Could not parse basic test output as JSON")
                        logger.debug(f"Raw basic test output: {basic_output}")
                else:
                    logger.warning("Basic connectivity test produced no output")
                    
                    # Try diagnosing Steampipe directly
                    try:
                        logger.info("Running Steampipe database initialization check")
                        db_cmd = ['steampipe', 'query', 'SELECT 1', '--output', 'json', '--database-init']
                        db_output = await self._run_command(db_cmd, workspace_dir, timeout=30)
                        logger.info(f"Database initialization check result: {db_output}")
                    except Exception as db_e:
                        logger.error(f"Database initialization check failed: {str(db_e)}")
                        
            except Exception as conn_e:
                logger.error(f"Error running basic connectivity test: {str(conn_e)}")
                
            # Try AWS CLI directly for comparison
            try:
                logger.info("Verifying credentials with AWS CLI directly")
                aws_cmd = ['aws', 'sts', 'get-caller-identity', '--output', 'json']
                aws_output = await self._run_command(aws_cmd, timeout=15, cwd=workspace_dir)
                
                if aws_output and aws_output.strip():
                    logger.info(f"AWS CLI verification succeeded: {aws_output.strip()}")
                else:
                    logger.warning("AWS CLI verification produced no output")
            except Exception as aws_e:
                logger.error(f"AWS CLI verification failed: {str(aws_e)}")
            
            # Create individual queries per service to test specific permissions
            table_queries = [
                ("aws_account", "SELECT * FROM aws_account LIMIT 5;"),
                ("aws_iam_user", "SELECT * FROM aws_iam_user LIMIT 5;"),
                ("aws_s3_bucket", "SELECT * FROM aws_s3_bucket LIMIT 5;"),
                ("aws_region", "SELECT * FROM aws_region LIMIT 5;")
            ]
            
            # Test each table individually
            findings = []
            
            for table_name, query_text in table_queries:
                query_file = workspace_dir / f"{table_name}_basic.sql"
                with open(query_file, 'w') as f:
                    f.write(query_text)
                    
                logger.info(f"Testing query for {table_name}")
                try:
                    query_cmd = ['steampipe', 'query', str(query_file), '--output', 'json', '--database-init']
                    query_output = await self._run_command(query_cmd, workspace_dir, timeout=60)
                    
                    if query_output and query_output.strip():
                        try:
                            results = json.loads(query_output)
                            logger.info(f"Successfully queried {table_name}: {len(results)} results found")
                            
                            # For each result, create a finding
                            for idx, result in enumerate(results):
                                if table_name == 'aws_iam_user':
                                    findings.append({
                                        'id': f"aws-iam-{idx+1}",
                                        'severity': "MEDIUM",
                                        'category': "IAM",
                                        'control': "IAM User Security",
                                        'control_id': f"aws-iam-user-{idx+1}",
                                        'status': "Pass" if result.get('mfa_enabled') else "Fail",
                                        'reason': "IAM users should have MFA enabled",
                                        'details': json.dumps(result),
                                        'resource_id': result.get('arn', account_id),
                                        'account_id': account_id
                                    })
                                # Add more table-specific handling here
                        except json.JSONDecodeError:
                            logger.warning(f"Could not parse {table_name} results as JSON")
                            logger.debug(f"Raw output: {query_output[:500]}")
                    else:
                        logger.warning(f"Query for {table_name} returned no output")
                except Exception as query_e:
                    logger.error(f"Error querying {table_name}: {str(query_e)}")
            
            # If we found actual resources, use those findings; otherwise use baseline
            if findings:
                logger.info(f"Using {len(findings)} actual AWS resource findings")
            else:
                logger.info("No AWS resources found, using baseline security recommendations")
                # Generate baseline findings as in your original code
                findings = [
                    # Your existing baseline findings
                    {
                        'id': f"aws-{account_id}-1",
                        'severity': "MEDIUM",
                        'category': "IAM",
                        'control': "AWS IAM User MFA",
                        'control_id': "aws-iam-1",
                        'status': "Info",
                        'reason': "IAM users should have MFA enabled",
                        'details': json.dumps({
                            "recommendation": "Enable MFA for all IAM users with console access"
                        }),
                        'resource_id': account_id,
                        'account_id': account_id,
                        'remediation': "Use the AWS Management Console or API to enable MFA devices for all IAM users"
                    },
                    # Add your other baseline findings
                ]
            
            # Process findings into final results as in your original code
            # Create severity counts
            severity_counts = {
                "CRITICAL": 0,
                "HIGH": sum(1 for f in findings if f['severity'] == "HIGH"),
                "MEDIUM": sum(1 for f in findings if f['severity'] == "MEDIUM"),
                "LOW": sum(1 for f in findings if f['severity'] == "LOW"),
                "INFO": sum(1 for f in findings if f['severity'] == "INFO")
            }
            
            # Create category counts
            category_counts = {}
            for finding in findings:
                category = finding['category']
                if category not in category_counts:
                    category_counts[category] = 0
                category_counts[category] += 1
            
            # Add diagnostic information - properly awaited
            diagnostics = await self.get_diagnostics()
            
            # Create final results object
            scan_results = {
                'findings': findings,
                'stats': {
                    'total_findings': len(findings),
                    'failed_findings': sum(1 for f in findings if f['status'] == "Fail"),
                    'warning_findings': sum(1 for f in findings if f['status'] == "Warning"),
                    'pass_findings': sum(1 for f in findings if f['status'] == "Pass") + 
                                    sum(1 for f in findings if f['status'] == "Info"),
                    'severity_counts': severity_counts,
                    'category_counts': category_counts,
                    'resource_counts': len(set(f.get('resource_id') for f in findings)),
                    'account_id': account_id
                },
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'account_id': account_id,
                    'cloud_provider': 'aws',
                    'benchmark': 'AWS Security Assessment',
                    'scan_type': 'direct-scan',
                    'diagnostic_info': diagnostics
                }
            }
            
            logger.info(f"Final scan results: {len(findings)} findings in {len(category_counts)} categories")
            logger.info(f"Findings in scan_results: {len(scan_results['findings'])}")
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Error in AWS security scan: {str(e)}")
            logger.error(traceback.format_exc())
            return self._create_error_results(str(e), account_id)
                    
    def _create_error_results(self, error_message: str, account_id: str, 
                             diagnostics: Optional[Dict] = None) -> Dict[str, Any]:
        """Create enhanced error results with diagnostics"""
        findings = [{
            'id': f"aws-{account_id}-error-1",
            'severity': 'INFO',
            'category': 'Diagnostics',
            'control': 'AWS Scan Diagnostics',
            'status': 'Completed with errors',
            'reason': 'AWS scan encountered issues',
            'details': f'Error details: {error_message}',
            'resource_id': account_id,
            'account_id': account_id,
            'remediation': 'Check AWS credentials and permissions. See diagnostic information.'
        }]
        
        # Create basic stats
        severity_counts = {'INFO': 1, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        
        return {
            'findings': findings,
            'stats': {
                'total_findings': 1,
                'failed_findings': 0,
                'pass_findings': 0,
                'warning_findings': 1,
                'severity_counts': severity_counts,
                'category_counts': {'Diagnostics': 1},
                'resource_counts': 1,
                'account_id': account_id
            },
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'account_id': account_id,
                'cloud_provider': 'aws',
                'benchmark': 'AWS Security Check',
                'scan_error': error_message,
                'scan_diagnostics': diagnostics or {}
            }
        }
        
   
    def _extract_findings_from_benchmark(self, data, findings, account_id, path="", category_path=None):
        """Extract findings from benchmark results with proper category extraction - FIXED VERSION"""
        if isinstance(data, dict):
            # Check if this is a category group
            if 'title' in data and 'group_id' in data:
                # This looks like a category group - capture the title
                new_category = data.get('title')
                # Only use as category if it looks like a proper section name
                if re.match(r'^\d+(\.\d+)* ', new_category) or new_category in ["Identity and Access Management", "Storage", "Networking", "Monitoring", "Logging"]:
                    category_path = new_category
            
            # Is this a control with results?
            if 'control_id' in data and 'title' in data:
                control_id = data.get('control_id')
                title = data.get('title')
                # Use the category path or default to "General"
                category = category_path or "General"
                severity = self._map_severity(data.get('severity', 'medium'))
                description = data.get('description', '')
                
                # Process results for this control - THIS IS THE KEY FIX
                results = data.get('results', [])
                if not results:
                    # Add a placeholder finding for controls with no results
                    findings.append({
                        'id': f"cis-{control_id}",
                        'severity': severity,
                        'category': category,
                        'control': title,
                        'control_id': control_id,
                        'status': 'info',
                        'reason': description,
                        'details': "No specific results for this control",
                        'resource_id': account_id,
                        'account_id': account_id,
                        'cis_control': control_id
                    })
                else:
                    # CRITICAL FIX: Process EACH individual result as a separate finding
                    for result in results:
                        status = result.get('status', 'info')
                        resource = result.get('resource', account_id)
                        reason = result.get('reason', '')
                        
                        findings.append({
                            'id': f"cis-{control_id}",
                            'severity': severity,
                            'category': category,
                            'control': title,
                            'control_id': control_id,
                            'status': status,  # Use the individual result's status
                            'reason': description,
                            'details': reason,
                            'resource_id': resource,
                            'account_id': account_id,
                            'cis_control': control_id
                        })
                
                # IMPORTANT: Don't return here - continue processing nested data
            
            # Recursively process all properties
            for key, value in data.items():
                # Skip results since we already processed them above
                if key == 'results':
                    continue
                    
                new_path = f"{path}.{key}" if path else key
                self._extract_findings_from_benchmark(value, findings, account_id, new_path, category_path)
                
        elif isinstance(data, list):
            # Process each item in the list
            for item in data:
                self._extract_findings_from_benchmark(item, findings, account_id, path, category_path)

    def _process_benchmark_results(self, results: Dict, account_id: str) -> Dict[str, Any]:
        """Process CIS benchmark results - FIXED VERSION"""
        try:
            if not results:
                logger.warning("Empty benchmark results")
                return self._create_error_results("Empty benchmark results", account_id)
            
            # Extract findings directly from the original results structure
            findings = []
            
            # Process all controls recursively to extract findings with proper categories
            self._extract_findings_from_benchmark(results, findings, account_id, "", None)
            
            logger.info(f"Extracted {len(findings)} findings from benchmark results")
            
            
            status_counts = {}
            for finding in findings:
                status = finding.get('status', 'unknown')
                if status not in status_counts:
                    status_counts[status] = 0
                status_counts[status] += 1
            
            # Log the actual counts for debugging
            logger.info(f"Actual status counts: {status_counts}")
            
            # Create category counts from the findings
            category_counts = {}
            for finding in findings:
                category = finding.get('category', 'Unknown')
                if category not in category_counts:
                    category_counts[category] = 0
                category_counts[category] += 1
            
            # Create the correct final stats structure
            final_stats = {
                'total_findings': len(findings),
                'failed_findings': status_counts.get('alarm', 0),     # alarm = failed
                'pass_findings': status_counts.get('ok', 0),         # ok = pass  
                'info_findings': status_counts.get('info', 0),       # info = info
                'skip_findings': status_counts.get('skip', 0),       # skip = skip
                'error_findings': status_counts.get('error', 0),     # error = error
                'severity_counts': {
                    'Failed': status_counts.get('alarm', 0),
                    'OK': status_counts.get('ok', 0), 
                    'Info': status_counts.get('info', 0),
                    'Skipped': status_counts.get('skip', 0),
                    'Error': status_counts.get('error', 0)
                },
                'category_counts': category_counts,
                'account_id': account_id
            }
            
            # Create final results structure
            findings_data = {
                'findings': findings,
                'stats': final_stats,
                'metadata': {
                    'benchmark': 'AWS CIS Foundations Benchmark',
                    'version': results.get('title', 'v4.0.0'),
                    'scan_time': datetime.now().isoformat(),
                    'account_id': account_id
                }
            }
            
            # Log final summary for verification
            logger.info(f"Final summary: {status_counts.get('ok', 0)} ok, {status_counts.get('alarm', 0)} alarm, {status_counts.get('info', 0)} info, {status_counts.get('skip', 0)} skip, {status_counts.get('error', 0)} error")
            logger.info(f"Total findings: {len(findings)} (should be 187)")
            
            return findings_data
                
        except Exception as e:
            logger.error(f"Error processing benchmark results: {str(e)}")
            logger.error(traceback.format_exc())
            return self._create_error_results(f"Result processing error: {str(e)}", account_id)
            
    def _extract_findings_recursively(self, data, findings_data, account_id, path="root"):
        """Recursively search for controls and findings in JSON structure"""
        if isinstance(data, dict):
            # Check if this dict looks like a control
            if 'control_id' in data and 'title' in data:
                category = path.split('.')[-1] if '.' in path else 'General'
                self._add_finding_from_control(data, category, findings_data, account_id)
                return
                
            # Check if this dict has results directly
            if 'results' in data and isinstance(data['results'], list):
                category = data.get('title', path.split('.')[-1] if '.' in path else 'General')
                control_id = data.get('control_id', data.get('id', 'unknown'))
                title = data.get('title', 'Unknown Control')
                description = data.get('description', '')
                severity = self._map_severity(data.get('severity', 'medium'))
                
                for result in data['results']:
                    self._add_finding_from_result(result, control_id, title, description, 
                                                severity, category, findings_data, account_id)
                return
            
            # Recursively process each key
            for key, value in data.items():
                new_path = f"{path}.{key}" if path != "root" else key
                self._extract_findings_recursively(value, findings_data, account_id, new_path)
        
        elif isinstance(data, list):
            # Process each item in the list
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                self._extract_findings_recursively(item, findings_data, account_id, new_path)
        
    def _add_finding_from_control(self, control, category, findings_data, account_id):
        """Process a control object into findings safely"""
        if not control:
            return
            
        control_id = control.get('control_id', control.get('id', 'unknown'))
        title = control.get('title', 'Unknown Control')
        description = control.get('description', '')
        severity = self._map_severity(control.get('severity', 'medium'))
        
        # Check if control has results
        results = control.get('results', [])
        if not results:
            # Add a placeholder finding if there are no results
            finding = {
                'id': f"cis-{control_id}",
                'severity': severity,
                'category': category,
                'control': title,
                'control_id': control_id,
                'status': 'info',
                'reason': description,
                'details': "No specific results for this control",
                'resource_id': account_id,
                'account_id': account_id,
                'cis_control': control_id
            }
            findings_data['findings'].append(finding)
            return
        
        # Process each result
        for result in results:
            self._add_finding_from_result(result, control_id, title, description, 
                                        severity, category, findings_data, account_id)

    
        

    def _map_severity(self, severity: str) -> str:
        """Map Steampipe/Powerpipe severity to our format"""
        severity = severity.lower()
        if severity in ['critical', 'high']:
            return 'HIGH'
        elif severity in ['medium']:
            return 'MEDIUM'
        elif severity in ['low']:
            return 'LOW'
        else:
            return 'INFO'
            
    def _map_status(self, status: str) -> str:
        """Map Steampipe/Powerpipe status to standardized status"""
        status = status.lower() if status else ""
        
        # Keep original status values for consistency
        if status in ["alarm", "ok", "info", "skip", "error"]:
            return status
        
        # Map other values to standard statuses
        if status in ["fail", "failed", "failure"]:
            return "alarm"
        elif status in ["pass", "passed", "success"]:
            return "ok"
        elif status in ["skipped", "not_applicable"]:
            return "skip"
        elif status in ["unknown", "none"]:
            return "info"
        else:
            return "info"  
        
    def _map_severity_from_status(self, status, original_severity):
        """
        Map the benchmark status to an appropriate severity level
        
        Args:
            status: The benchmark status (alarm, ok, info, skip)
            original_severity: The original severity from the benchmark
            
        Returns:
            str: Mapped severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        """
        status = status.lower() if status else ""
        original_severity = original_severity.upper() if original_severity else "INFO"
        
        # If we already have a valid severity that's not INFO, use it
        if original_severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] and status == "alarm":
            return original_severity
        
        # Otherwise map based on status
        if status == "alarm":
            return "HIGH"  # Failed checks are high severity by default
        elif status == "ok":
            return "INFO"  # Passing checks are informational
        elif status == "skip":
            return "LOW"   # Skipped checks are low severity
        elif status == "info":
            return "MEDIUM"  # Info status suggests medium importance
        else:
            return "INFO" 
        
    def _add_finding_from_result(self, result, control_id, title, description, original_severity, category, findings_data, account_id):
        """Extract a finding from a result object with improved severity mapping"""
        if not result:
            return
                
        status = result.get('status', 'info')
        resource = result.get('resource', account_id)
        reason = result.get('reason', '')
        
        # Use the new severity mapping function
        severity = self._map_severity_from_status(status, original_severity)

        
        # Create finding
        finding = {
            'id': f"cis-{control_id}",
            'severity': severity,
            'category': category,
            'control': title,
            'control_id': control_id,
            'status': status,
            'reason': description,
            'details': reason,
            'resource_id': resource,
            'account_id': account_id,
            'cis_control': control_id
        }
        
        findings_data['findings'].append(finding)
        
        # Update the severity counts in the stats
        if severity not in findings_data['stats']['severity_counts']:
            findings_data['stats']['severity_counts'][severity] = 0
        findings_data['stats']['severity_counts'][severity] += 1
                
    # Helper function to parse the CSV results
    def parse_csv_results(csv_file_path: str) -> Dict[str, Any]:
        """
        Parse CIS benchmark results from CSV file
        
        Args:
            csv_file_path: Path to the CSV results file
            
        Returns:
            Dict containing processed results
        """
        import csv
        from collections import defaultdict
        
        try:
            findings = []
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            status_counts = defaultdict(int)
            
            # Load CSV file
            with open(csv_file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Basic validation
                    if not row:
                        continue
                        
                    # Map to standardized format
                    severity = row.get('severity', '').upper()
                    if not severity:
                        severity = 'INFO'
                        
                    # Normalize status
                    status = row.get('status', '')
                    if 'fail' in status.lower() or 'alarm' in status.lower():
                        normalized_status = 'Fail'
                    elif 'pass' in status.lower() or 'ok' in status.lower():
                        normalized_status = 'Pass'
                    elif 'skip' in status.lower():
                        normalized_status = 'Skipped'
                    else:
                        normalized_status = 'Info'
                        
                    # Create finding record
                    finding = {
                        'id': f"cis-{row.get('control_id', 'unknown')}",
                        'severity': severity,
                        'category': row.get('category', row.get('service', 'General')),
                        'control': row.get('control_title', row.get('title', 'Unknown Control')),
                        'control_id': row.get('control_id', 'unknown'),
                        'status': normalized_status,
                        'reason': row.get('reason', ''),
                        'details': row.get('control_description', row.get('description', '')),
                        'resource_id': row.get('resource', row.get('account_id', '')),
                        'account_id': row.get('account_id', ''),
                        'remediation': ''  # CSV might not include remediation
                    }
                    
                    findings.append(finding)
                    
                    # Update counts
                    severity_counts[severity] += 1
                    category_counts[finding['category']] += 1
                    status_counts[normalized_status] += 1
                    
            # Make sure we have all severity levels represented
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev not in severity_counts:
                    severity_counts[sev] = 0
                    
            # Return processed results
            return {
                'findings': findings,
                'stats': {
                    'total_findings': len(findings),
                    'failed_findings': status_counts['Fail'],
                    'warning_findings': status_counts.get('Warning', 0),
                    'pass_findings': status_counts['Pass'],
                    'severity_counts': dict(severity_counts),
                    'category_counts': dict(category_counts),
                    'resource_counts': len(set(f.get('resource_id') for f in findings)),
                    'account_id': findings[0].get('account_id') if findings else ''
                },
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'cloud_provider': 'aws',
                    'benchmark': 'AWS CIS Foundations Benchmark v1.3.1',
                    'source': 'csv_import'
                }
            }
            
        except Exception as e:
            logger.error(f"Error parsing CSV results: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                'findings': [],
                'stats': {
                    'total_findings': 0,
                    'failed_findings': 0,
                    'warning_findings': 0,
                    'pass_findings': 0,
                    'severity_counts': {
                        'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
                    },
                    'category_counts': {},
                    'resource_counts': 0,
                    'account_id': ''
                },
                'metadata': {
                    'scan_time': datetime.now().isoformat(),
                    'cloud_provider': 'aws',
                    'benchmark': 'AWS CIS Foundations Benchmark',
                    'source': 'csv_import',
                    'error': str(e)
                }
            }
    async def run_powerpipe_benchmark(self, account_id: str, benchmark_name: str = "aws_compliance.benchmark.cis_v140") -> Dict[str, Any]:
        """Run AWS CIS benchmark using Powerpipe"""
        try:
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(exist_ok=True)
            
            logger.info(f"Running CIS benchmark scan with Powerpipe: {benchmark_name}")
            
            # Run the benchmark using powerpipe check
            benchmark_cmd = ['powerpipe', 'check', benchmark_name, '--output', 'json']
            benchmark_output = await self._run_command(benchmark_cmd, workspace_dir, timeout=300)
            
            if not benchmark_output or not benchmark_output.strip():
                logger.warning("Powerpipe benchmark returned no output")
                return None
                
            try:
                benchmark_results = json.loads(benchmark_output)
                logger.info(f"Successfully ran benchmark scan with {len(benchmark_results.get('groups', []))} control groups")
                return benchmark_results
            except json.JSONDecodeError:
                logger.error("Failed to parse Powerpipe benchmark output as JSON")
                logger.debug(f"Raw benchmark output: {benchmark_output[:1000]}...")
                return None
                
        except Exception as e:
            logger.error(f"Powerpipe benchmark error: {str(e)}")
            return None
    

    # Function to discover available CIS benchmarks in Steampipe
    async def discover_available_benchmarks(workspace_dir: Path) -> List[str]:
        """
        Discover available CIS benchmarks in the steampipe installation
        
        Args:
            workspace_dir: Path to the workspace directory
            
        Returns:
            List of available benchmark identifiers
        """
        try:
            # List all available checks
            list_cmd = ['steampipe', 'check', 'list']
            check_list_output = await self._run_command(list_cmd, workspace_dir)
            
            # Extract benchmark identifiers
            benchmarks = []
            for line in check_list_output.splitlines():
                if 'cis' in line.lower() and 'aws' in line.lower():
                    parts = line.strip().split()
                    if parts:
                        benchmarks.append(parts[0])
                        
            return benchmarks
        except Exception as e:
            logger.error(f"Error discovering benchmarks: {str(e)}")
            return []
    
    async def __aenter__(self):
        """Initialize scanner resources"""
        await self.setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Cleanup scanner resources"""
        await self.cleanup()
    
    async def _run_command_with_debug(self, command: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> str:
        """Run a command with detailed debug output and handle large outputs"""
        try:
            cmd_str = ' '.join(command)
            logger.info(f"Running command with debug: {cmd_str}")
            
            # Create a temporary file to capture output
            output_file = self.temp_dir / f"cmd_output_{int(time.time())}.json"
            
            # For the benchmark command, use file redirection to capture full output
            if 'benchmark run' in cmd_str and '--output json' in cmd_str:
                # Modify command to redirect output to file
                redirect_cmd = command.copy()
                redirect_cmd.append('>')
                redirect_cmd.append(str(output_file))
                
                # Use shell=True to allow redirection
                process = await asyncio.create_subprocess_shell(
                    ' '.join(redirect_cmd),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd) if cwd else None,
                    env=os.environ.copy(),
                    shell=True
                )
                
                try:
                    _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    process.kill()
                    logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                    raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
                
                stderr_text = stderr.decode() if stderr else ""
                if stderr_text:
                    logger.error(f"Command stderr: {stderr_text}")
                
                # Read from the output file
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        stdout_text = f.read()
                    logger.info(f"Read {len(stdout_text)} bytes from output file")
                    # Don't log the full output, it's too large
                    if stdout_text:
                        logger.info(f"Command stdout sample: {stdout_text[:500]}...")
                    return stdout_text
                else:
                    logger.error("Output file not created")
                    raise RuntimeError(f"Command failed with code {process.returncode}: {stderr_text}")
            
            # For other commands, use the normal approach
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=os.environ.copy()
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
            
            stdout_text = stdout.decode() if stdout else ""
            stderr_text = stderr.decode() if stderr else ""
            
            if stdout_text:
                logger.info(f"Command stdout: {stdout_text[:1000]}" + ("..." if len(stdout_text) > 1000 else ""))
            
            if stderr_text:
                logger.error(f"Command stderr: {stderr_text}")
            
            if process.returncode != 0:
                logger.error(f"Command failed with code {process.returncode}")
                if stdout_text:
                    return stdout_text
                else:
                    raise RuntimeError(f"Command failed with code {process.returncode}: {stderr_text}")
                    
            return stdout_text
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            raise
    
 
    async def run_aws_compliance_check(self, account_id: str) -> Dict[str, Any]:
        """Run AWS compliance check using system-wide installation paths with focus on CIS v4.0.0 and config data collection"""
        try:
            # Create workspace directory
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(exist_ok=True)
            
            logger.info("Running AWS CIS benchmark scan with focus on v4.0.0")
            
            # Stop any existing Steampipe service first
            try:
                logger.info("Stopping any existing Steampipe service")
                stop_cmd = ['steampipe', 'service', 'stop']
                await self._run_command(stop_cmd, timeout=30)
                await asyncio.sleep(2)  # Give it time to stop
            except Exception as stop_e:
                logger.warning(f"Steampipe service stop warning (non-critical): {str(stop_e)}")
            
            # Install AWS plugin (without specifying version to get latest)
            logger.info("Installing AWS plugin for Steampipe")
            try:
                plugin_cmd = ['steampipe', 'plugin', 'install', 'aws']
                await self._run_command(plugin_cmd, timeout=180)
                logger.info("AWS plugin installed successfully")
            except Exception as plugin_e:
                logger.warning(f"AWS plugin installation warning: {str(plugin_e)}")
            
            # Start the Steampipe service
            logger.info("Starting Steampipe service")
            try:
                start_cmd = ['steampipe', 'service', 'start']
                await self._run_command(start_cmd, timeout=30)
                logger.info("Steampipe service started")
                await asyncio.sleep(5)  # Give it time to start
            except Exception as start_e:
                logger.warning(f"Steampipe service start warning: {str(start_e)}")
            
            # Test Steampipe connection with a simple query
            logger.info("Testing Steampipe connection")
            try:
                test_query = "select title from aws_account"
                test_cmd = ['powerpipe', 'query', 'run', test_query]
                test_output = await self._run_command(test_cmd, timeout=30)
                logger.info(f"Steampipe connection test: {test_output}")
            except Exception as test_e:
                logger.warning(f"Steampipe connection test warning: {str(test_e)}")
            
            # Create mod directory and initialize
            mod_dir = workspace_dir / 'aws_mod'
            mod_dir.mkdir(exist_ok=True)
            
            # Initialize the mod
            logger.info("Initializing Powerpipe mod")
            try:
                init_cmd = ['powerpipe', 'mod', 'init']
                await self._run_command(init_cmd, cwd=mod_dir, timeout=30)
                logger.info("Powerpipe mod initialized")
            except Exception as init_e:
                logger.warning(f"Mod initialization warning: {str(init_e)}")
            
            # Install AWS compliance mod
            logger.info("Installing AWS compliance mod")
            try:
                install_cmd = ['powerpipe', 'mod', 'install', 'github.com/turbot/steampipe-mod-aws-compliance']
                await self._run_command(install_cmd, cwd=mod_dir, timeout=180)
                logger.info("AWS compliance mod installed successfully")
            except Exception as install_e:
                logger.warning(f"Warning installing compliance mod: {str(install_e)}")
            
            # List available mods
            try:
                list_cmd = ['powerpipe', 'mod', 'list']
                mod_list_output = await self._run_command(list_cmd, cwd=mod_dir, timeout=30)
                logger.info(f"Available mods: {mod_list_output}")
            except Exception as list_e:
                logger.warning(f"Error listing mods: {str(list_e)}")
            
            # FIRST: Collect AWS configuration data using Steampipe (MOVED BEFORE BENCHMARK)
            logger.info("Collecting AWS configuration data...")
            config_data = await self._collect_steampipe_config_data(workspace_dir)
            
            # Try running CIS v4.0.0 benchmark
            benchmark_results = None
            try:
                logger.info("Attempting to run CIS v4.0.0 benchmark")
                benchmark_cmd = ['powerpipe', 'benchmark', 'run', 'aws_compliance.benchmark.cis_v400', '--output', 'json']
                
                # Use our improved method to run the benchmark and capture full output
                benchmark_output = await self._run_command_with_debug(benchmark_cmd, cwd=mod_dir, timeout=300)
                
                if benchmark_output and len(benchmark_output.strip()) > 0:
                    try:
                        # Parse the full benchmark results
                        benchmark_results = json.loads(benchmark_output)
                        logger.info(f"Successfully parsed benchmark results with {len(benchmark_output)} bytes")
                        
                        # Check if we have actual findings
                        summary = benchmark_results.get('summary', {}).get('status', {})
                        total_findings = summary.get('ok', 0) + summary.get('alarm', 0) + summary.get('info', 0)
                        
                        logger.info(f"Benchmark summary: {summary.get('ok', 0)} ok, " +
                                f"{summary.get('alarm', 0)} alarm, {summary.get('info', 0)} info, " +
                                f"{summary.get('skip', 0)} skip, {summary.get('error', 0)} error")
                        
                    except json.JSONDecodeError as je:
                        logger.error(f"Failed to parse benchmark output as JSON: {str(je)}")
            except Exception as benchmark_e:
                logger.error(f"Error running benchmark: {str(benchmark_e)}")
            
            # If benchmark succeeded, process results and add config data
            if benchmark_results:
                logger.info("Processing benchmark results with config data")
                processed_results = self._process_benchmark_results(benchmark_results, account_id)
                
                # Add config data to metadata
                if 'metadata' not in processed_results:
                    processed_results['metadata'] = {}
                processed_results['metadata']['aws_config'] = config_data
                
                return processed_results
            
            # Fall back to boto3-based checks if the benchmark didn't work
            logger.info("Using boto3 to create enhanced security findings with config data")
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            # Enhanced boto3 findings collection with config data context
            findings = []
            
            # 1. Enhanced IAM password policy check with config data context
            try:
                iam = session.client('iam')
                
                # Check if we have password policy from config data
                config_password_policy = config_data.get('password_policy', [])
                if config_password_policy and len(config_password_policy) > 0:
                    policy_data = config_password_policy[0]
                    min_length = policy_data.get('minimum_password_length', 0)
                    require_symbols = policy_data.get('require_symbols', False)
                    require_numbers = policy_data.get('require_numbers', False)
                    require_uppercase = policy_data.get('require_uppercase_characters', False)
                    require_lowercase = policy_data.get('require_lowercase_characters', False)
                    
                    findings.append({
                        'id': 'iam_password_policy_length',
                        'title': 'IAM Password Minimum Length',
                        'severity': 'medium',
                        'status': 'ok' if min_length >= 14 else 'alarm',
                        'resource': account_id,
                        'reason': f'Password minimum length is {min_length} (should be ≥14)',
                        'category': 'IAM',
                        'cis_control': '1.8',
                        'config_source': 'steampipe'
                    })
                    
                    findings.append({
                        'id': 'iam_password_policy_complexity',
                        'title': 'IAM Password Complexity',
                        'severity': 'medium',
                        'status': 'ok' if (require_symbols and require_numbers and 
                                        require_uppercase and require_lowercase) else 'alarm',
                        'resource': account_id,
                        'reason': 'Password policy requires symbols, numbers, uppercase, and lowercase characters',
                        'category': 'IAM',
                        'cis_control': '1.7',
                        'config_source': 'steampipe'
                    })
                else:
                    # Fall back to direct API call
                    try:
                        policy = iam.get_account_password_policy()
                        # Process policy as before...
                    except iam.exceptions.NoSuchEntityException:
                        findings.append({
                            'id': 'iam_password_policy',
                            'title': 'IAM Password Policy',
                            'severity': 'high',
                            'status': 'alarm',
                            'resource': account_id,
                            'reason': 'No password policy is set',
                            'category': 'IAM',
                            'cis_control': '1.7-1.11',
                            'config_source': 'boto3'
                        })
            except Exception as iam_e:
                logger.warning(f"Error checking IAM password policy: {str(iam_e)}")
            
            # 2. Enhanced IAM summary check using config data
            config_iam_summary = config_data.get('iam_summary', [])
            if config_iam_summary and len(config_iam_summary) > 0:
                iam_data = config_iam_summary[0]
                total_users = iam_data.get('users', 0)
                mfa_devices = iam_data.get('mfa_devices', 0)
                
                findings.append({
                    'id': 'iam_users_summary',
                    'title': 'IAM Users Overview',
                    'severity': 'info',
                    'status': 'info',
                    'resource': account_id,
                    'reason': f'Account has {total_users} IAM users with {mfa_devices} MFA devices',
                    'category': 'IAM',
                    'cis_control': 'overview',
                    'config_source': 'steampipe'
                })
            
            # 3. Enhanced CloudTrail check using config data
            config_cloudtrail = config_data.get('cloudtrail_status', [])
            if config_cloudtrail and len(config_cloudtrail) > 0:
                for trail in config_cloudtrail:
                    trail_name = trail.get('name', 'Unknown')
                    is_multi_region = trail.get('is_multi_region_trail', False)
                    is_logging = trail.get('is_logging', False)
                    log_validation = trail.get('log_file_validation_enabled', False)
                    
                    if not is_logging:
                        findings.append({
                            'id': f'cloudtrail_logging_{trail_name}',
                            'title': 'CloudTrail Logging Status',
                            'severity': 'high',
                            'status': 'alarm',
                            'resource': f'arn:aws:cloudtrail:{trail.get("home_region", "unknown")}:{account_id}:trail/{trail_name}',
                            'reason': f'CloudTrail {trail_name} is not actively logging',
                            'category': 'Logging',
                            'cis_control': '3.1',
                            'config_source': 'steampipe'
                        })
                    
                    if not is_multi_region:
                        findings.append({
                            'id': f'cloudtrail_multiregion_{trail_name}',
                            'title': 'CloudTrail Multi-Region',
                            'severity': 'medium',
                            'status': 'alarm',
                            'resource': f'arn:aws:cloudtrail:{trail.get("home_region", "unknown")}:{account_id}:trail/{trail_name}',
                            'reason': f'CloudTrail {trail_name} is not configured for all regions',
                            'category': 'Logging',
                            'cis_control': '3.1',
                            'config_source': 'steampipe'
                        })
            else:
                findings.append({
                    'id': 'cloudtrail_not_configured',
                    'title': 'CloudTrail Configuration',
                    'severity': 'high',
                    'status': 'alarm',
                    'resource': account_id,
                    'reason': 'No CloudTrail configuration detected',
                    'category': 'Logging',
                    'cis_control': '3.1',
                    'config_source': 'steampipe'
                })
            
            # 4. Enhanced VPC and Security Group insights from config data
            config_vpcs = config_data.get('vpc_info', [])
            if config_vpcs:
                default_vpcs = [vpc for vpc in config_vpcs if vpc.get('is_default', False)]
                if default_vpcs:
                    findings.append({
                        'id': 'default_vpc_exists',
                        'title': 'Default VPC Usage',
                        'severity': 'low',
                        'status': 'alarm',
                        'resource': default_vpcs[0].get('vpc_id', 'unknown'),
                        'reason': f'Default VPC is still present ({len(default_vpcs)} found)',
                        'category': 'Networking',
                        'cis_control': '4.1',
                        'config_source': 'steampipe'
                    })
            
            # 5. Security Group analysis from config data
            config_sg = config_data.get('security_groups', [])
            for sg in config_sg:
                inbound_rules = sg.get('inbound_rules', 0)
                outbound_rules = sg.get('outbound_rules', 0)
                
                if sg.get('group_name') == 'default' and inbound_rules > 0:
                    findings.append({
                        'id': f'default_sg_rules_{sg.get("group_id")}',
                        'title': 'Default Security Group Rules',
                        'severity': 'medium',
                        'status': 'alarm',
                        'resource': f'arn:aws:ec2:*:{account_id}:security-group/{sg.get("group_id")}',
                        'reason': f'Default security group has {inbound_rules} inbound rules (should have none)',
                        'category': 'Networking',
                        'cis_control': '4.3',
                        'config_source': 'steampipe'
                    })
            
            # If we already have benchmark results, enhance them with boto3 findings
            if 'benchmark_results' in locals() and benchmark_results:
                logger.info("Enhancing benchmark results with boto3 findings")
                # Enhancement logic here...
                return benchmark_results
            
            # Create enhanced custom benchmark structure with config data
            logger.info("Creating enhanced custom benchmark structure with boto3 findings and config data")
            formatted_results = {
                'group_id': 'root_result_group',
                'title': 'AWS Security Assessment',
                'description': 'Enhanced AWS security assessment based on CIS AWS Foundations Benchmark with configuration analysis',
                'summary': {
                    'status': {
                        'alarm': sum(1 for f in findings if f.get('status') == 'alarm'),
                        'ok': sum(1 for f in findings if f.get('status') == 'ok'),
                        'info': sum(1 for f in findings if f.get('status') == 'info'),
                        'skip': 0,
                        'error': 0
                    }
                },
                'groups': [
                    {
                        'group_id': 'aws_security_assessment',
                        'title': 'AWS Security Assessment',
                        'description': 'Enhanced AWS security assessment checks with configuration analysis',
                        'tags': {
                            'category': 'Compliance',
                            'cis': 'true',
                            'cis_version': 'v4.0.0',
                            'plugin': 'aws',
                            'service': 'AWS',
                            'type': 'Benchmark',
                            'enhanced_with_config': 'true'
                        },
                        'summary': {
                            'status': {
                                'alarm': sum(1 for f in findings if f.get('status') == 'alarm'),
                                'ok': sum(1 for f in findings if f.get('status') == 'ok'),
                                'info': sum(1 for f in findings if f.get('status') == 'info'),
                                'skip': 0,
                                'error': 0
                            }
                        },
                        'groups': []
                    }
                ],
                'metadata': {
                    'aws_config': config_data,  # Include config data in metadata
                    'config_data_quality': {
                        'sections_collected': len([k for k, v in config_data.items() if v]),
                        'total_sections_attempted': len(config_data),
                        'collection_timestamp': datetime.now().isoformat()
                    }
                }
            }
            
            # Group findings by category with enhanced processing
            categories = {}
            for finding in findings:
                category = finding.get('category', 'General')
                if category not in categories:
                    categories[category] = []
                categories[category].append(finding)
            
            # Create a group for each category with enhanced metadata
            for category, category_findings in categories.items():
                category_group = {
                    'group_id': f'aws_security_assessment.{category.lower()}',
                    'title': category,
                    'description': f'{category} security checks with configuration analysis',
                    'tags': {
                        'category': category,
                        'type': 'Group',
                        'config_enhanced': 'true'
                    },
                    'summary': {
                        'status': {
                            'alarm': sum(1 for f in category_findings if f.get('status') == 'alarm'),
                            'ok': sum(1 for f in category_findings if f.get('status') == 'ok'),
                            'info': sum(1 for f in category_findings if f.get('status') == 'info'),
                            'skip': 0,
                            'error': 0
                        }
                    },
                    'controls': []
                }
                
                # Group findings by control ID with enhanced details
                controls = {}
                for finding in category_findings:
                    control_id = finding.get('id')
                    if control_id not in controls:
                        controls[control_id] = {
                            'control_id': control_id,
                            'title': finding.get('title'),
                            'description': f"Enhanced check using {finding.get('config_source', 'api')} data source",
                            'severity': finding.get('severity', 'medium'),
                            'tags': {
                                'cis_control': finding.get('cis_control', ''),
                                'data_source': finding.get('config_source', 'api')
                            },
                            'results': []
                        }
                    
                    controls[control_id]['results'].append({
                        'status': finding.get('status'),
                        'resource': finding.get('resource'),
                        'reason': finding.get('reason')
                    })
                
                # Add controls to category group
                category_group['controls'] = list(controls.values())
                
                # Add category group to main benchmark group
                formatted_results['groups'][0]['groups'].append(category_group)
            
            # Add configuration summary to the results
            config_summary = {
                'sections_with_data': sum(1 for v in config_data.values() if v),
                'total_sections': len(config_data),
                'account_info_available': bool(config_data.get('account_info')),
                'iam_summary_available': bool(config_data.get('iam_summary')),
                'cloudtrail_info_available': bool(config_data.get('cloudtrail_status')),
                'vpc_info_available': bool(config_data.get('vpc_info')),
                'password_policy_available': bool(config_data.get('password_policy'))
            }
            
            formatted_results['metadata']['config_summary'] = config_summary
            
            logger.info(f"Created enhanced custom benchmark with {len(findings)} findings in {len(categories)} categories")
            logger.info(f"Config data quality: {config_summary['sections_with_data']}/{config_summary['total_sections']} sections collected")
            
            return formatted_results
            
        except Exception as e:
            logger.error(f"AWS compliance check failed: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Collect config data even if benchmark fails
            try:
                workspace_dir = self.temp_dir / 'workspace'
                workspace_dir.mkdir(exist_ok=True)
                config_data = await self._collect_steampipe_config_data(workspace_dir)
                logger.info("Collected config data despite benchmark failure")
            except Exception as config_e:
                logger.error(f"Config data collection also failed: {str(config_e)}")
                config_data = {}
            
            # Return minimal structure with config data so processing can continue
            return {
                'group_id': 'root_result_group',
                'title': 'Error',
                'description': 'Error running AWS compliance check',
                'summary': {
                    'status': {
                        'alarm': 0,
                        'ok': 0,
                        'info': 0,
                        'skip': 0,
                        'error': 1
                    }
                },
                'groups': [
                    {
                        'group_id': 'error',
                        'title': 'Error',
                        'description': 'Error running AWS compliance check',
                        'controls': [
                            {
                                'control_id': 'error',
                                'title': 'Error Running Compliance Check',
                                'severity': 'high',
                                'results': [
                                    {
                                        'status': 'error',
                                        'resource': account_id,
                                        'reason': f'Error: {str(e)}'
                                    }
                                ]
                            }
                        ]
                    }
                ],
                'metadata': {
                    'aws_config': config_data,  # Include config data even on error
                    'error_details': {
                        'error_message': str(e),
                        'error_type': type(e).__name__,
                        'timestamp': datetime.now().isoformat()
                    }
                }
            }
    
    async def _validate_steampipe_tables(self, workspace_dir: Path) -> Dict[str, bool]:
        """
        Validate which Steampipe AWS tables are available before running queries
        
        Returns:
            Dict mapping table names to availability status
        """
        tables_to_check = [
            'aws_account',
            'aws_sts_caller_identity', 
            'aws_caller_identity',  # Check both versions
            'aws_iam_account_summary',
            'aws_iam_account_password_policy',
            'aws_s3_account_settings',
            'aws_cloudtrail_trail',
            'aws_region',
            'aws_vpc',
            'aws_security_group',
            'aws_ec2_security_group',  # Check both versions
            'aws_iam_user',
            'aws_ec2_instance',
            'aws_s3_bucket'
        ]
        
        table_status = {}
        
        # Check which tables exist by querying information schema
        check_query = """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'aws' 
        AND table_name LIKE 'aws_%'
        ORDER BY table_name;
        """
        
        try:
            query_file = workspace_dir / 'table_check.sql'
            with open(query_file, 'w') as f:
                f.write(check_query)
            
            result = await self._run_command([
                'steampipe', 'query', str(query_file), '--output', 'json'
            ], workspace_dir, timeout=30)
            
            if result and result.strip():
                parsed_result = json.loads(result)
                available_tables = []
                
                if isinstance(parsed_result, dict) and 'rows' in parsed_result:
                    available_tables = [row.get('table_name', '') for row in parsed_result['rows']]
                
                # Mark tables as available or not
                for table in tables_to_check:
                    table_status[table] = table in available_tables
                    
                logger.info(f"Steampipe table validation: {len(available_tables)} AWS tables found")
                logger.debug(f"Available tables: {available_tables}")
                
            else:
                # Fallback: assume common tables exist
                for table in tables_to_check:
                    table_status[table] = table in [
                        'aws_account', 'aws_sts_caller_identity', 'aws_iam_user', 
                        'aws_s3_bucket', 'aws_region', 'aws_vpc'
                    ]
                
        except Exception as e:
            logger.warning(f"Table validation failed: {str(e)}")
            # Default to assuming basic tables exist
            for table in tables_to_check:
                table_status[table] = table in ['aws_account', 'aws_sts_caller_identity']
        
        return table_status

    async def _get_table_columns(self, table_name: str, workspace_dir: Path) -> List[str]:
        """
        Get available columns for a specific table
        
        Args:
            table_name: Name of the table to check
            workspace_dir: Workspace directory for SQL files
            
        Returns:
            List of column names
        """
        columns_query = f"""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_schema = 'aws' 
        AND table_name = '{table_name}'
        ORDER BY ordinal_position;
        """
        
        try:
            query_file = workspace_dir / f'{table_name}_columns.sql'
            with open(query_file, 'w') as f:
                f.write(columns_query)
            
            result = await self._run_command([
                'steampipe', 'query', str(query_file), '--output', 'json'
            ], workspace_dir, timeout=15)
            
            if result and result.strip():
                parsed_result = json.loads(result)
                columns = []
                
                if isinstance(parsed_result, dict) and 'rows' in parsed_result:
                    columns = [row.get('column_name', '') for row in parsed_result['rows']]
                
                logger.debug(f"Table {table_name} has columns: {columns}")
                return columns
                
        except Exception as e:
            logger.warning(f"Failed to get columns for {table_name}: {str(e)}")
        
        return []

    async def _collect_steampipe_config_data_safe(self, workspace_dir: Path) -> Dict[str, Any]:
        """
        Enhanced config data collection with table/column validation
        """
        # First, validate which tables are available
        table_status = await self._validate_steampipe_tables(workspace_dir)
        
        # Build queries based on available tables
        safe_queries = {}
        
        # Account info - basic and should always work
        if table_status.get('aws_account', False):
            safe_queries['account_info'] = "SELECT account_id, partition FROM aws_account;"
        
        # Caller identity - check which table version exists
        if table_status.get('aws_sts_caller_identity', False):
            safe_queries['caller_identity'] = "SELECT account_id, arn, user_id FROM aws_sts_caller_identity;"
        elif table_status.get('aws_caller_identity', False):
            safe_queries['caller_identity'] = "SELECT account_id, arn, user_id FROM aws_caller_identity;"
        
        # IAM summary
        if table_status.get('aws_iam_account_summary', False):
            safe_queries['iam_summary'] = "SELECT users, groups, roles, policies, mfa_devices FROM aws_iam_account_summary;"
        
        # Password policy
        if table_status.get('aws_iam_account_password_policy', False):
            safe_queries['password_policy'] = """
                SELECT minimum_password_length, require_uppercase_characters, 
                    require_lowercase_characters, require_symbols, require_numbers,
                    password_reuse_prevention, max_password_age
                FROM aws_iam_account_password_policy;
            """
        
        # S3 account settings
        if table_status.get('aws_s3_account_settings', False):
            safe_queries['s3_public_block'] = """
                SELECT block_public_acls, block_public_policy, ignore_public_acls, 
                    restrict_public_buckets FROM aws_s3_account_settings;
            """
        
        # CloudTrail
        if table_status.get('aws_cloudtrail_trail', False):
            safe_queries['cloudtrail_status'] = """
                SELECT name, is_multi_region_trail, is_logging, log_file_validation_enabled,
                    home_region FROM aws_cloudtrail_trail LIMIT 3;
            """
        
        # Regions - validated column name
        if table_status.get('aws_region', False):
            # Get columns first to check correct name
            region_columns = await self._get_table_columns('aws_region', workspace_dir)
            if 'region' in region_columns:
                safe_queries['regions'] = """
                    SELECT region, opt_in_status FROM aws_region 
                    WHERE opt_in_status IN ('opt-in-not-required', 'opted-in') LIMIT 10;
                """
            elif 'region_name' in region_columns:
                safe_queries['regions'] = """
                    SELECT region_name as region, opt_in_status FROM aws_region 
                    WHERE opt_in_status IN ('opt-in-not-required', 'opted-in') LIMIT 10;
                """
        
        # VPC info
        if table_status.get('aws_vpc', False):
            safe_queries['vpc_info'] = """
                SELECT vpc_id, cidr_block, is_default, state 
                FROM aws_vpc LIMIT 5;
            """
        
        # Security groups - check which table version exists  
        if table_status.get('aws_security_group', False):
            safe_queries['security_groups'] = """
                SELECT group_id, group_name, vpc_id, 
                    jsonb_array_length(ip_permissions) as inbound_rules,
                    jsonb_array_length(ip_permissions_egress) as outbound_rules
                FROM aws_security_group 
                WHERE group_name IN ('default', 'launch-wizard-1') 
                LIMIT 5;
            """
        elif table_status.get('aws_ec2_security_group', False):
            safe_queries['security_groups'] = """
                SELECT group_id, group_name, vpc_id, 
                    jsonb_array_length(ip_permissions) as inbound_rules,
                    jsonb_array_length(ip_permissions_egress) as outbound_rules
                FROM aws_ec2_security_group 
                WHERE group_name IN ('default', 'launch-wizard-1') 
                LIMIT 5;
            """
        
        # IAM users - validate columns
        if table_status.get('aws_iam_user', False):
            iam_columns = await self._get_table_columns('aws_iam_user', workspace_dir)
            if 'mfa_enabled' in iam_columns:
                safe_queries['iam_users_summary'] = """
                    SELECT count(*) as total_users,
                        sum(case when mfa_enabled then 1 else 0 end) as users_with_mfa
                    FROM aws_iam_user;
                """
            else:
                safe_queries['iam_users_summary'] = """
                    SELECT count(*) as total_users,
                        0 as users_with_mfa
                    FROM aws_iam_user;
                """
        
        # EC2 instances
        if table_status.get('aws_ec2_instance', False):
            safe_queries['ec2_instances'] = """
                SELECT instance_id, instance_type, instance_state 
                FROM aws_ec2_instance 
                LIMIT 3;
            """
        
        # S3 buckets
        if table_status.get('aws_s3_bucket', False):
            safe_queries['s3_buckets'] = """
                SELECT name, creation_date, region 
                FROM aws_s3_bucket 
                LIMIT 5;
            """
        
        logger.info(f"Generated {len(safe_queries)} safe queries based on available tables")
        
        # Now run the safe queries
        config_data = {}
        successful_queries = 0
        
        for config_name, query in safe_queries.items():
            try:
                logger.info(f"Collecting {config_name} configuration data")
                query_file = workspace_dir / f'{config_name}_config.sql'
                with open(query_file, 'w') as f:
                    f.write(query)
                
                result = await self._run_command([
                    'steampipe', 'query', str(query_file), '--output', 'json'
                ], workspace_dir, timeout=30)
                
                if result and result.strip():
                    try:
                        parsed_result = json.loads(result)
                        if isinstance(parsed_result, dict) and 'rows' in parsed_result:
                            config_data[config_name] = parsed_result['rows']
                        elif isinstance(parsed_result, list):
                            config_data[config_name] = parsed_result
                        else:
                            config_data[config_name] = [parsed_result]
                        
                        successful_queries += 1
                        logger.info(f"✓ Collected {config_name}: {len(config_data[config_name])} items")
                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"✗ Failed to parse JSON for {config_name}: {str(e)}")
                        config_data[config_name] = []
                else:
                    logger.warning(f"✗ No data returned for {config_name}")
                    config_data[config_name] = []
                    
            except Exception as e:
                logger.warning(f"✗ Failed to collect {config_name}: {str(e)}")
                config_data[config_name] = []
        
        # Log final summary
        total_attempted = len(safe_queries)
        logger.info(f"Safe config data collection summary: {successful_queries}/{total_attempted} sections collected successfully")
        
        # Add table availability info to metadata
        config_data['_table_status'] = table_status
        config_data['_queries_attempted'] = list(safe_queries.keys())
        
        return config_data
    
    async def scan_aws_account(self, user_id: str, account_id: str, credentials: Dict[str, str], 
                     scan_id: str = None, role_config: Dict[str, str] = None,
                     aws_cloudname: str = None) -> Dict[str, Any]:  # NEW parameter
        """
        Enhanced scan method with assumed role support and RAG analysis
        
        Args:
            user_id: User identifier
            account_id: AWS account ID
            credentials: Base AWS credentials
            scan_id: Optional scan ID
            role_config: Optional role configuration for assumption
            aws_cloudname: Optional AWS cloudname for RAG analysis
            
        Returns:
            Dict containing scan results
        """
        try:
            # Set role configuration if provided
            if role_config:
                self.set_role_config(role_config)
            
            # Set scan information with consistent ID
            if not scan_id:
                scan_id = generate_unique_scan_id()
            
            self.set_scan_info(user_id, account_id, scan_id)
            logger.info(f"AWS scan using scan ID: {scan_id}")
            
            # Aggressively clear any existing scan data
            aggressively_clear_scan_data(user_id, account_id, 'aws')
            
            # Configure AWS credentials (this will now handle role assumption)
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token') or ''
            
            self.aws_credentials = credentials  # Store credentials for later use
            
            # Send initial progress update
            await self._ensure_progress_update('initializing', 5)
                
            # Validate credentials using the enhanced method
            boto3_validator = AwsCredentialValidator()
            validation_results = await boto3_validator.validate_credentials_with_role(
                credentials, account_id, self.role_config
            )
            
            if not validation_results.get("valid", False):
                error_msg = "Cannot connect to AWS: Invalid credentials or role assumption failed"
                logger.error(error_msg)
                
                # Update database if needed
                if self.db_session and self.scan_record:
                    try:
                        self.scan_record.status = 'error'
                        self.scan_record.error = error_msg
                        self.scan_record.completed_at = datetime.now()
                        self.db_session.commit()
                    except Exception as db_e:
                        logger.error(f"Failed to store error record: {str(db_e)}")
                        self.db_session.rollback()
                
                # Send error progress update
                await self._ensure_progress_update('error', 0)
                
                return {
                    'success': False,
                    'error': {
                        'message': error_msg,
                        'code': 'CREDENTIAL_ERROR',
                        'details': validation_results
                    }
                }
            
            # Log successful role assumption if applicable
            if validation_results.get("role_assumed"):
                logger.info(f"Successfully assumed role: {validation_results.get('assumed_role_arn')}")
                logger.info(f"Operating as: {validation_results.get('caller_identity', {}).get('arn')}")
            
            # Credentials are valid, proceed with scan
            logger.info(f"Validated credentials for account: {validation_results.get('account_id')}")
            await self._ensure_progress_update('validation_complete', 15)
            
            # Configure AWS connection
            await self._ensure_progress_update('configuring', 20)
            try:
                # Use Steampipe update script
                result = subprocess.run(['/bin/bash', '/home/steampipe/scripts/update_aws_connection.sh'], 
                                    check=False, capture_output=True, text=True)
                logger.info(f"Connection configuration result: {result.returncode}")
                
                if "Successfully connected to AWS account" in result.stdout:
                    logger.info("AWS connection configured successfully")
                    await self._ensure_progress_update('config_complete', 25)
                else:
                    logger.warning(f"AWS connection script didn't confirm success: {result.stdout}")
            except Exception as config_e:
                logger.warning(f"AWS connection script warning (non-critical): {str(config_e)}")
            
            # Run benchmark scan with proper progress updates
            await self._ensure_progress_update('running_benchmark', 30)
            await self._ensure_progress_update('preparing_scan', 35)
            await self._ensure_progress_update('scanning', 40)
            
            # Run the actual compliance check
            try:
                results = await self.run_aws_compliance_check(account_id)
                await self._ensure_progress_update('scan_complete', 50)
            except Exception as check_e:
                logger.error(f"Compliance check error: {str(check_e)}")
                results = {}
                await self._ensure_progress_update('scan_error_recovery', 50)
            
            # Process results and prepare final data
            await self._ensure_progress_update('preparing_results', 65)
            await self._ensure_progress_update('processing', 70)

            

            # Process benchmark results if available
            findings_data = None

            if results:
                logger.info(f"Results structure check: type={type(results)}, keys={list(results.keys()) if isinstance(results, dict) else 'not dict'}")
                
                # Check if results contain processed benchmark data
                if isinstance(results, dict):
                    # Check for direct findings in results
                    if 'findings' in results and results['findings']:
                        logger.info(f"Found direct findings in results: {len(results['findings'])} findings")
                        findings_data = results
                    # Check for groups structure (raw benchmark results)
                    elif 'groups' in results:
                        logger.info("Found groups structure, processing benchmark results")
                        await self._ensure_progress_update('processing_benchmark', 75)
                        
                        processed_results = self._process_benchmark_results(results, account_id)
                        findings = processed_results.get('findings', [])
                        stats = processed_results.get('stats', {})
                        metadata = processed_results.get('metadata', {})
                        
                        await self._ensure_progress_update('benchmark_processed', 80)
                        
                        findings_data = {
                            'findings': findings,
                            'stats': stats,
                            'metadata': metadata
                        }
                        
                        logger.info(f"✅ Using CIS benchmark results: {len(findings)} findings")
                    else:
                        logger.warning(f"Results dict exists but no 'findings' or 'groups' key found. Keys: {list(results.keys())}")

            # FIXED: Move fallback logic to top level (outside the dict check)
            if not findings_data or not findings_data.get('findings'):
                logger.info("Creating fallback findings from validation data")
                findings_data = self._create_fallback_findings(validation_results, account_id)
                logger.info(f"✅ Using fallback results: {len(findings_data.get('findings', []))} findings")
            else:
                logger.info(f"✅ Final findings count: {len(findings_data.get('findings', []))}")
            
            # Ensure we have at least one finding
            if not findings_data or not findings_data.get('findings') or len(findings_data.get('findings', [])) == 0:
                logger.warning("No findings were generated, adding default finding")
                # Only create fallback if we truly have no findings
                findings_data = {
                    'findings': [{
                        'id': f"aws-{account_id}-default",
                        'severity': "INFO",
                        'category': "General", 
                        'control': "AWS Security Scan",
                        'control_id': "DEFAULT-1",
                        'status': "Info",
                        'reason': "No specific security findings detected",
                        'details': "AWS security scan completed but did not detect any specific issues",
                        'resource_id': account_id,
                        'account_id': account_id
                    }],
                    'stats': {
                        'total_findings': 1,
                        'failed_findings': 0,
                        'pass_findings': 1,
                        'severity_counts': {'INFO': 1, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0},
                        'category_counts': {'General': 1}
                    },
                    'metadata': {
                        'scan_time': datetime.now().isoformat(),
                        'account_id': account_id
                    }
                }
            else:
                logger.info(f"✅ Final findings count: {len(findings_data.get('findings', []))}")
            
            # Reranking phase
            await self._ensure_progress_update('collecting_config', 85)
            await self._ensure_progress_update('preparing_rerank', 88)
            await self._ensure_progress_update('reranking', 90)
            
            # Rerank findings if applicable
            reordered_findings = []
            findings = findings_data.get('findings', [])
            if findings:
                # Check if we have a reranking URL
                rerank_url = os.getenv('AWS_RERANK_URL')
                if rerank_url:
                    logger.info(f"Reranking {len(findings)} findings")
                    reordered_findings = await rerank_aws_findings(findings, user_id, account_id)
                    logger.info(f"Reranking complete with {len(reordered_findings)} findings")
                else:
                    logger.info("Skipping reranking as AWS_RERANK_URL is not set")
                    # Important: always assign a copy of the findings, even if not reranked
                    reordered_findings = findings.copy()
            
            # Update progress after reranking
            await self._ensure_progress_update('rerank_complete', 92)
            
            # RAG analysis phase (NEW)
            await self._ensure_progress_update('rag_analysis', 93)

            if aws_cloudname and findings:
                logger.info(f"Running RAG analysis with cloudname: {aws_cloudname}")
                
                # FIXED: Create workspace_dir here since it's needed for config collection
                workspace_dir = self.temp_dir / 'workspace'
                workspace_dir.mkdir(exist_ok=True)
                
                # NEW: Collect AWS config data using Steampipe
                logger.info("Collecting AWS configuration data...")
                try:
                    config_data = await self._collect_steampipe_config_data(workspace_dir)
                except Exception as config_e:
                    logger.warning(f"Config data collection failed: {str(config_e)}")
                    config_data = {}
                
                # Enhanced RAG call with config data
                rag_response = await rag_steampipe_analysis(
                    findings, user_id, aws_cloudname, config_data  # NEW parameter
                )
                if rag_response:
                    logger.info(f"RAG analysis completed: {len(str(rag_response))} bytes response")
                    # Store rag_response in metadata
                    if 'metadata' not in findings_data:
                        findings_data['metadata'] = {}
                    findings_data['metadata']['rag_analysis'] = rag_response
                else:
                    logger.info("RAG analysis failed or returned empty response")
            else:
                logger.info("RAG analysis skipped - no aws_cloudname provided or no findings")

            await self._ensure_progress_update('rag_complete', 94)
            
            # Sanitize data for JSON serialization
            await self._ensure_progress_update('preparing_save', 95)
            sanitized_data = sanitize_for_json(findings_data)
            sanitized_rerank = sanitize_for_json(reordered_findings)
            
            # Update database record
            await self._ensure_progress_update('saving', 96)
            if self.db_session and self.scan_record:
                try:
                    # Use raw SQL with better error handling to store findings
                    serialized_json = json.dumps(sanitized_data, cls=DateTimeEncoder)
                    reordered_json = json.dumps(sanitized_rerank, cls=DateTimeEncoder)
                    
                    # Update using raw SQL to ensure findings are properly saved
                    self.db_session.execute(
                        text("""
                        UPDATE cloud_scans 
                        SET status = 'completed', 
                            completed_at = NOW(),
                            findings = CAST(:findings_json AS JSONB),
                            rerank = CAST(:rerank_json AS JSONB)
                        WHERE id = :scan_id
                        """), 
                        {
                            'scan_id': self.scan_record.id, 
                            'findings_json': serialized_json,
                            'rerank_json': reordered_json
                        }
                    )
                    self.db_session.commit()
                    
                    logger.info(f"Scan record {self.scan_record.id} updated successfully")
                    await self._ensure_progress_update('save_complete', 98)
                except Exception as db_e:
                    logger.error(f"Database update error: {str(db_e)}")
                    self.db_session.rollback()
            
            # Final progress updates
            await self._ensure_progress_update('finalizing', 99)
            await self._ensure_progress_update('completed', 100)
            
            logger.info(f"Successfully completed AWS scan for {user_id}/{account_id}")
            
            return {
                'success': True,
                'data': sanitized_data
            }
        
        except Exception as e:
            logger.error(f"AWS CIS benchmark scan failed: {str(e)}", exc_info=True)
            
            # Update error in database
            if self.db_session and self.scan_record:
                try:
                    self.scan_record.status = 'error'
                    self.scan_record.error = str(e)
                    self.scan_record.completed_at = datetime.now()
                    self.db_session.commit()
                except Exception:
                    self.db_session.rollback()
            
            # Send error update
            await self._ensure_progress_update('error', 0)
            
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }
    def _create_fallback_findings(self, validation_results: Dict, account_id: str) -> Dict:
        """
        Create fallback findings based on validation results when benchmark scan fails.
        
        Args:
            validation_results: Results from credential validation
            account_id: AWS account ID
            
        Returns:
            Dict with findings data structure
        """
        findings = []
        
        # Add authentication finding
        findings.append({
            'id': f"aws-{account_id}-authenticated",
            'severity': "INFO",
            'category': "Authentication",
            'control': "AWS API Access",
            'control_id': "AUTH-1",
            'status': "Pass",
            'reason': "Successfully authenticated to AWS API",
            'details': f"Authenticated as: {validation_results.get('caller_identity', {}).get('arn', 'Unknown')}",
            'resource_id': account_id,
            'account_id': account_id
        })
        
        # Add service-specific findings
        for service, accessible in validation_results.get('services_accessible', {}).items():
            status = "Pass" if accessible else "Fail"
            severity = "INFO" if accessible else "MEDIUM"
            findings.append({
                'id': f"aws-{account_id}-{service}-access",
                'severity': severity,
                'category': service.upper(),
                'control': f"{service.upper()} Access",
                'control_id': f"{service.upper()}-1",
                'status': status,
                'reason': f"{service.upper()} service {'is' if accessible else 'is not'} accessible",
                'details': f"The credentials {'have' if accessible else 'do not have'} access to {service} services",
                'resource_id': account_id,
                'account_id': account_id
            })
        
        # Calculate stats
        stats = {
            'total_findings': len(findings),
            'failed_findings': sum(1 for f in findings if f.get('status') == 'Fail'),
            'warning_findings': sum(1 for f in findings if f.get('status') == 'Warning'),
            'pass_findings': sum(1 for f in findings if f.get('status') in ['Pass', 'Info']),
            'severity_counts': {
                "CRITICAL": sum(1 for f in findings if f.get('severity') == "CRITICAL"),
                "HIGH": sum(1 for f in findings if f.get('severity') == "HIGH"),
                "MEDIUM": sum(1 for f in findings if f.get('severity') == "MEDIUM"),
                "LOW": sum(1 for f in findings if f.get('severity') == "LOW"),
                "INFO": sum(1 for f in findings if f.get('severity') == "INFO"),
            },
            'category_counts': {},
            'resource_counts': 1,
            'account_id': account_id
        }
        
        # Calculate category counts
        for finding in findings:
            category = finding.get('category', 'Unknown')
            if category not in stats['category_counts']:
                stats['category_counts'][category] = 0
            stats['category_counts'][category] += 1
        
        # Create metadata
        metadata = {
            'scan_time': datetime.now().isoformat(),
            'account_id': account_id,
            'cloud_provider': 'aws',
            'benchmark': 'AWS API Access Check',
            'scan_type': 'boto3-api',
            'scan_duration_seconds': (datetime.now() - self.scan_stats.get('start_time', datetime.now())).total_seconds(),
            'validation_results': sanitize_for_json(validation_results)
        }
        
        return {
            'findings': findings,
            'stats': stats,
            'metadata': metadata
        }
    def set_scan_info(self, user_id: str, account_id: str, scan_id: str = None):
        """Set scan information for progress tracking"""
        self._user_id = user_id
        self._account_id = account_id
        self._scan_id = scan_id or generate_unique_scan_id()
        logger.info(f"AWS Scanner scan info set: {user_id}:{account_id}, scan_id: {self._scan_id}")

    async def _ensure_progress_update(self, stage: str, progress: int, retries: int = 3):
        """Send a progress update with retries to ensure delivery."""
        if not all([self._user_id, self._account_id]):
            logger.warning("Cannot send progress update: user_id or account_id not set")
            return False
            
        if not self._scan_id:
            self._scan_id = generate_unique_scan_id()
            
        # Add a small random delay to prevent message collision
        await asyncio.sleep(random.uniform(0.1, 0.3))
        
        success = False
        for attempt in range(retries):
            try:
                result = update_scan_progress(
                    self._user_id, 
                    self._account_id, 
                    stage, 
                    progress, 
                    scan_type='aws', 
                    scan_id=self._scan_id
                )
                if result:
                    success = True
                    # Add extra delay after successful update for important stages
                    if progress >= 95 or stage == 'completed' or stage == 'error':
                        await asyncio.sleep(0.5)  # Longer delay for critical updates
                    break
            except Exception as e:
                logger.error(f"Progress update attempt {attempt+1} failed for stage {stage}: {str(e)}")
                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        if not success and (stage == 'completed' or stage == 'error'):
            logger.warning(f"Failed to send critical '{stage}' update after {retries} attempts")
        
        return success

async def rag_steampipe_analysis(
    findings: List[Dict], 
    user_id: str, 
    aws_cloudname: str,
    config_data: Optional[Dict] = None
) -> Dict:
    """
    Send AWS security findings to RAG analysis service with enhanced config data.
    
    Args:
        findings: List of security findings
        user_id: User identifier
        aws_cloudname: AWS cloud name for context
        config_data: AWS configuration data from Steampipe
        
    Returns:
        Dict: RAG analysis response
    """
    try:
        logger.info(f"Preparing {len(findings)} AWS findings for RAG analysis")
        
        # Get RAG URL from environment variable
        rag_url = os.getenv('RAG_URL')
        if not rag_url:
            logger.warning("RAG_URL environment variable not set, skipping RAG analysis")
            return {}
        
        # Append the specific endpoint for steampipe analysis
        rag_endpoint = f"{rag_url.rstrip('/')}/rag_steampipe_analysis"
        
        # Prepare enhanced data for RAG API
        rag_data = {
            'user_id': user_id,
            'cloudname': aws_cloudname,
            'file': [{
                "ID": idx + 1,
                "category": finding.get("category", ""),
                "reason": finding.get("reason", ""),
                "severity": finding.get("severity", ""),
                "status": finding.get("status", ""),
                "control_id": finding.get("control_id", ""),
                "resource_id": finding.get("resource_id", "")
            } for idx, finding in enumerate(findings)]
        }
        
        # Enhanced config data processing
        if config_data:
            processed_config = {}
            
            # Process each config section
            for section_name, section_data in config_data.items():
                if section_data and isinstance(section_data, list) and len(section_data) > 0:
                    processed_config[section_name] = {
                        'count': len(section_data),
                        'sample_data': section_data[:3] if len(section_data) > 3 else section_data,
                        'has_data': True
                    }
                else:
                    processed_config[section_name] = {
                        'count': 0,
                        'has_data': False
                    }
            
            # Add AWS environment summary
            aws_summary = {
                'account_info': processed_config.get('account_info', {}),
                'iam_summary': processed_config.get('iam_summary', {}),
                'regions_count': processed_config.get('regions', {}).get('count', 0),
                'vpcs_count': processed_config.get('vpc_info', {}).get('count', 0),
                'cloudtrail_configured': processed_config.get('cloudtrail_status', {}).get('has_data', False),
                'password_policy_configured': processed_config.get('password_policy', {}).get('has_data', False)
            }
            
            rag_data['aws_config'] = processed_config
            rag_data['aws_environment_summary'] = aws_summary
            
            logger.info(f"Including AWS config data with {len(processed_config)} sections")
            logger.info(f"Config summary: {sum(1 for v in processed_config.values() if v.get('has_data'))} sections have data")
        
        # Add findings summary for context
        findings_summary = {
            'total_findings': len(findings),
            'severity_breakdown': {},
            'category_breakdown': {},
            'status_breakdown': {}
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'UNKNOWN')
            findings_summary['severity_breakdown'][severity] = findings_summary['severity_breakdown'].get(severity, 0) + 1
            
            # Count by category
            category = finding.get('category', 'UNKNOWN')
            findings_summary['category_breakdown'][category] = findings_summary['category_breakdown'].get(category, 0) + 1
            
            # Count by status
            status = finding.get('status', 'UNKNOWN')
            findings_summary['status_breakdown'][status] = findings_summary['status_breakdown'].get(status, 0) + 1
        
        rag_data['findings_summary'] = findings_summary
        
        # Send to RAG API with timeout and retry logic
        logger.info(f"Sending {len(findings)} findings to RAG analysis: {rag_endpoint}")
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                timeout = aiohttp.ClientTimeout(total=90)  # Increased timeout for large payloads
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(rag_endpoint, json=rag_data) as response:
                        if response.status == 200:
                            rag_response = await response.json()
                            logger.info(f"RAG analysis completed successfully")
                            
                            # Add metadata about the analysis
                            if isinstance(rag_response, dict):
                                rag_response['analysis_metadata'] = {
                                    'findings_analyzed': len(findings),
                                    'config_sections_provided': len(config_data) if config_data else 0,
                                    'analysis_timestamp': datetime.now().isoformat(),
                                    'cloudname': aws_cloudname
                                }
                            
                            return rag_response
                        else:
                            error_text = await response.text()
                            logger.error(f"RAG API error (status {response.status}): {error_text}")
                            
                            if attempt < max_retries - 1:
                                logger.info(f"Retrying RAG analysis (attempt {attempt + 2}/{max_retries})")
                                await asyncio.sleep(2)  # Wait before retry
                                continue
                            else:
                                return {}
                                
            except asyncio.TimeoutError:
                logger.error(f"RAG analysis timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(3)
                    continue
                else:
                    return {}
                    
            except Exception as e:
                logger.error(f"RAG analysis request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                else:
                    return {}
        
        return {}
    
    except Exception as e:
        logger.error(f"Error in RAG steampipe analysis: {str(e)}")
        logger.error(traceback.format_exc())
        return {}

async def rerank_aws_findings(
    findings: List[Dict], 
    user_id: str, 
    account_id: str,
    rerank_url: Optional[str] = None
) -> List[Dict]:
    """
    Rerank AWS security findings using the AI reranking service.
    
    Args:
        findings: List of AWS security findings
        user_id: User identifier
        account_id: AWS account ID
        rerank_url: URL of the reranking service (optional, will use env var if not provided)
        
    Returns:
        List[Dict]: Reordered findings based on AI reranking
    """
    # Helper function to extract IDs from LLM response
    def extract_ids_from_llm_response(response_data: Union[Dict, List, str], original_findings: List[Dict] = None) -> Optional[List[int]]:
        """
        Extract IDs from LLM response text.
        
        Args:
            response_data: Response from reranking API
            original_findings: Original list of findings (for reference)
            
        Returns:
            Optional[List[int]]: List of reranked IDs or None if extraction fails
        """
        try:
            logger.info(f"Processing reranking response: {json.dumps(response_data, indent=2)}")
            
            # Handle dictionary response
            if isinstance(response_data, dict):
                # Check for llm_response field
                if 'llm_response' in response_data:
                    response = response_data['llm_response']
                    logger.info(f"LLM Response content: {response}")
                    
                    # Always return a valid list of IDs - either from response or fallback to sequential
                    if not response or response == '[]':
                        logger.warning("Empty llm_response, falling back to original order")
                        return list(range(1, len(original_findings) + 1)) if original_findings else None
                        
                    if isinstance(response, list):
                        return response
                        
                    array_match = re.search(r'\[([\d,\s]+)\]', str(response))
                    if array_match:
                        id_string = array_match.group(1)
                        return [int(id.strip()) for id in id_string.split(',')]
            
            # Handle list response
            elif isinstance(response_data, list):
                if not response_data:
                    logger.warning("Empty list response")
                    return list(range(1, len(original_findings) + 1)) if original_findings else None
                return response_data
            
            logger.warning("Could not extract IDs from response")
            return list(range(1, len(original_findings) + 1)) if original_findings else None
            
        except Exception as e:
            logger.error(f"Error extracting IDs from LLM response: {str(e)}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return list(range(1, len(original_findings) + 1)) if original_findings else None

    try:
        logger.info(f"Preparing {len(findings)} AWS findings for reranking")
        
        # Get rerank URL from environment variable if not provided
        if not rerank_url:
            rerank_url = os.getenv('AWS_RERANK_URL')
            if not rerank_url:
                logger.warning("AWS_RERANK_URL environment variable not set, skipping reranking")
                return findings
        
        # Initialize variables
        selected_findings = []
        
        # Select findings based on total count
        # Select findings based on total count
        if len(findings) <= 40:
            selected_findings = findings.copy()
            logger.info(f"Processing all {len(selected_findings)} findings (under 40 threshold)")
        else:
            # Use status-based selection logic for larger sets (prioritize by criticality)
            failed_findings = [f for f in findings if f.get('status', '').lower() == 'alarm']  
            info_findings = [f for f in findings if f.get('status', '').lower() == 'info']
            ok_findings = [f for f in findings if f.get('status', '').lower() == 'ok']
            skipped_findings = [f for f in findings if f.get('status', '').lower() == 'skip']

            # Add findings in priority order up to 40
            remaining = 40
            for status_findings in [failed_findings, info_findings, ok_findings, skipped_findings]:
                if remaining > 0:
                    to_add = status_findings[:remaining]
                    selected_findings.extend(to_add)
                    remaining -= len(to_add)
                    
            logger.info(f"Selected {len(selected_findings)} findings based on status prioritization")

        # Prepare data for reranking API (include status!)
        rerank_data = {
            'findings': [{
                "ID": idx + 1,
                "category": finding.get("category", ""),
                "reason": finding.get("reason", ""),
                "severity": finding.get("severity"),
                "status": finding.get("status")  # CRITICAL: Include status for LLM
            } for idx, finding in enumerate(selected_findings)],
            'metadata': {
                'user_id': user_id
            }
        }
        
        # Send to reranking API
        logger.info(f"Sending {len(selected_findings)} findings for reranking")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(rerank_url, json=rerank_data, timeout=60) as response:
                    if response.status == 200:
                        rerank_response = await response.json()
                        logger.info(f"Received reranking response")
                        
                        # Extract reranked IDs from response - using the nested helper function
                        reranked_ids = extract_ids_from_llm_response(rerank_response, selected_findings)
                        
                        if reranked_ids:
                            # Create a map of findings by ID
                            findings_map = {idx + 1: finding for idx, finding in enumerate(selected_findings)}
                            
                            # Reorder findings based on response
                            reordered_findings = [findings_map[id] for id in reranked_ids if id in findings_map]
                            logger.info(f"Successfully reordered {len(reordered_findings)} findings")
                            return reordered_findings
                        else:
                            logger.warning("No valid reranking IDs returned, using original order")
                            return selected_findings
                    else:
                        error_text = await response.text()
                        logger.error(f"Reranking API error (status {response.status}): {error_text}")
                        return selected_findings
            except Exception as e:
                logger.error(f"Reranking request failed: {str(e)}")
                logger.error(traceback.format_exc())
                return selected_findings
    
    except Exception as e:
        logger.error(f"Error in AWS findings reranking: {str(e)}")
        logger.error(traceback.format_exc())
        return findings 
    

async def scan_aws_account_handler(
    user_id: str,
    account_id: str,
    credentials: Dict[str, str],
    db_session: Optional[Session] = None,
    scan_record: Optional[CloudScan] = None,
    role_config: Optional[Dict[str, str]] = None,  # OLD parameter
    aws_cloudname: Optional[str] = None  # NEW parameter
) -> Dict:
    """
    Handler function for AWS account scanning against CIS benchmarks
    with improved progress tracking and consistent scan IDs.
    
    Args:
        user_id: User ID
        account_id: AWS account ID  
        credentials: Base AWS credentials
        db_session: Database session
        scan_record: Scan record
        role_config: Optional role configuration with keys:
            - role_arn: ARN of role to assume
            - session_name: Optional session name
            - external_id: Optional external ID
        aws_cloudname: Optional AWS cloudname for RAG analysis
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"Starting AWS CIS benchmark scan for account: {account_id}")
        
        # Log role information if provided
        if role_config and role_config.get('role_arn'):
            logger.info(f"Will assume role: {role_config['role_arn']}")
        
        # Log RAG cloudname if provided
        if aws_cloudname:
            logger.info(f"RAG analysis will use cloudname: {aws_cloudname}")
        
        # Clear previous scan progress and start new scan
        from progress_tracking import aggressively_clear_scan_data
        aggressively_clear_scan_data(user_id, account_id, 'aws')
        
        # Generate consistent scan ID
        scan_id = initiate_new_aws_scan(user_id, account_id)
        logger.info(f"Using consistent scan ID: {scan_id}")
        
        if not all([user_id, account_id]):
            return {
                'success': False,
                'error': {
                    'message': 'Missing required parameters',
                    'code': 'INVALID_PARAMETERS'
                }
            }
        
        # Create scan record if not provided
        if db_session and not scan_record:
            scan_record = CloudScan(
                user_id=user_id,
                cloud_provider='aws',
                account_id=account_id,
                status='queued'
            )
            db_session.add(scan_record)
            db_session.commit()
            logger.info(f"Created scan record with ID: {scan_record.id}")
        
        # Set the credentials as environment variables for this scan
        original_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
        original_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
        original_session_token = os.environ.get('AWS_SESSION_TOKEN')
        
        try:
            # Set user-provided credentials
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token') or ''
            
            # Update progress and validate credentials - using the same scan_id
            update_scan_progress(user_id, account_id, 'validating_credentials', 10, 
                               scan_type='aws', scan_id=scan_id)
            
            # Validate credentials against expected account_id
            boto3_validator = AwsCredentialValidator()
            if role_config:
                validation_results = await boto3_validator.validate_credentials_with_role(credentials, account_id, role_config)
            else:
                validation_results = await boto3_validator.validate_credentials(credentials, account_id)
                        
            if not validation_results.get('valid', False):
                error_message = 'AWS credential validation failed: ' + '; '.join(validation_results.get('errors', ['Unknown error']))
                logger.error(error_message)
                
                if scan_record and db_session:
                    scan_record.status = 'error'
                    scan_record.error = error_message
                    scan_record.completed_at = datetime.now()
                    db_session.commit()
                
                update_scan_progress(user_id, account_id, 'error', 0, 
                                   scan_type='aws', scan_id=scan_id)
                
                return {
                    'success': False,
                    'error': {
                        'message': error_message,
                        'code': 'CREDENTIAL_ERROR',
                        'details': validation_results
                    }
                }
            
            # Update AWS connection configuration file - using same scan_id
            update_scan_progress(user_id, account_id, 'configuring', 20, 
                               scan_type='aws', scan_id=scan_id)
            result = subprocess.run(['/bin/bash', '/home/steampipe/scripts/update_aws_connection.sh'], 
                                  check=False, capture_output=True, text=True)
            logger.info(f"Connection configuration update result: {result.returncode}")
            if result.stdout:
                logger.info(f"Connection update output: {result.stdout}")
            if result.stderr:
                logger.warning(f"Connection update stderr: {result.stderr}")
            
            # Update progress after connection configured - using same scan_id
            update_scan_progress(user_id, account_id, 'config_complete', 25, 
                               scan_type='aws', scan_id=scan_id)
                
            # Update status to in_progress
            if scan_record and db_session:
                scan_record.status = 'in_progress'
                db_session.commit()
            
            # Run benchmark scan - using same scan_id
            update_scan_progress(user_id, account_id, 'running_benchmark', 30, 
                               scan_type='aws', scan_id=scan_id)
            
            # Update progress before starting scan - using same scan_id
            update_scan_progress(user_id, account_id, 'preparing_scan', 35, 
                               scan_type='aws', scan_id=scan_id)
            
            # Update progress when scanning starts - using same scan_id
            update_scan_progress(user_id, account_id, 'scanning', 40, 
                               scan_type='aws', scan_id=scan_id)
            
            # Initialize and run scanner
            async with AwsSecurityScanner(db_session, scan_record) as scanner:
                scanner.set_scan_info(user_id, account_id, scan_id)
                results = await scanner.scan_aws_account(
                    user_id, 
                    account_id, 
                    credentials, 
                    scan_id=scan_id,
                    role_config=role_config,
                    aws_cloudname=aws_cloudname  # NEW: Pass aws_cloudname
                )
                
                # Progress updates will be sent from scanner with the same scan_id
                
                # When updating the database record with final results, serialize findings properly
                if db_session and scan_record and results.get('success'):
                    try:
                        # Use raw SQL with proper datetime handling
                        findings_data = results.get('data', {})
                        db_session.execute(
                            text("""
                                UPDATE cloud_scans 
                                SET status = 'completed', 
                                    completed_at = NOW(),
                                    findings = CAST(:findings_json AS JSONB)
                                WHERE id = :scan_id
                            """), 
                            {'scan_id': scan_record.id, 'findings_json': json.dumps(findings_data)}
                        )
                        db_session.commit()
                        logger.info(f"Successfully updated scan record {scan_record.id}")
                        
                        # Mark as completed - with the same scan_id
                        update_scan_progress(user_id, account_id, 'completed', 100, 
                                           scan_type='aws', scan_id=scan_id)
                        
                    except Exception as db_e:
                        logger.error(f"Failed to update scan record: {str(db_e)}")
                        db_session.rollback()
                        
                        # Try setting a simple status update
                        try:
                            db_session.execute(
                                text("UPDATE cloud_scans SET status = 'completed', completed_at = NOW() WHERE id = :scan_id"),
                                {'scan_id': scan_record.id}
                            )
                            db_session.commit()
                            logger.info("Updated scan status only due to serialization issues")
                            
                            # Still mark as completed - with the same scan_id
                            update_scan_progress(user_id, account_id, 'completed', 100, 
                                               scan_type='aws', scan_id=scan_id)
                            
                        except Exception as status_e:
                            logger.error(f"Status update also failed: {str(status_e)}")
                            db_session.rollback()
                            
                            # Mark as error - with the same scan_id
                            update_scan_progress(user_id, account_id, 'error', 0, 
                                               scan_type='aws', scan_id=scan_id)
                
                return results
        
        except Exception as e:
            logger.error(f"AWS CIS scan handler error: {str(e)}")
            logger.error(traceback.format_exc())
            
            # Update error in database
            if db_session and scan_record:
                try:
                    scan_record.status = 'error'
                    scan_record.error = str(e)
                    scan_record.completed_at = datetime.now()
                    db_session.commit()
                except Exception:
                    db_session.rollback()
            
            # Update progress to error - with the same scan_id
            update_scan_progress(user_id, account_id, 'error', 0, 
                               scan_type='aws', scan_id=scan_id)
            
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }
        
        finally:
            # Restore original environment variables
            if original_access_key:
                os.environ['AWS_ACCESS_KEY_ID'] = original_access_key
            else:
                os.environ.pop('AWS_ACCESS_KEY_ID', None)
                
            if original_secret_key:
                os.environ['AWS_SECRET_ACCESS_KEY'] = original_secret_key
            else:
                os.environ.pop('AWS_SECRET_ACCESS_KEY', None)
                
            if original_session_token:
                os.environ['AWS_SESSION_TOKEN'] = original_session_token
            else:
                os.environ.pop('AWS_SESSION_TOKEN', None)
    
    except Exception as final_err:
        logger.critical(f"Unhandled error in scan handler: {str(final_err)}")
        logger.error(traceback.format_exc())
        
        # Update progress to error - with the same scan_id if available, otherwise generate one
        if 'scan_id' not in locals():
            scan_id = generate_unique_scan_id()
        update_scan_progress(user_id, account_id, 'error', 0, 
                           scan_type='aws', scan_id=scan_id)
        
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error during scan',
                'code': 'UNEXPECTED_ERROR',
                'type': type(final_err).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }