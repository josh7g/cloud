"""
AWS Security Scanner - Refactored to use unified cloud scanner architecture
"""
import os
import json
import logging
import asyncio
import boto3
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import time

from cloud_scanner.base_scanner import BaseCloudScanner
from cloud_scanner.steampipe_service import SteampipeService, STEAMPIPE_CONFIGS

logger = logging.getLogger(__name__)


class AwsCredentialValidator:
    """Validates AWS credentials using boto3"""
    
    @staticmethod
    async def validate_credentials(credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """
        Validate AWS credentials by calling STS GetCallerIdentity
        
        Args:
            credentials: Dict with aws_access_key_id, aws_secret_access_key, aws_session_token
            account_id: Optional expected account ID to validate against
            
        Returns:
            Dict with validation results
        """
        logger.info("Starting AWS credential validation")
        
        results = {
            "valid": False,
            "account_id": None,
            "caller_identity": None,
            "errors": []
        }
        
        try:
            # Create boto3 session with provided credentials
            session = boto3.Session(
                aws_access_key_id=credentials.get('aws_access_key_id'),
                aws_secret_access_key=credentials.get('aws_secret_access_key'),
                aws_session_token=credentials.get('aws_session_token')
            )
            
            # Test credentials with STS GetCallerIdentity
            sts_client = session.client('sts')
            
            try:
                response = sts_client.get_caller_identity()
                
                results['valid'] = True
                results['account_id'] = response['Account']
                results['caller_identity'] = {
                    'arn': response['Arn'],
                    'user_id': response['UserId'],
                    'account': response['Account']
                }
                
                logger.info(f"✓ Credentials valid for account: {response['Account']}")
                
                # Validate against expected account_id if provided
                if account_id and results['account_id'] != account_id:
                    results['valid'] = False
                    results['errors'].append(
                        f"Account ID mismatch: expected {account_id}, got {results['account_id']}"
                    )
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                logger.error(f"✗ STS GetCallerIdentity failed: {error_code} - {error_message}")
                results['errors'].append(f"Authentication failed: {error_code} - {error_message}")
                
        except Exception as e:
            logger.error(f"✗ Credential validation error: {str(e)}")
            results['errors'].append(f"Validation error: {str(e)}")
        
        return results
    
    @staticmethod
    async def validate_credentials_with_role(
        base_credentials: Dict[str, str],
        account_id: str,
        role_config: Dict[str, str]
    ) -> Dict[str, Any]:
        """
        Validate credentials by assuming a role
        
        Args:
            base_credentials: Base AWS credentials to assume role with
            account_id: Expected AWS account ID
            role_config: Dict with role_arn, external_id, session_name
            
        Returns:
            Dict with validation results
        """
        logger.info(f"Validating credentials by assuming role: {role_config.get('role_arn')}")
        
        results = {
            "valid": False,
            "account_id": None,
            "caller_identity": None,
            "assumed_role": None,
            "errors": []
        }
        
        try:
            # Create session with base credentials
            session = boto3.Session(
                aws_access_key_id=base_credentials.get('aws_access_key_id'),
                aws_secret_access_key=base_credentials.get('aws_secret_access_key'),
                aws_session_token=base_credentials.get('aws_session_token')
            )
            
            sts_client = session.client('sts')
            
            # Prepare assume role parameters
            assume_role_params = {
                'RoleArn': role_config['role_arn'],
                'RoleSessionName': role_config.get('session_name', f'SecurityScan-{int(time.time())}'),
                'DurationSeconds': 3600
            }
            
            if role_config.get('external_id'):
                assume_role_params['ExternalId'] = role_config['external_id']
            
            # Assume the role
            try:
                response = sts_client.assume_role(**assume_role_params)
                credentials_data = response['Credentials']
                
                # Create new session with assumed role credentials
                assumed_session = boto3.Session(
                    aws_access_key_id=credentials_data['AccessKeyId'],
                    aws_secret_access_key=credentials_data['SecretAccessKey'],
                    aws_session_token=credentials_data['SessionToken']
                )
                
                # Verify assumed role identity
                assumed_sts = assumed_session.client('sts')
                identity = assumed_sts.get_caller_identity()
                
                results['valid'] = True
                results['account_id'] = identity['Account']
                results['caller_identity'] = {
                    'arn': identity['Arn'],
                    'user_id': identity['UserId'],
                    'account': identity['Account']
                }
                results['assumed_role'] = {
                    'arn': response['AssumedRoleUser']['Arn'],
                    'expiration': credentials_data['Expiration'].isoformat()
                }
                
                logger.info(f"✓ Successfully assumed role for account: {identity['Account']}")
                
                # Validate against expected account_id
                if account_id and results['account_id'] != account_id:
                    results['valid'] = False
                    results['errors'].append(
                        f"Account ID mismatch: expected {account_id}, got {results['account_id']}"
                    )
                
            except ClientError as e:
                error_code = e.response['Error']['Code']
                error_message = e.response['Error']['Message']
                logger.error(f"✗ AssumeRole failed: {error_code} - {error_message}")
                results['errors'].append(f"Role assumption failed: {error_code} - {error_message}")
                
        except Exception as e:
            logger.error(f"✗ Role validation error: {str(e)}")
            results['errors'].append(f"Role validation error: {str(e)}")
        
        return results


class AwsAssumedRoleCredentials:
    """Manages AWS assumed role credentials with automatic refresh"""
    
    def __init__(
        self, 
        role_arn: str, 
        session_name: str = None,
        external_id: str = None, 
        base_credentials: Dict[str, str] = None
    ):
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


class AwsSecurityScanner(BaseCloudScanner):
    """
    AWS Security Scanner using Steampipe/Powerpipe for CIS benchmarks
    Inherits from BaseCloudScanner for common functionality
    """
    
    def __init__(self, db_session=None, scan_record=None):
        super().__init__(db_session, scan_record)
        self.steampipe_service = None
        self.aws_config = STEAMPIPE_CONFIGS['aws']
    
    def get_provider_name(self) -> str:
        """Return provider name"""
        return 'aws'
    
    async def validate_credentials(self, credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """Validate AWS credentials"""
        validator = AwsCredentialValidator()
        
        # Check if this is role assumption
        if 'role_arn' in credentials:
            base_creds = {
                'aws_access_key_id': credentials.get('aws_access_key_id'),
                'aws_secret_access_key': credentials.get('aws_secret_access_key'),
                'aws_session_token': credentials.get('aws_session_token')
            }
            
            role_config = {
                'role_arn': credentials['role_arn'],
                'external_id': credentials.get('external_id'),
                'session_name': credentials.get('session_name', f'SecurityScan-{int(time.time())}')
            }
            
            return await validator.validate_credentials_with_role(base_creds, account_id, role_config)
        else:
            return await validator.validate_credentials(credentials, account_id)
    
    async def setup(self):
        """Setup AWS scanner resources"""
        try:
            # Create workspace directory
            self.temp_dir = Path(f"/tmp/aws_scan_{int(time.time())}")
            self.temp_dir.mkdir(exist_ok=True, parents=True)
            
            logger.info(f"AWS scanner workspace: {self.temp_dir}")
            
            # Initialize Steampipe service
            self.steampipe_service = SteampipeService('aws', self.temp_dir)
            
            # Initialize Steampipe
            await self.steampipe_service.initialize_service()
            
            # Install AWS plugin
            await self.steampipe_service.install_plugin(
                self.aws_config['plugin_name'],
                self.aws_config['plugin_version']
            )
            
            # Initialize and install compliance mod
            await self.steampipe_service.initialize_mod()
            await self.steampipe_service.install_compliance_mod(
                self.aws_config['compliance_mod']
            )
            
            logger.info("AWS scanner setup complete")
            
        except Exception as e:
            logger.error(f"AWS scanner setup failed: {str(e)}")
            raise
    
    async def cleanup(self):
        """Clean up temporary resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                import shutil
                shutil.rmtree(self.temp_dir, ignore_errors=True)
                logger.info(f"Cleaned up workspace: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"Cleanup warning: {str(e)}")
    
    async def run_compliance_check(self, account_id: str) -> Dict[str, Any]:
        """Run AWS CIS compliance check using Steampipe"""
        try:
            if not self.steampipe_service:
                raise RuntimeError("Steampipe service not initialized")
            
            # Run the benchmark
            benchmark_name = self.aws_config['default_benchmark']
            logger.info(f"Running AWS benchmark: {benchmark_name}")
            
            results = await self.steampipe_service.run_benchmark(
                benchmark_name=benchmark_name,
                timeout=300
            )
            
            if not results:
                logger.warning("No benchmark results returned")
                return {}
            
            logger.info(f"AWS benchmark scan completed")
            return results
            
        except Exception as e:
            logger.error(f"AWS compliance check failed: {str(e)}")
            raise
    
    def _process_benchmark_results(self, results: Dict, account_id: str) -> Dict[str, Any]:
        """Process AWS benchmark results into standardized format"""
        try:
            findings = []
            category_counts = {}
            severity_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
            status_counts = {"alarm": 0, "ok": 0, "info": 0, "skip": 0}
            
            # Extract controls from benchmark results
            if 'groups' in results:
                for group in results['groups']:
                    self._process_group(group, findings, category_counts, severity_counts, status_counts, account_id)
            
            # Calculate stats
            stats = {
                'total_findings': len(findings),
                'failed_findings': status_counts.get('alarm', 0),
                'pass_findings': status_counts.get('ok', 0),
                'warning_findings': status_counts.get('info', 0),
                'skip_findings': status_counts.get('skip', 0),
                'severity_counts': severity_counts,
                'category_counts': category_counts,
                'status_counts': status_counts,
                'account_id': account_id
            }
            
            metadata = {
                'scan_time': datetime.now().isoformat(),
                'account_id': account_id,
                'cloud_provider': 'aws',
                'benchmark': 'AWS CIS Benchmark',
                'total_controls_evaluated': len(findings)
            }
            
            return {
                'findings': findings,
                'stats': stats,
                'metadata': metadata
            }
            
        except Exception as e:
            logger.error(f"Error processing benchmark results: {str(e)}")
            raise
    
    def _process_group(self, group, findings, category_counts, severity_counts, status_counts, account_id):
        """Recursively process benchmark groups and controls"""
        # Process controls in this group
        if 'controls' in group and group['controls'] is not None:
            for control in group['controls']:
                finding = self._process_control(control, account_id)
                if finding:
                    findings.append(finding)
                    
                    # Update counts
                    category = finding.get('category', 'Unknown')
                    category_counts[category] = category_counts.get(category, 0) + 1
                    
                    severity = finding.get('severity', 'INFO')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    status = finding.get('status', 'unknown').lower()
                    status_counts[status] = status_counts.get(status, 0) + 1
        
        # Recursively process child groups
        if 'groups' in group and group['groups'] is not None:
            for child_group in group['groups']:
                self._process_group(child_group, findings, category_counts, severity_counts, status_counts, account_id)
    
    def _process_control(self, control, account_id) -> Optional[Dict]:
        """Process a single control into a finding"""
        try:
            # Debug: Log first control to see structure
            if not hasattr(self, '_logged_control_structure'):
                logger.debug(f"Sample control structure: {json.dumps(control, indent=2, default=str)[:500]}")
                self._logged_control_structure = True
            
            control_id = control.get('control_id', 'unknown')
            title = control.get('title', 'Unknown Control')
            description = control.get('description', '')
            
            # Extract status from multiple possible locations
            status = 'unknown'
            if 'status' in control:
                status = control['status']
            elif 'summary' in control and control['summary'] is not None:
                if isinstance(control['summary'], dict):
                    status = control['summary'].get('status', 'unknown')
                else:
                    status = control['summary']
            
            # Also check results array for status
            if status == 'unknown' and 'results' in control and control['results']:
                # Get the most common status from results
                from collections import Counter
                statuses = [r.get('status', 'unknown') for r in control['results'] if isinstance(r, dict)]
                if statuses:
                    status = Counter(statuses).most_common(1)[0][0]
            
            # Map Steampipe status to our status
            status_map = {
                'alarm': 'alarm',
                'error': 'alarm',
                'ok': 'ok',
                'info': 'info',
                'skip': 'skip'
            }
            
            mapped_status = status_map.get(status.lower() if isinstance(status, str) else 'unknown', 'unknown')
            
            # Extract severity from control metadata or determine based on status and control type
            severity = control.get('severity', 'MEDIUM').upper()
            
            # If severity not in control, determine based on status and control type
            if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if mapped_status == 'alarm':
                    # High severity for IAM, root, encryption, and public access issues
                    if any(keyword in control_id.lower() for keyword in ['iam', 'root', 'mfa', 'password']):
                        severity = 'HIGH'
                    elif any(keyword in control_id.lower() for keyword in ['encryption', 'kms', 'public', 'exposed']):
                        severity = 'HIGH'
                    elif any(keyword in control_id.lower() for keyword in ['logging', 'monitoring', 'cloudtrail']):
                        severity = 'MEDIUM'
                    else:
                        severity = 'MEDIUM'
                elif mapped_status == 'ok':
                    severity = 'INFO'
                elif mapped_status == 'info':
                    severity = 'LOW'
                else:
                    severity = 'MEDIUM'
            
            # Extract category from control ID
            category = 'Security'
            if 'iam' in control_id.lower():
                category = 'Identity and Access Management'
            elif 's3' in control_id.lower():
                category = 'Storage'
            elif 'ec2' in control_id.lower():
                category = 'Compute'
            elif 'vpc' in control_id.lower():
                category = 'Network'
            
            finding = {
                'id': f"aws-{account_id}-{control_id}",
                'control_id': control_id,
                'control': title,
                'category': category,
                'severity': severity,
                'status': mapped_status,
                'reason': description or title,
                'details': description,
                'account_id': account_id,
                'resource_id': account_id,
                'cloud_provider': 'aws'
            }
            
            return finding
            
        except Exception as e:
            logger.warning(f"Error processing control: {str(e)}")
            return None
    
    async def _collect_config_data(self) -> Dict[str, Any]:
        """Collect AWS configuration data for RAG analysis"""
        if not self.steampipe_service:
            return {}
        
        aws_queries = {
            'iam_users': 'SELECT name, arn, create_date FROM aws_iam_user',
            'iam_roles': 'SELECT name, arn, create_date FROM aws_iam_role LIMIT 10',
            's3_buckets': 'SELECT name, region, creation_date FROM aws_s3_bucket',
            'ec2_instances': 'SELECT instance_id, instance_type, instance_state, region FROM aws_ec2_instance',
            'vpcs': 'SELECT vpc_id, cidr_block, is_default, region FROM aws_vpc',
            'security_groups': 'SELECT group_id, group_name, vpc_id, region FROM aws_vpc_security_group LIMIT 20'
        }
        
        return await self.steampipe_service.collect_config_data(aws_queries)


# ============================================================================
# Handler Functions for Provider Registry
# ============================================================================

async def scan_aws_account_handler(
    user_id: str,
    account_id: str,
    credentials: Dict[str, str],
    db_session,
    scan_record,
    **kwargs
) -> Dict[str, Any]:
    """
    Handler function for AWS account scanning - used by UnifiedCloudAPI
    
    Args:
        user_id: User identifier
        account_id: AWS account ID
        credentials: AWS credentials (can include role_arn for role assumption)
        db_session: SQLAlchemy session
        scan_record: CloudScan database record
        **kwargs: Additional parameters (cloudname, scan_id, etc.)
    
    Returns:
        Dict with scan results
    """
    try:
        logger.info(f"AWS scan handler called for {user_id}:{account_id}")
        
        # Create scanner instance
        async with AwsSecurityScanner(db_session, scan_record) as scanner:
            # Extract optional parameters
            scan_id = kwargs.get('scan_id')
            cloudname = kwargs.get('cloudname')
            
            # Run the scan using base class method
            results = await scanner.scan_account(
                user_id=user_id,
                account_id=account_id,
                credentials=credentials,
                scan_id=scan_id,
                cloudname=cloudname
            )
            
            return results
            
    except Exception as e:
        logger.error(f"AWS scan handler error: {str(e)}", exc_info=True)
        return {
            'success': False,
            'error': {
                'message': str(e),
                'code': 'AWS_SCAN_ERROR',
                'type': type(e).__name__
            }
        }


async def validate_aws_credentials(
    credentials: Dict[str, str] = None, 
    account_id: str = None,
    role_arn: str = None,
    external_id: str = None,
    session_name: str = None
) -> Dict[str, Any]:
    """
    Validate AWS credentials - wrapper for UnifiedCloudAPI
    
    Args:
        credentials: AWS credentials dict (optional if using role_arn)
        account_id: Optional expected account ID
        role_arn: Optional IAM role ARN for cross-account access
        external_id: Optional external ID for role assumption
        session_name: Optional session name for assumed role
    
    Returns:
        Dict with success status and validation results
    """
    validator = AwsCredentialValidator()
    
    # Default credentials to empty dict if not provided
    if credentials is None:
        credentials = {}
    
    # Check if role assumption is needed
    if role_arn:
        # Use app's own credentials for role assumption
        base_creds = {
            'aws_access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
            'aws_secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
            'aws_session_token': os.getenv('AWS_SESSION_TOKEN')
        }
        
        # If credentials were provided, use those instead of env vars
        if credentials.get('aws_access_key_id'):
            base_creds = credentials
        
        role_config = {
            'role_arn': role_arn,
            'external_id': external_id,
            'session_name': session_name or f'SecurityScan-{int(time.time())}'
        }
        
        result = await validator.validate_credentials_with_role(base_creds, account_id, role_config)
        
        # Convert to unified API format
        if result.get('valid'):
            return {
                'success': True,
                'data': {
                    'account_id': result.get('account_id'),
                    'caller_identity': result.get('caller_identity'),
                    'method': 'role_assumption'
                }
            }
        else:
            return {
                'success': False,
                'error': {
                    'message': 'Role assumption failed',
                    'code': 'INVALID_ROLE',
                    'details': ', '.join(result.get('errors', []))
                }
            }
    
    # Legacy path: check if role info is inside credentials dict
    elif 'role_arn' in credentials:
        base_creds = {
            'aws_access_key_id': credentials.get('aws_access_key_id'),
            'aws_secret_access_key': credentials.get('aws_secret_access_key'),
            'aws_session_token': credentials.get('aws_session_token')
        }
        
        role_config = {
            'role_arn': credentials['role_arn'],
            'external_id': credentials.get('external_id'),
            'session_name': credentials.get('session_name', f'SecurityScan-{int(time.time())}')
        }
        
        result = await validator.validate_credentials_with_role(base_creds, account_id, role_config)
        
        # Convert to unified API format
        if result.get('valid'):
            return {
                'success': True,
                'data': {
                    'account_id': result.get('account_id'),
                    'caller_identity': result.get('caller_identity'),
                    'method': 'role_assumption'
                }
            }
        else:
            return {
                'success': False,
                'error': {
                    'message': 'Role assumption failed',
                    'code': 'INVALID_ROLE',
                    'details': ', '.join(result.get('errors', []))
                }
            }
    
    # Direct credentials validation
    else:
        result = await validator.validate_credentials(credentials, account_id)
        
        # Convert to unified API format
        if result.get('valid'):
            return {
                'success': True,
                'data': {
                    'account_id': result.get('account_id'),
                    'caller_identity': result.get('caller_identity'),
                    'method': 'direct_credentials'
                }
            }
        else:
            return {
                'success': False,
                'error': {
                    'message': 'Invalid credentials',
                    'code': 'INVALID_CREDENTIALS',
                    'details': ', '.join(result.get('errors', []))
                }
            }