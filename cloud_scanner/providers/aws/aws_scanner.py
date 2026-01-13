"""
AWS Security Scanner - Reimplemented using base classes and common Steampipe service
"""
import os
import json
import logging
import asyncio
import boto3
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session
from models import CloudScan
from botocore.exceptions import ClientError
from datetime import datetime, timedelta
import time

from cloud_scanner.base_scanner import BaseCloudScanner
from cloud_scanner.steampipe_service import SteampipeService, STEAMPIPE_CONFIGS

logger = logging.getLogger(__name__)


class AwsCredentialValidator:
    """Validates AWS credentials"""
    
    @staticmethod
    async def validate_credentials(credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """Validate AWS credentials"""
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
        
        original_env = {
            'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID'),
            'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'AWS_SESSION_TOKEN': os.environ.get('AWS_SESSION_TOKEN')
        }
        
        try:
            os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
            os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
            if 'aws_session_token' in credentials:
                os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token') or ''
            
            if not os.environ.get('AWS_ACCESS_KEY_ID') or not os.environ.get('AWS_SECRET_ACCESS_KEY'):
                results["errors"].append("Missing required AWS credentials")
                return results
            
            session = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            
            try:
                sts_client = session.client('sts')
                identity = sts_client.get_caller_identity()
                
                if account_id:
                    aws_account_id = identity.get("Account")
                    if str(aws_account_id).strip() != str(account_id).strip():
                        error_message = f"Account ID mismatch. Credentials are for account {aws_account_id}, but expected {account_id}"
                        logger.error(error_message)
                        results["errors"].append(error_message)
                        return results
                
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
                return results
            
            # Test service access
            service_tests = {
                'ec2': {'method': lambda client: client.describe_instances(MaxResults=5), 'region': 'us-east-1'},
                's3': {'method': lambda client: client.list_buckets(), 'region': None},
                'iam': {'method': lambda client: client.list_users(MaxItems=5), 'region': None},
            }
            
            for service_name, test_info in service_tests.items():
                try:
                    if test_info['region']:
                        client = session.client(service_name, region_name=test_info['region'])
                    else:
                        client = session.client(service_name)
                    
                    test_info['method'](client)
                    results["services_accessible"][service_name] = True
                except ClientError as e:
                    results["services_accessible"][service_name] = False
                    logger.warning(f"Could not access {service_name}: {str(e)}")
            
            return results
            
        except Exception as e:
            logger.error(f"Unexpected error during credential validation: {str(e)}")
            results["errors"].append(str(e))
            return results
        finally:
            for key, value in original_env.items():
                if value is not None:
                    os.environ[key] = value
                elif key in os.environ:
                    del os.environ[key]


class AwsAssumedRoleCredentials:
    """Handles AWS assumed role credentials"""
    
    def __init__(self, role_arn: str, session_name: str = None, 
                 external_id: str = None, base_credentials: Dict[str, str] = None):
        self.role_arn = role_arn
        self.session_name = session_name or f"SecurityScan-{int(time.time())}"
        self.external_id = external_id
        self.base_credentials = base_credentials or {}
        self.assumed_credentials = None
        self.credentials_expiry = None
    
    async def get_credentials(self) -> Dict[str, str]:
        """Get valid assumed role credentials"""
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
            if self.base_credentials:
                session = boto3.Session(
                    aws_access_key_id=self.base_credentials.get('aws_access_key_id'),
                    aws_secret_access_key=self.base_credentials.get('aws_secret_access_key'),
                    aws_session_token=self.base_credentials.get('aws_session_token')
                )
            else:
                session = boto3.Session()
            
            sts_client = session.client('sts')
            assume_role_params = {
                'RoleArn': self.role_arn,
                'RoleSessionName': self.session_name,
                'DurationSeconds': 3600
            }
            
            if self.external_id:
                assume_role_params['ExternalId'] = self.external_id
            
            response = sts_client.assume_role(**assume_role_params)
            credentials = response['Credentials']
            
            self.assumed_credentials = {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken']
            }
            
            self.credentials_expiry = credentials['Expiration'] - timedelta(minutes=5)
            logger.info(f"Successfully assumed role. Credentials expire at: {self.credentials_expiry}")
            
        except Exception as e:
            logger.error(f"Failed to assume role {self.role_arn}: {str(e)}")
            raise


class AwsSecurityScanner(BaseCloudScanner):
    """
    AWS Security Scanner - using BaseCloudScanner and common Steampipe service
    """
    
    def __init__(self, db_session: Optional[Session] = None, scan_record: Optional[CloudScan] = None):
        super().__init__(db_session, scan_record)
        self.steampipe_service = None
        self.role_config = {}
        self.assumed_role_handler = None
    
    def get_provider_name(self) -> str:
        """Return the cloud provider name"""
        return 'aws'
    
    def set_role_config(self, role_config: Dict[str, str]):
        """Set assumed role configuration"""
        self.role_config = role_config
        if role_config and role_config.get('role_arn'):
            logger.info(f"Configured to use assumed role: {role_config['role_arn']}")
    
    async def validate_credentials(self, credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """Validate AWS credentials"""
        validator = AwsCredentialValidator()
        
        if self.role_config and self.role_config.get('role_arn'):
            # Handle role assumption
            try:
                role_handler = AwsAssumedRoleCredentials(
                    role_arn=self.role_config['role_arn'],
                    session_name=self.role_config.get('session_name'),
                    external_id=self.role_config.get('external_id'),
                    base_credentials=credentials
                )
                assumed_creds = await role_handler.get_credentials()
                return await validator.validate_credentials(assumed_creds, account_id)
            except Exception as e:
                return {
                    "valid": False,
                    "errors": [f"Failed to assume role: {str(e)}"]
                }
        else:
            return await validator.validate_credentials(credentials, account_id)
    
    async def setup(self):
        """Setup AWS scanner resources"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='aws_scanner_'))
            workspace_dir = self.temp_dir / 'workspace'
            workspace_dir.mkdir(exist_ok=True)
            
            # Initialize Steampipe service
            self.steampipe_service = SteampipeService('aws', workspace_dir)
            
            # Initialize Steampipe
            await self.steampipe_service.initialize_service()
            
            # Install AWS plugin
            config = STEAMPIPE_CONFIGS['aws']
            await self.steampipe_service.install_plugin(config['plugin_name'], config['plugin_version'])
            
            # Configure AWS credentials in Steampipe
            await self._configure_steampipe_credentials()
            
            # Initialize mod
            await self.steampipe_service.initialize_mod()
            
            # Install compliance mod
            await self.steampipe_service.install_compliance_mod(config['compliance_mod'])
            
            self.scan_stats['start_time'] = datetime.now()
            logger.info("AWS scanner setup completed")
            
        except Exception as e:
            logger.error(f"AWS scanner setup failed: {str(e)}")
            raise
    
    async def _configure_steampipe_credentials(self):
        """Configure AWS credentials in Steampipe config"""
        try:
            steampipe_config_dir = os.path.expanduser('~/.steampipe/config')
            os.makedirs(steampipe_config_dir, exist_ok=True)
            
            access_key = self.credentials.get('aws_access_key_id', '').strip()
            secret_key = self.credentials.get('aws_secret_access_key', '').strip()
            session_token = self.credentials.get('aws_session_token', '').strip()
            
            aws_config_path = os.path.join(steampipe_config_dir, 'aws.spc')
            with open(aws_config_path, 'w') as f:
                f.write(f"""
connection "aws" {{
    plugin = "aws"
    aws_access_key_id     = "{access_key}"
    aws_secret_access_key = "{secret_key}"
    regions = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"]
    default_region = "us-east-1"
    max_error_retry_attempts = 10
    min_error_retry_delay = 50
""")
                if session_token:
                    f.write(f'    aws_session_token = "{session_token}"\n')
                f.write("}\n")
            
            os.chmod(aws_config_path, 0o600)
            
            # Restart Steampipe service
            try:
                await self.steampipe_service._run_command(['steampipe', 'service', 'stop'], timeout=30)
                await asyncio.sleep(2)
                await self.steampipe_service._run_command(['steampipe', 'service', 'start'], timeout=30)
                await asyncio.sleep(3)
            except Exception as e:
                logger.warning(f"Failed to restart Steampipe service: {str(e)}")
            
        except Exception as e:
            logger.error(f"Failed to configure Steampipe credentials: {str(e)}")
            raise
    
    async def cleanup(self):
        """Clean up AWS scanner resources"""
        try:
            if self.temp_dir and self.temp_dir.exists():
                import shutil
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
            
            self.scan_stats['end_time'] = datetime.now()
        except Exception as e:
            logger.error(f"Cleanup error: {str(e)}")
    
    async def run_compliance_check(self, account_id: str) -> Dict[str, Any]:
        """Run AWS compliance check using Steampipe/Powerpipe"""
        try:
            config = STEAMPIPE_CONFIGS['aws']
            
            # Collect configuration data
            logger.info("Collecting AWS configuration data...")
            config_queries = self._get_aws_config_queries()
            config_data = await self.steampipe_service.collect_config_data(config_queries)
            
            # Run benchmark
            benchmark_results = None
            try:
                benchmark_name = config['default_benchmark']
                benchmark_results = await self.steampipe_service.run_benchmark(benchmark_name, timeout=300)
            except Exception as benchmark_e:
                logger.error(f"Error running benchmark: {str(benchmark_e)}")
            
            # Process results
            if benchmark_results:
                logger.info("Processing benchmark results with config data")
                processed_results = self._process_benchmark_results(benchmark_results, account_id)
                
                if 'metadata' not in processed_results:
                    processed_results['metadata'] = {}
                processed_results['metadata']['aws_config'] = config_data
                
                return processed_results
            
            # Fallback to basic findings if benchmark fails
            logger.info("Using fallback findings")
            return self._create_fallback_findings_from_config(config_data, account_id)
            
        except Exception as e:
            logger.error(f"AWS compliance check failed: {str(e)}")
            raise
    
    def _get_aws_config_queries(self) -> Dict[str, str]:
        """Get AWS-specific Steampipe queries for config data collection"""
        return {
            'account_info': "SELECT account_id, partition FROM aws_account;",
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
            'regions': """
                SELECT region, opt_in_status FROM aws_region 
                WHERE opt_in_status IN ('opt-in-not-required', 'opted-in') LIMIT 10;
            """,
            'vpc_info': """
                SELECT vpc_id, cidr_block, is_default, state 
                FROM aws_vpc LIMIT 5;
            """,
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
    
    def _process_benchmark_results(self, results: Dict, account_id: str) -> Dict[str, Any]:
        """Process Powerpipe benchmark results"""
        try:
            findings = []
            self._extract_findings_from_benchmark(results, findings, account_id, "", None)
            
            logger.info(f"Extracted {len(findings)} findings from benchmark results")
            
            status_counts = {}
            for finding in findings:
                status = finding.get('status', 'unknown')
                status_counts[status] = status_counts.get(status, 0) + 1
            
            category_counts = {}
            for finding in findings:
                category = finding.get('category', 'Unknown')
                category_counts[category] = category_counts.get(category, 0) + 1
            
            final_stats = {
                'total_findings': len(findings),
                'failed_findings': status_counts.get('alarm', 0),
                'pass_findings': status_counts.get('ok', 0),
                'info_findings': status_counts.get('info', 0),
                'skip_findings': status_counts.get('skip', 0),
                'error_findings': status_counts.get('error', 0),
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
            
            return {
                'findings': findings,
                'stats': final_stats,
                'metadata': {
                    'benchmark': 'AWS CIS Foundations Benchmark',
                    'version': results.get('title', 'v4.0.0'),
                    'scan_time': datetime.now().isoformat(),
                    'account_id': account_id
                }
            }
        except Exception as e:
            logger.error(f"Error processing benchmark results: {str(e)}")
            raise
    
    def _extract_findings_from_benchmark(self, data, findings, account_id, path="", category_path=None):
        """Extract findings from benchmark results recursively"""
        if isinstance(data, dict):
            if 'title' in data and 'group_id' in data:
                new_category = data.get('title')
                if new_category and ('CIS' in new_category or new_category in ["Identity and Access Management", "Storage", "Networking"]):
                    category_path = new_category
            
            if 'control_id' in data and 'title' in data:
                control_id = data.get('control_id')
                title = data.get('title')
                category = category_path or "General"
                severity = self._map_severity(data.get('severity', 'medium'))
                description = data.get('description', '')
                
                results = data.get('results', [])
                if not results:
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
                            'status': status,
                            'reason': description,
                            'details': reason,
                            'resource_id': resource,
                            'account_id': account_id,
                            'cis_control': control_id
                        })
            
            for key, value in data.items():
                if key == 'results':
                    continue
                new_path = f"{path}.{key}" if path else key
                self._extract_findings_from_benchmark(value, findings, account_id, new_path, category_path)
        elif isinstance(data, list):
            for item in data:
                self._extract_findings_from_benchmark(item, findings, account_id, path, category_path)
    
    def _map_severity(self, severity: str) -> str:
        """Map Steampipe severity to our format"""
        severity = severity.lower()
        if severity in ['critical', 'high']:
            return 'HIGH'
        elif severity in ['medium']:
            return 'MEDIUM'
        elif severity in ['low']:
            return 'LOW'
        else:
            return 'INFO'
    
    def _create_fallback_findings_from_config(self, config_data: Dict, account_id: str) -> Dict[str, Any]:
        """Create findings from config data if benchmark fails"""
        findings = []
        
        # Add findings based on config data
        if config_data.get('password_policy'):
            policy = config_data['password_policy'][0] if config_data['password_policy'] else {}
            min_length = policy.get('minimum_password_length', 0)
            findings.append({
                'id': 'iam_password_policy_length',
                'severity': 'MEDIUM',
                'category': 'IAM',
                'control': 'IAM Password Minimum Length',
                'control_id': '1.8',
                'status': 'ok' if min_length >= 14 else 'alarm',
                'reason': f'Password minimum length is {min_length} (should be ≥14)',
                'resource_id': account_id,
                'account_id': account_id
            })
        
        stats = {
            'total_findings': len(findings),
            'failed_findings': sum(1 for f in findings if f.get('status') == 'alarm'),
            'pass_findings': sum(1 for f in findings if f.get('status') == 'ok'),
            'severity_counts': {'MEDIUM': len(findings)},
            'category_counts': {'IAM': len(findings)},
            'account_id': account_id
        }
        
        return {
            'findings': findings,
            'stats': stats,
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'account_id': account_id,
                'source': 'config_data'
            }
        }
    
    async def _collect_config_data(self) -> Dict[str, Any]:
        """Collect AWS configuration data"""
        if not self.steampipe_service:
            return {}
        
        config_queries = self._get_aws_config_queries()
        return await self.steampipe_service.collect_config_data(config_queries)
    
    async def scan_account(
        self, 
        user_id: str, 
        account_id: str, 
        credentials: Dict[str, str], 
        scan_id: str = None,
        cloudname: Optional[str] = None,
        role_config: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Override to handle AWS-specific role_config"""
        if role_config:
            self.set_role_config(role_config)
        
        # Set credentials in environment
        os.environ['AWS_ACCESS_KEY_ID'] = credentials.get('aws_access_key_id', '').strip()
        os.environ['AWS_SECRET_ACCESS_KEY'] = credentials.get('aws_secret_access_key', '').strip()
        if 'aws_session_token' in credentials:
            os.environ['AWS_SESSION_TOKEN'] = credentials.get('aws_session_token') or ''
        
        self.credentials = credentials
        
        return await super().scan_account(
            user_id=user_id,
            account_id=account_id,
            credentials=credentials,
            scan_id=scan_id,
            cloudname=cloudname,
            **kwargs
        )

