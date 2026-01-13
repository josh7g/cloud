"""
AWS API - Registers AWS provider with unified API
"""
import logging
from typing import Dict, Optional
from sqlalchemy.orm import Session
from models import CloudScan
from cloud_scanner.providers.aws.aws_scanner import (
    AwsSecurityScanner,
    AwsCredentialValidator
)
from cloud_scanner.provider_registry import register_provider

logger = logging.getLogger(__name__)


async def scan_aws_account_handler(
    user_id: str,
    account_id: str,
    credentials: Dict[str, str],
    db_session: Optional[Session] = None,
    scan_record: Optional[CloudScan] = None,
    role_config: Optional[Dict[str, str]] = None,
    cloudname: Optional[str] = None,
    **kwargs
) -> Dict:
    """
    AWS scan handler - registered with provider registry
    """
    try:
        async with AwsSecurityScanner(db_session, scan_record) as scanner:
            scanner.set_scan_info(user_id, account_id, scan_record.id if scan_record else None)
            
            if role_config:
                scanner.set_role_config(role_config)
            
            results = await scanner.scan_account(
                user_id=user_id,
                account_id=account_id,
                credentials=credentials,
                scan_id=scan_record.id if scan_record else None,
                cloudname=cloudname,
                role_config=role_config,
                **kwargs
            )
            
            return results
            
    except Exception as e:
        logger.error(f"AWS scan handler error: {str(e)}")
        return {
            'success': False,
            'error': {
                'message': str(e),
                'code': 'SCAN_ERROR'
            }
        }


async def validate_aws_credentials(credentials: Dict, account_id: str = None):
    """Validate AWS credentials"""
    validator = AwsCredentialValidator()
    return await validator.validate_credentials(credentials, account_id)


def register_aws_provider():
    """Register AWS provider with the registry"""
    register_provider(
        provider_name='aws',
        scan_handler=scan_aws_account_handler,
        validator=validate_aws_credentials,
        scanner_class=AwsSecurityScanner,
        api_blueprint=None  # Using unified API
    )
    
    logger.info("AWS provider registered successfully")

