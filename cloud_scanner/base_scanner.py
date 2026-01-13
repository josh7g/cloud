"""
Base Cloud Scanner - Abstract base class for all cloud provider scanners
"""
import os
import json
import logging
import asyncio
import tempfile
import shutil
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from sqlalchemy.orm import Session
from models import CloudScan
from progress_tracking import (
    update_scan_progress, 
    clear_scan_progress, 
    start_new_scan, 
    generate_unique_scan_id,
    aggressively_clear_scan_data
)
from sqlalchemy import text

logger = logging.getLogger(__name__)


class BaseCloudScanner(ABC):
    """
    Abstract base class for all cloud provider security scanners.
    
    This class provides common functionality for:
    - Progress tracking
    - Database operations
    - Result processing
    - RAG analysis
    - Reranking
    - Error handling
    """
    
    def __init__(self, db_session: Optional[Session] = None, scan_record: Optional[CloudScan] = None):
        self.db_session = db_session
        self.scan_record = scan_record
        self.temp_dir = None
        self._user_id = None
        self._account_id = None
        self._scan_id = None
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'scan_durations': {}
        }
        self.credentials = {}
        self.provider_name = self.get_provider_name()
    
    @abstractmethod
    def get_provider_name(self) -> str:
        """Return the cloud provider name (e.g., 'aws', 'azure', 'gcp')"""
        pass
    
    @abstractmethod
    async def validate_credentials(self, credentials: Dict[str, str], account_id: str = None) -> Dict[str, Any]:
        """Validate cloud provider credentials"""
        pass
    
    @abstractmethod
    async def run_compliance_check(self, account_id: str) -> Dict[str, Any]:
        """Run compliance/security check for the cloud provider"""
        pass
    
    @abstractmethod
    async def setup(self):
        """Setup scanner resources and temporary directories"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Clean up temporary resources"""
        pass
    
    def set_scan_info(self, user_id: str, account_id: str, scan_id: str = None):
        """Set scan information for progress tracking"""
        self._user_id = user_id
        self._account_id = account_id
        self._scan_id = scan_id or generate_unique_scan_id()
        logger.info(f"{self.provider_name.upper()} Scanner scan info set: {user_id}:{account_id}, scan_id: {self._scan_id}")
    
    async def _ensure_progress_update(self, stage: str, progress: int, retries: int = 3):
        """Send a progress update with retries to ensure delivery."""
        if not all([self._user_id, self._account_id]):
            logger.warning("Cannot send progress update: user_id or account_id not set")
            return False
            
        if not self._scan_id:
            self._scan_id = generate_unique_scan_id()
        
        import random
        await asyncio.sleep(random.uniform(0.1, 0.3))
        
        success = False
        for attempt in range(retries):
            try:
                result = update_scan_progress(
                    self._user_id, 
                    self._account_id, 
                    stage, 
                    progress, 
                    scan_type=self.provider_name, 
                    scan_id=self._scan_id
                )
                if result:
                    success = True
                    if progress >= 95 or stage == 'completed' or stage == 'error':
                        await asyncio.sleep(0.5)
                    break
            except Exception as e:
                logger.error(f"Progress update attempt {attempt+1} failed for stage {stage}: {str(e)}")
                await asyncio.sleep(0.5 * (attempt + 1))
        
        if not success and (stage == 'completed' or stage == 'error'):
            logger.warning(f"Failed to send critical '{stage}' update after {retries} attempts")
        
        return success
    
    def sanitize_for_json(self, obj):
        """Recursively sanitize an object for JSON serialization"""
        if isinstance(obj, dict):
            return {k: self.sanitize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.sanitize_for_json(i) for i in obj]
        elif isinstance(obj, (datetime,)):
            return obj.isoformat()
        elif hasattr(obj, 'isoformat'):
            return obj.isoformat()
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)
    
    def _create_error_results(self, error_message: str, account_id: str, 
                             diagnostics: Optional[Dict] = None) -> Dict[str, Any]:
        """Create enhanced error results with diagnostics"""
        findings = [{
            'id': f"{self.provider_name}-{account_id}-error-1",
            'severity': 'INFO',
            'category': 'Diagnostics',
            'control': f'{self.provider_name.upper()} Scan Diagnostics',
            'status': 'Completed with errors',
            'reason': f'{self.provider_name.upper()} scan encountered issues',
            'details': f'Error details: {error_message}',
            'resource_id': account_id,
            'account_id': account_id,
            'remediation': f'Check {self.provider_name.upper()} credentials and permissions. See diagnostic information.'
        }]
        
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
                'cloud_provider': self.provider_name,
                'benchmark': f'{self.provider_name.upper()} Security Check',
                'scan_error': error_message,
                'scan_diagnostics': diagnostics or {}
            }
        }
    
    async def scan_account(
        self, 
        user_id: str, 
        account_id: str, 
        credentials: Dict[str, str], 
        scan_id: str = None,
        cloudname: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Main scan orchestration method - common flow for all cloud providers
        
        Args:
            user_id: User identifier
            account_id: Cloud account ID
            credentials: Provider-specific credentials
            scan_id: Optional scan ID
            cloudname: Optional cloud name for RAG analysis
            **kwargs: Provider-specific additional parameters
            
        Returns:
            Dict containing scan results
        """
        try:
            # Set scan information
            if not scan_id:
                scan_id = generate_unique_scan_id()
            
            self.set_scan_info(user_id, account_id, scan_id)
            logger.info(f"{self.provider_name.upper()} scan using scan ID: {scan_id}")
            
            # Clear previous scan data
            aggressively_clear_scan_data(user_id, account_id, self.provider_name)
            
            # Store credentials
            self.credentials = credentials
            
            # Send initial progress update
            await self._ensure_progress_update('initializing', 5)
            
            # Validate credentials
            await self._ensure_progress_update('validating_credentials', 10)
            validation_results = await self.validate_credentials(credentials, account_id)
            
            if not validation_results.get("valid", False):
                error_msg = f"Cannot connect to {self.provider_name.upper()}: Invalid credentials"
                logger.error(error_msg)
                
                if self.db_session and self.scan_record:
                    try:
                        self.scan_record.status = 'error'
                        self.scan_record.error = error_msg
                        self.scan_record.completed_at = datetime.now()
                        self.db_session.commit()
                    except Exception as db_e:
                        logger.error(f"Failed to store error record: {str(db_e)}")
                        self.db_session.rollback()
                
                await self._ensure_progress_update('error', 0)
                
                return {
                    'success': False,
                    'error': {
                        'message': error_msg,
                        'code': 'CREDENTIAL_ERROR',
                        'details': validation_results
                    }
                }
            
            logger.info(f"Validated credentials for account: {validation_results.get('account_id')}")
            await self._ensure_progress_update('validation_complete', 15)
            
            # Setup scanner
            await self._ensure_progress_update('configuring', 20)
            await self.setup()
            await self._ensure_progress_update('config_complete', 25)
            
            # Run compliance check
            await self._ensure_progress_update('running_benchmark', 30)
            await self._ensure_progress_update('preparing_scan', 35)
            await self._ensure_progress_update('scanning', 40)
            
            try:
                results = await self.run_compliance_check(account_id)
                await self._ensure_progress_update('scan_complete', 50)
            except Exception as check_e:
                logger.error(f"Compliance check error: {str(check_e)}")
                results = {}
                await self._ensure_progress_update('scan_error_recovery', 50)
            
            # Process results
            await self._ensure_progress_update('preparing_results', 65)
            await self._ensure_progress_update('processing', 70)
            
            findings_data = None
            
            if results:
                logger.info(f"Results structure check: type={type(results)}, keys={list(results.keys()) if isinstance(results, dict) else 'not dict'}")
                
                if isinstance(results, dict):
                    if 'findings' in results and results['findings']:
                        logger.info(f"Found direct findings in results: {len(results['findings'])} findings")
                        findings_data = results
                    elif 'groups' in results:
                        logger.info("Found groups structure, processing benchmark results")
                        await self._ensure_progress_update('processing_benchmark', 75)
                        findings_data = self._process_benchmark_results(results, account_id)
                        await self._ensure_progress_update('benchmark_processed', 80)
                        logger.info(f"✅ Using benchmark results: {len(findings_data.get('findings', []))} findings")
            
            # Fallback if no findings
            if not findings_data or not findings_data.get('findings'):
                logger.info("Creating fallback findings from validation data")
                findings_data = self._create_fallback_findings(validation_results, account_id)
                logger.info(f"✅ Using fallback results: {len(findings_data.get('findings', []))} findings")
            
            # Ensure we have at least one finding
            if not findings_data or not findings_data.get('findings') or len(findings_data.get('findings', [])) == 0:
                logger.warning("No findings were generated, adding default finding")
                findings_data = {
                    'findings': [{
                        'id': f"{self.provider_name}-{account_id}-default",
                        'severity': "INFO",
                        'category': "General", 
                        'control': f"{self.provider_name.upper()} Security Scan",
                        'control_id': "DEFAULT-1",
                        'status': "Info",
                        'reason': "No specific security findings detected",
                        'details': f"{self.provider_name.upper()} security scan completed but did not detect any specific issues",
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
            
            # Reranking phase
            await self._ensure_progress_update('collecting_config', 85)
            await self._ensure_progress_update('preparing_rerank', 88)
            await self._ensure_progress_update('reranking', 90)
            
            findings = findings_data.get('findings', [])
            reordered_findings = []
            
            if findings:
                rerank_url = os.getenv(f'{self.provider_name.upper()}_RERANK_URL')
                if rerank_url:
                    logger.info(f"Reranking {len(findings)} findings")
                    reordered_findings = await self._rerank_findings(findings, user_id, account_id)
                    logger.info(f"Reranking complete with {len(reordered_findings)} findings")
                else:
                    logger.info(f"Skipping reranking as {self.provider_name.upper()}_RERANK_URL is not set")
                    reordered_findings = findings.copy()
            
            await self._ensure_progress_update('rerank_complete', 92)
            
            # RAG analysis phase
            await self._ensure_progress_update('rag_analysis', 93)
            
            if cloudname and findings:
                logger.info(f"Running RAG analysis with cloudname: {cloudname}")
                config_data = await self._collect_config_data()
                rag_response = await self._rag_analysis(findings, user_id, cloudname, config_data)
                if rag_response:
                    logger.info(f"RAG analysis completed: {len(str(rag_response))} bytes response")
                    if 'metadata' not in findings_data:
                        findings_data['metadata'] = {}
                    findings_data['metadata']['rag_analysis'] = rag_response
                else:
                    logger.info("RAG analysis failed or returned empty response")
            
            await self._ensure_progress_update('rag_complete', 94)
            
            # Save results
            await self._ensure_progress_update('preparing_save', 95)
            sanitized_data = self.sanitize_for_json(findings_data)
            sanitized_rerank = self.sanitize_for_json(reordered_findings)
            
            await self._ensure_progress_update('saving', 96)
            if self.db_session and self.scan_record:
                try:
                    class DateTimeEncoder(json.JSONEncoder):
                        def default(self, obj):
                            if isinstance(obj, datetime):
                                return obj.isoformat()
                            return super(DateTimeEncoder, self).default(obj)
                    
                    serialized_json = json.dumps(sanitized_data, cls=DateTimeEncoder)
                    reordered_json = json.dumps(sanitized_rerank, cls=DateTimeEncoder)
                    
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
            
            logger.info(f"Successfully completed {self.provider_name.upper()} scan for {user_id}/{account_id}")
            
            return {
                'success': True,
                'data': sanitized_data
            }
        
        except Exception as e:
            logger.error(f"{self.provider_name.upper()} scan failed: {str(e)}", exc_info=True)
            
            if self.db_session and self.scan_record:
                try:
                    self.scan_record.status = 'error'
                    self.scan_record.error = str(e)
                    self.scan_record.completed_at = datetime.now()
                    self.db_session.commit()
                except Exception:
                    self.db_session.rollback()
            
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
        finally:
            await self.cleanup()
    
    def _process_benchmark_results(self, results: Dict, account_id: str) -> Dict[str, Any]:
        """Process benchmark results - override in subclasses if needed"""
        # Default implementation - subclasses should override
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'failed_findings': 0,
                'pass_findings': 0,
                'severity_counts': {},
                'category_counts': {}
            },
            'metadata': {
                'scan_time': datetime.now().isoformat(),
                'account_id': account_id
            }
        }
    
    def _create_fallback_findings(self, validation_results: Dict, account_id: str) -> Dict:
        """Create fallback findings based on validation results"""
        findings = []
        
        findings.append({
            'id': f"{self.provider_name}-{account_id}-authenticated",
            'severity': "INFO",
            'category': "Authentication",
            'control': f"{self.provider_name.upper()} API Access",
            'control_id': "AUTH-1",
            'status': "Pass",
            'reason': f"Successfully authenticated to {self.provider_name.upper()} API",
            'details': f"Authenticated as: {validation_results.get('caller_identity', {}).get('arn', 'Unknown')}",
            'resource_id': account_id,
            'account_id': account_id
        })
        
        stats = {
            'total_findings': len(findings),
            'failed_findings': 0,
            'warning_findings': 0,
            'pass_findings': len(findings),
            'severity_counts': {"INFO": len(findings), "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
            'category_counts': {"Authentication": len(findings)},
            'resource_counts': 1,
            'account_id': account_id
        }
        
        metadata = {
            'scan_time': datetime.now().isoformat(),
            'account_id': account_id,
            'cloud_provider': self.provider_name,
            'benchmark': f'{self.provider_name.upper()} API Access Check',
            'scan_type': 'api-validation',
            'scan_duration_seconds': (datetime.now() - self.scan_stats.get('start_time', datetime.now())).total_seconds() if self.scan_stats.get('start_time') else 0,
            'validation_results': self.sanitize_for_json(validation_results)
        }
        
        return {
            'findings': findings,
            'stats': stats,
            'metadata': metadata
        }
    
    async def _collect_config_data(self) -> Dict[str, Any]:
        """Collect configuration data - override in subclasses"""
        return {}
    
    async def _rag_analysis(
        self, 
        findings: List[Dict], 
        user_id: str, 
        cloudname: str,
        config_data: Optional[Dict] = None
    ) -> Dict:
        """Perform RAG analysis using common service"""
        from cloud_scanner.common_services import rag_cloud_analysis
        return await rag_cloud_analysis(
            findings=findings,
            user_id=user_id,
            cloudname=cloudname,
            provider_name=self.provider_name,
            config_data=config_data
        )
    
    async def _rerank_findings(
        self, 
        findings: List[Dict], 
        user_id: str, 
        account_id: str
    ) -> List[Dict]:
        """Rerank findings using common service"""
        from cloud_scanner.common_services import rerank_cloud_findings
        return await rerank_cloud_findings(
            findings=findings,
            user_id=user_id,
            account_id=account_id,
            provider_name=self.provider_name
        )
    
    async def __aenter__(self):
        """Context manager entry"""
        await self.setup()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.cleanup()

