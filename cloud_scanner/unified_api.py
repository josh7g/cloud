"""
Unified Cloud API - Single set of endpoints for all cloud providers
"""
import logging
from flask import Blueprint, request, jsonify
from typing import Dict, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text
from models import CloudScan, db
from db_utils import create_api_engine
from cloud_scanner.provider_registry import CloudProviderRegistry

logger = logging.getLogger(__name__)


class UnifiedCloudAPI:
    """
    Unified API for all cloud providers.
    All providers use the same endpoints with provider specified in request body or query params.
    """
    
    def __init__(self):
        self.blueprint = Blueprint('cloud', __name__, url_prefix='/cloud')
        self.registry = CloudProviderRegistry()
        self._register_routes()
    
    def _register_routes(self):
        """Register unified routes for all cloud providers"""
        
        @self.blueprint.route('/scan', methods=['POST'])
        def trigger_scan():
            """Trigger a cloud security scan - provider specified in request"""
            return self._handle_scan_request()
        
        @self.blueprint.route('/scans/<user_id>/list', methods=['GET'])
        def list_user_scans(user_id):
            """List all scans for a user - optionally filter by provider"""
            return self._handle_list_scans(user_id)
        
        @self.blueprint.route('/scans/<user_id>', methods=['GET'])
        def get_user_scans(user_id):
            """Get user scans with filtering"""
            return self._handle_get_user_scans(user_id)
        
        @self.blueprint.route('/scans/<scan_id>/result', methods=['GET'])
        def get_scan_result(scan_id):
            """Get scan result by scan ID"""
            return self._handle_get_scan_result(scan_id)
        
        @self.blueprint.route('/scans/<scan_id>', methods=['DELETE'])
        def delete_scan(scan_id):
            """Delete a scan"""
            return self._handle_delete_scan(scan_id)
        
        @self.blueprint.route('/scans/<user_id>/cloudname/<cloudname>/result', methods=['GET'])
        def get_scan_result_by_cloudname(user_id, cloudname):
            """Get scan result by user ID and cloudname"""
            return self._handle_get_scan_result_by_cloudname(user_id, cloudname)
        
        @self.blueprint.route('/scans/<user_id>/cloudname/<cloudname>/reranked', methods=['GET'])
        def get_reranked_findings_by_cloudname(user_id, cloudname):
            """Get reranked findings by user ID and cloudname"""
            return self._handle_get_reranked_by_cloudname(user_id, cloudname)
        
        @self.blueprint.route('/scans/<user_id>/cloudname/<cloudname>/worksheet/<int:worksheet_number>/reranked', methods=['GET'])
        def get_reranked_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number):
            """Get reranked findings by cloudname and worksheet"""
            return self._handle_get_reranked_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number)
        
        @self.blueprint.route('/scans/<user_id>/cloudname/<cloudname>/worksheets', methods=['GET'])
        def list_worksheets_for_cloudname(user_id, cloudname):
            """List worksheets for a cloudname"""
            return self._handle_list_worksheets(user_id, cloudname)
        
        @self.blueprint.route('/scans/<user_id>/cloudname/<cloudname>/worksheet/<int:worksheet_number>/result', methods=['GET'])
        def get_scan_result_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number):
            """Get scan result by cloudname and worksheet"""
            return self._handle_get_scan_result_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number)
        
        @self.blueprint.route('/security/summary/<user_id>', methods=['GET'])
        def get_security_summary(user_id):
            """Get security summary for a user - optionally filter by provider"""
            return self._handle_get_security_summary(user_id)
        
        @self.blueprint.route('/validate-credentials', methods=['POST'])
        def validate_credentials():
            """Validate cloud provider credentials - provider specified in request"""
            return self._handle_validate_credentials()
        
        @self.blueprint.route('/providers', methods=['GET'])
        def list_providers():
            """List all available cloud providers"""
            return jsonify({
                'providers': self.registry.list_providers()
            }), 200
    
    def _get_provider_from_request(self) -> Optional[str]:
        """Extract provider name from request (body or query param)"""
        if request.is_json:
            data = request.get_json() or {}
            provider = data.get('provider') or data.get('cloud_provider')
            if provider:
                return provider.lower()
        
        provider = request.args.get('provider') or request.args.get('cloud_provider')
        if provider:
            return provider.lower()
        
        return None
    
    def _handle_scan_request(self):
        """Handle scan request - provider specified in request body"""
        try:
            data = request.get_json() or {}
            provider = self._get_provider_from_request()
            
            if not provider:
                return jsonify({
                    'error': 'Missing required field: provider or cloud_provider'
                }), 400
            
            if not self.registry.is_provider_registered(provider):
                return jsonify({
                    'error': f'Provider {provider} is not registered'
                }), 400
            
            user_id = data.get('user_id')
            account_id = data.get('account_id')
            credentials = data.get('credentials', {})
            cloudname = data.get('cloudname')
            worksheet_number = data.get('worksheet_number', 1)
            
            if not all([user_id, account_id, credentials]):
                return jsonify({
                    'error': 'Missing required fields: user_id, account_id, credentials'
                }), 400
            
            # Get provider-specific handler
            handler = self.registry.get_scan_handler(provider)
            if not handler:
                return jsonify({
                    'error': f'No scan handler registered for {provider}'
                }), 500
            
            # Create scan record
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                scan_record = CloudScan(
                    user_id=user_id,
                    cloud_provider=provider,
                    account_id=account_id,
                    cloudname=cloudname,
                    worksheet_number=worksheet_number,
                    status='queued'
                )
                session.add(scan_record)
                session.commit()
                
                # Run scan in background
                import threading
                scan_thread = threading.Thread(
                    target=lambda: handler(
                        user_id=user_id,
                        account_id=account_id,
                        credentials=credentials,
                        db_session=session,
                        scan_record=scan_record,
                        cloudname=cloudname,
                        **data.get('provider_specific', {})
                    ),
                    daemon=True
                )
                scan_thread.start()
                
                return jsonify({
                    'success': True,
                    'scan_id': scan_record.id,
                    'provider': provider,
                    'message': f'{provider.upper()} scan started'
                }), 202
                
            except Exception as e:
                session.rollback()
                logger.error(f"Error creating scan record: {str(e)}")
                return jsonify({
                    'error': f'Failed to start scan: {str(e)}'
                }), 500
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error in scan request: {str(e)}")
            return jsonify({
                'error': f'Internal server error: {str(e)}'
            }), 500
    
    def _handle_list_scans(self, user_id: str):
        """List all scans for a user - optionally filter by provider"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.user_id == user_id)
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scans = query.order_by(CloudScan.created_at.desc()).all()
                
                return jsonify({
                    'scans': [scan.to_dict() for scan in scans],
                    'provider': provider or 'all'
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error listing scans: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_user_scans(self, user_id: str):
        """Get user scans with filtering"""
        try:
            provider = self._get_provider_from_request()
            status = request.args.get('status')
            limit = request.args.get('limit', type=int, default=10)
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.user_id == user_id)
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                if status:
                    query = query.filter(CloudScan.status == status)
                
                scans = query.order_by(CloudScan.created_at.desc()).limit(limit).all()
                
                return jsonify({
                    'scans': [scan.to_dict() for scan in scans],
                    'count': len(scans),
                    'provider': provider or 'all'
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting user scans: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_scan_result(self, scan_id: int):
        """Get scan result by scan ID"""
        try:
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                scan = session.query(CloudScan).filter(CloudScan.id == scan_id).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                return jsonify(scan.to_dict()), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting scan result: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_delete_scan(self, scan_id: int):
        """Delete a scan"""
        try:
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                scan = session.query(CloudScan).filter(CloudScan.id == scan_id).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                session.delete(scan)
                session.commit()
                
                return jsonify({'success': True, 'message': 'Scan deleted'}), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error deleting scan: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_scan_result_by_cloudname(self, user_id: str, cloudname: str):
        """Get scan result by cloudname"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname
                )
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scan = query.order_by(CloudScan.created_at.desc()).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                return jsonify(scan.to_dict()), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting scan result by cloudname: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_reranked_by_cloudname(self, user_id: str, cloudname: str):
        """Get reranked findings by cloudname"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname
                )
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scan = query.order_by(CloudScan.created_at.desc()).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                if not scan.rerank:
                    return jsonify({'error': 'Reranked findings not available'}), 404
                
                return jsonify({
                    'reranked_findings': scan.rerank,
                    'scan_id': scan.id,
                    'provider': scan.cloud_provider
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting reranked findings: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_reranked_by_cloudname_and_worksheet(
        self, 
        user_id: str, 
        cloudname: str, 
        worksheet_number: int
    ):
        """Get reranked findings by cloudname and worksheet"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname,
                    CloudScan.worksheet_number == worksheet_number
                )
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scan = query.order_by(CloudScan.created_at.desc()).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                if not scan.rerank:
                    return jsonify({'error': 'Reranked findings not available'}), 404
                
                return jsonify({
                    'reranked_findings': scan.rerank,
                    'scan_id': scan.id,
                    'worksheet_number': worksheet_number,
                    'provider': scan.cloud_provider
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting reranked findings: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_list_worksheets(self, user_id: str, cloudname: str):
        """List worksheets for a cloudname"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan.worksheet_number).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname
                )
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scans = query.distinct().all()
                worksheets = [scan[0] for scan in scans]
                
                return jsonify({
                    'worksheets': sorted(worksheets),
                    'count': len(worksheets),
                    'provider': provider or 'all'
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error listing worksheets: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_scan_result_by_cloudname_and_worksheet(
        self, 
        user_id: str, 
        cloudname: str, 
        worksheet_number: int
    ):
        """Get scan result by cloudname and worksheet"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname,
                    CloudScan.worksheet_number == worksheet_number
                )
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scan = query.order_by(CloudScan.created_at.desc()).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                return jsonify(scan.to_dict()), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting scan result: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_security_summary(self, user_id: str):
        """Get security summary for a user - optionally filter by provider"""
        try:
            provider = self._get_provider_from_request()
            
            engine = create_api_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.status == 'completed'
                )
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scans = query.all()
                
                total_scans = len(scans)
                total_findings = 0
                severity_counts = {}
                provider_counts = {}
                
                for scan in scans:
                    if scan.findings and isinstance(scan.findings, dict):
                        stats = scan.findings.get('stats', {})
                        total_findings += stats.get('total_findings', 0)
                        sev_counts = stats.get('severity_counts', {})
                        for sev, count in sev_counts.items():
                            severity_counts[sev] = severity_counts.get(sev, 0) + count
                    
                    # Count by provider
                    prov = scan.cloud_provider
                    provider_counts[prov] = provider_counts.get(prov, 0) + 1
                
                return jsonify({
                    'total_scans': total_scans,
                    'total_findings': total_findings,
                    'severity_counts': severity_counts,
                    'provider_counts': provider_counts,
                    'filtered_provider': provider or 'all'
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting security summary: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_validate_credentials(self):
        """Validate credentials - provider specified in request"""
        try:
            data = request.get_json() or {}
            provider = self._get_provider_from_request()
            
            if not provider:
                return jsonify({
                    'error': 'Missing required field: provider or cloud_provider'
                }), 400
            
            if not self.registry.is_provider_registered(provider):
                return jsonify({
                    'error': f'Provider {provider} is not registered'
                }), 400
            
            validator = self.registry.get_validator(provider)
            if not validator:
                return jsonify({
                    'error': f'Credential validation not implemented for {provider}'
                }), 501
            
            credentials = data.get('credentials', {})
            account_id = data.get('account_id')
            
            if not credentials:
                return jsonify({'error': 'Missing credentials'}), 400
            
            import asyncio
            result = asyncio.run(validator(credentials, account_id))
            
            return jsonify(result), 200
            
        except Exception as e:
            logger.error(f"Error validating credentials: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def get_blueprint(self):
        """Get the Flask blueprint"""
        return self.blueprint

