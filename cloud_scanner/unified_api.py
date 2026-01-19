"""
Unified Cloud API - Single set of endpoints for all cloud providers
"""
import logging
import traceback
from flask import Blueprint, request, jsonify, make_response
from typing import Dict, Optional
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import text
from models import CloudScan, db
from db_utils import create_db_engine
from cloud_scanner.provider_registry import CloudProviderRegistry

logger = logging.getLogger(__name__)


class UnifiedCloudAPI:
    """
    Unified API for all cloud providers.
    All providers use the same endpoints with provider specified in request body or query params.
    """
    
    def __init__(self):
        # Define blueprint without prefix; app.py will mount it at /api/v1/cloud
        self.blueprint = Blueprint('cloud', __name__)
        self.registry = CloudProviderRegistry()
        self._register_cors_handler()
        self._register_routes()
    
    def _register_cors_handler(self):
        """Register CORS handler for all routes on this blueprint"""

        @self.blueprint.before_request
        def handle_preflight():
            """Handle OPTIONS preflight requests at the blueprint level"""
            if request.method == 'OPTIONS':
                response = make_response('', 200)
                response.headers['Access-Control-Allow-Origin'] = '*'
                response.headers['Access-Control-Allow-Headers'] = (
                    'Content-Type,Authorization,X-Requested-With,'
                    'workspace-id,organization-id,accesstoken,accessToken'
                )
                response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
                response.headers['Access-Control-Max-Age'] = '3600'
                response.headers['Access-Control-Allow-Credentials'] = 'false'
                return response

        @self.blueprint.after_request
        def after_request(response):
            """Add CORS headers to all responses for this blueprint"""
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Headers'] = (
                'Content-Type,Authorization,X-Requested-With,'
                'workspace-id,organization-id,accesstoken,accessToken'
            )
            response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PUT,DELETE,OPTIONS'
            response.headers['Access-Control-Max-Age'] = '3600'
            response.headers['Access-Control-Allow-Credentials'] = 'false'
            return response
    
    def _register_routes(self):
        """Register unified routes for all cloud providers"""
        
        @self.blueprint.route('/scan', methods=['POST'])
        def trigger_scan():
            """Trigger a cloud security scan - provider specified in request"""
            return self._handle_scan_request()
        
        # Register more specific routes first (with int converters) before general routes
        # These must come before /scans/<user_id> routes to avoid conflicts
        # IMPORTANT: Routes with path segments (like /result, /reranked) must come before
        # routes without path segments to ensure proper matching
        @self.blueprint.route('/scans/<int:scan_id>/result', methods=['GET'])
        def get_scan_result(scan_id):
            """Get scan result by scan ID"""
            return self._handle_get_scan_result(scan_id)
        
        @self.blueprint.route('/scans/<int:scan_id>/reranked', methods=['GET'])
        def get_reranked_by_scan_id(scan_id):
            """Get reranked findings by scan ID"""
            return self._handle_get_reranked_by_scan_id(scan_id)
        
        @self.blueprint.route('/scans/<int:scan_id>', methods=['DELETE'])
        def delete_scan(scan_id):
            """Delete a scan"""
            return self._handle_delete_scan(scan_id)
        
        # Register user-based routes after scan_id routes to avoid conflicts
        # Use string converter explicitly to ensure these don't match integers
        # IMPORTANT: Routes with /list must come before routes without path segments
        @self.blueprint.route('/scans/<string:user_id>/list', methods=['GET'])
        def list_user_scans(user_id):
            """List all scans for a user - optionally filter by provider"""
            return self._handle_list_scans(user_id)
        
        # This route must come last among /scans routes to avoid matching /scans/125/reranked
        # as /scans/<string:user_id> where user_id = "125/reranked"
        @self.blueprint.route('/scans/<string:user_id>', methods=['GET'])
        def get_user_scans(user_id):
            """Get user scans with filtering"""
            return self._handle_get_user_scans(user_id)
        
        @self.blueprint.route('/scans/<string:user_id>/cloudname/<cloudname>/result', methods=['GET'])
        def get_scan_result_by_cloudname(user_id, cloudname):
            """Get scan result by user ID and cloudname"""
            return self._handle_get_scan_result_by_cloudname(user_id, cloudname)
        
        @self.blueprint.route('/scans/<string:user_id>/cloudname/<cloudname>/reranked', methods=['GET'])
        def get_reranked_findings_by_cloudname(user_id, cloudname):
            """Get reranked findings by user ID and cloudname"""
            return self._handle_get_reranked_by_cloudname(user_id, cloudname)
        
        @self.blueprint.route('/scans/<string:user_id>/cloudname/<cloudname>/worksheet/<int:worksheet_number>/reranked', methods=['GET'])
        def get_reranked_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number):
            """Get reranked findings by cloudname and worksheet"""
            return self._handle_get_reranked_by_cloudname_and_worksheet(user_id, cloudname, worksheet_number)
        
        @self.blueprint.route('/scans/<string:user_id>/cloudname/<cloudname>/worksheets', methods=['GET'])
        def list_worksheets_for_cloudname(user_id, cloudname):
            """List worksheets for a cloudname"""
            return self._handle_list_worksheets(user_id, cloudname)
        
        @self.blueprint.route('/scans/<string:user_id>/cloudname/<cloudname>/worksheet/<int:worksheet_number>/result', methods=['GET'])
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
    
    def _get_workspace_id_from_request(self) -> Optional[str]:
        """Extract workspace_id from request headers or body"""
        # First check headers (preferred method)
        workspace_id = request.headers.get('workspace-id') or request.headers.get('workspace_id')
        if workspace_id:
            logger.debug(f"Extracted workspace_id from headers: {workspace_id}")
            return workspace_id.strip()
        
        # Fallback to request body (for POST requests)
        if request.is_json:
            data = request.get_json() or {}
            workspace_id = data.get('workspace_id')
            if workspace_id:
                logger.debug(f"Extracted workspace_id from request body: {workspace_id}")
                return str(workspace_id).strip()
        
        # Fallback to query params (for GET requests)
        workspace_id = request.args.get('workspace_id')
        if workspace_id:
            logger.debug(f"Extracted workspace_id from query params: {workspace_id}")
            return str(workspace_id).strip()
        
        logger.debug("No workspace_id found in request")
        return None
    
    def _handle_scan_request(self):
        """Handle cloud scan request - delegates to provider-specific handler"""
        try:
            data = request.get_json() or {}
            provider = self._get_provider_from_request()
            
            if not provider:
                return jsonify({
                    'error': 'Missing required field: provider or cloud_provider'
                }), 400
            
            # Check if provider is registered
            if not self.registry.is_provider_registered(provider):
                return jsonify({
                    'error': f'Provider {provider} is not registered',
                    'available_providers': self.registry.list_providers()
                }), 400
            
            # Get the scan handler for this provider
            scan_handler = self.registry.get_scan_handler(provider)
            if not scan_handler:
                return jsonify({
                    'error': f'Scan handler not found for provider {provider}'
                }), 500
            
            # Extract workspace_id from request
            workspace_id = self._get_workspace_id_from_request()
            if workspace_id:
                data['workspace_id'] = workspace_id
                logger.info(f"Including workspace_id in scan request: {workspace_id}")
            
            # Call the provider-specific scan handler
            import asyncio
            result = asyncio.run(scan_handler(data))
            
            return jsonify(result), 200
            
        except Exception as e:
            logger.error(f"Error handling scan request: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_scan_result(self, scan_id: int):
        """Get scan result by scan ID"""
        try:
            engine = create_db_engine()
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
    
    def _handle_get_reranked_by_scan_id(self, scan_id: int):
        """Get reranked findings by scan ID"""
        try:
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                scan = session.query(CloudScan).filter(CloudScan.id == scan_id).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                if not scan.rerank:
                    return jsonify({'error': 'No reranked findings available'}), 404
                
                return jsonify({
                    'scan_id': scan.id,
                    'reranked_findings': scan.rerank
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting reranked findings: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_delete_scan(self, scan_id: int):
        """Delete a scan"""
        try:
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                scan = session.query(CloudScan).filter(CloudScan.id == scan_id).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                session.delete(scan)
                session.commit()
                
                return jsonify({'message': 'Scan deleted successfully'}), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error deleting scan: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_list_scans(self, user_id: str):
        """List all scans for a user - optionally filter by provider and workspace"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.user_id == user_id)
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scans by workspace_id: {workspace_id}")
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scans = query.order_by(CloudScan.created_at.desc()).all()
                
                return jsonify({
                    'scans': [scan.to_dict() for scan in scans],
                    'count': len(scans),
                    'provider': provider or 'all',
                    'workspace_id': workspace_id
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
            workspace_id = self._get_workspace_id_from_request()
            status = request.args.get('status')
            limit = request.args.get('limit', type=int, default=50)
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.user_id == user_id)
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scans by workspace_id: {workspace_id}")
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                if status:
                    query = query.filter(CloudScan.status == status)
                
                scans = query.order_by(CloudScan.created_at.desc()).limit(limit).all()
                
                return jsonify({
                    'scans': [scan.to_dict() for scan in scans],
                    'count': len(scans),
                    'filters': {
                        'provider': provider or 'all',
                        'status': status or 'all',
                        'workspace_id': workspace_id
                    }
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting user scans: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_scan_result_by_cloudname(self, user_id: str, cloudname: str):
        """Get scan result by cloudname - filter by workspace if provided"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname
                )
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scan by workspace_id: {workspace_id}")
                
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
    
    def _handle_get_reranked_by_cloudname(self, user_id: str, cloudname: str):
        """Get reranked findings by cloudname - filter by workspace if provided"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname
                )
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering reranked findings by workspace_id: {workspace_id}")
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scan = query.order_by(CloudScan.created_at.desc()).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                if not scan.rerank:
                    return jsonify({'error': 'No reranked findings available'}), 404
                
                return jsonify({
                    'scan_id': scan.id,
                    'cloudname': cloudname,
                    'reranked_findings': scan.rerank,
                    'workspace_id': workspace_id
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
        """Get reranked findings by cloudname and worksheet - filter by workspace if provided"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname,
                    CloudScan.worksheet_number == worksheet_number
                )
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering reranked findings by workspace_id: {workspace_id}")
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scan = query.order_by(CloudScan.created_at.desc()).first()
                
                if not scan:
                    return jsonify({'error': 'Scan not found'}), 404
                
                if not scan.rerank:
                    return jsonify({'error': 'No reranked findings available'}), 404
                
                return jsonify({
                    'scan_id': scan.id,
                    'cloudname': cloudname,
                    'worksheet_number': worksheet_number,
                    'reranked_findings': scan.rerank,
                    'workspace_id': workspace_id
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting reranked findings: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_list_worksheets(self, user_id: str, cloudname: str):
        """List worksheets for a cloudname - filter by workspace if provided"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan.worksheet_number).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname
                )
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering worksheets by workspace_id: {workspace_id}")
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                scans = query.distinct().all()
                worksheets = [scan[0] for scan in scans]
                
                return jsonify({
                    'worksheets': sorted(worksheets),
                    'count': len(worksheets),
                    'provider': provider or 'all',
                    'workspace_id': workspace_id
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
        """Get scan result by cloudname and worksheet - filter by workspace if provided"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.cloudname == cloudname,
                    CloudScan.worksheet_number == worksheet_number
                )
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scan by workspace_id: {workspace_id}")
                
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
        """Get security summary for a user - optionally filter by provider and workspace"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(
                    CloudScan.user_id == user_id,
                    CloudScan.status == 'completed'
                )
                
                # Filter by workspace_id if provided
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering security summary by workspace_id: {workspace_id}")
                
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
                    'filtered_provider': provider or 'all',
                    'workspace_id': workspace_id
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting security summary: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_validate_credentials(self):
        """
        Validate credentials for any cloud provider.
        Request body should include:
        - provider: Cloud provider name (aws, azure, gcp, etc.)
        - credentials: Provider-specific credentials dict
        - account_id (optional): Account/subscription/project ID
        """
        try:
            data = request.get_json() or {}
            provider = self._get_provider_from_request()
            
            if not provider:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Missing required field: provider or cloud_provider',
                        'code': 'MISSING_PROVIDER'
                    }
                }), 400
            
            # Check if provider is registered
            if not self.registry.is_provider_registered(provider):
                return jsonify({
                    'success': False,
                    'error': {
                        'message': f'Provider {provider} is not registered',
                        'code': 'INVALID_PROVIDER',
                        'available_providers': self.registry.list_providers()
                    }
                }), 400
            
            # Get validator for this provider
            validator = self.registry.get_validator(provider)
            if not validator:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': f'Credential validation not implemented for {provider}',
                        'code': 'VALIDATOR_NOT_FOUND'
                    }
                }), 501
            
            # Extract credentials from request
            credentials = data.get('credentials', {})
            
            # Optional account/subscription/project ID
            account_id = data.get('account_id')
            role_arn = data.get('role_arn')  # For AWS role assumption
            external_id = data.get('external_id')  # For AWS external ID
            
            # Validate that we have either credentials OR role_arn (for AWS)
            if not credentials and not role_arn:
                return jsonify({
                    'success': False,
                    'error': {
                        'message': 'Must provide either credentials or role_arn for validation',
                        'code': 'MISSING_CREDENTIALS'
                    }
                }), 400
            
            # Call the provider-specific validator
            import asyncio
            
            # Build validation kwargs based on provider
            if provider == 'aws' and role_arn:
                # For AWS role assumption, put role info in credentials dict
                # to match existing validate_aws_credentials function signature
                aws_credentials = credentials.copy()
                aws_credentials['role_arn'] = role_arn
                if external_id:
                    aws_credentials['external_id'] = external_id
                
                validation_kwargs = {
                    'credentials': aws_credentials,
                    'account_id': account_id
                }
            else:
                # Standard validation
                validation_kwargs = {
                    'credentials': credentials,
                    'account_id': account_id
                }
            
            result = asyncio.run(validator(**validation_kwargs))
            
            # Return the validation result
            # Convert AWS-specific format to unified API format if needed
            if isinstance(result, dict):
                # Handle AWS-specific format: {'valid': bool} -> {'success': bool}
                if 'valid' in result and 'success' not in result:
                    if result['valid']:
                        return jsonify({
                            'success': True,
                            'data': {
                                'account_id': result.get('account_id'),
                                'caller_identity': result.get('caller_identity'),
                                'assumed_role': result.get('assumed_role')
                            }
                        }), 200
                    else:
                        return jsonify({
                            'success': False,
                            'error': {
                                'message': 'Credential validation failed',
                                'code': 'INVALID_CREDENTIALS',
                                'details': ', '.join(result.get('errors', []))
                            }
                        }), 400
                
                # Standard unified API format
                status_code = 200 if result.get('success') else 400
                return jsonify(result), status_code
            else:
                # Fallback for non-standard return format
                return jsonify({
                    'success': True,
                    'provider': provider,
                    'data': result
                }), 200
            
        except Exception as e:
            logger.error(f"Error validating credentials: {str(e)}")
            logger.error(traceback.format_exc())
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Internal server error during credential validation',
                    'code': 'VALIDATION_ERROR',
                    'details': str(e)
                }
            }), 500
    
    def get_blueprint(self):
        """Get the Flask blueprint"""
        return self.blueprint