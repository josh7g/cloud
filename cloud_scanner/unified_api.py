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
        
        logger.debug("No workspace_id found in headers, body, or query params")
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
            provider_specific = data.get('provider_specific', {})
            
            # Extract workspace_id from headers or body
            workspace_id = self._get_workspace_id_from_request()
            logger.info(f"Cloud scan request - user_id: {user_id}, workspace_id: {workspace_id}, provider: {provider}")
            
            # Extract role_config from provider_specific if present
            role_config = provider_specific.get('role_config') if provider_specific else None
            
            # Validate required fields
            # For IAM role scanning, credentials can be empty if role_config is provided
            if not user_id or not account_id:
                return jsonify({
                    'error': 'Missing required fields: user_id, account_id'
                }), 400
            
            # Credentials are required unless using IAM role assumption
            if not credentials and not role_config:
                return jsonify({
                    'error': 'Missing required fields: credentials or role_config must be provided'
                }), 400
            
            # Get provider-specific handler
            handler = self.registry.get_scan_handler(provider)
            if not handler:
                return jsonify({
                    'error': f'No scan handler registered for {provider}'
                }), 500
            
            # Create scan record
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                scan_record = CloudScan(
                    user_id=user_id,
                    cloud_provider=provider,
                    account_id=account_id,
                    cloudname=cloudname,
                    worksheet_number=worksheet_number,
                    status='queued',
                    workspace_id=workspace_id  # Associate scan with workspace
                )
                session.add(scan_record)
                session.commit()
                logger.info(f"Created cloud scan record - scan_id: {scan_record.id}, workspace_id: {workspace_id}, user_id: {user_id}, provider: {provider}")
                
                # Run scan in background
                import threading
                import asyncio
                
                def run_async_scan():
                    """Run async scan handler in new event loop"""
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        # Prepare handler arguments
                        handler_kwargs = {
                            'user_id': user_id,
                            'account_id': account_id,
                            'credentials': credentials,
                            'db_session': session,
                            'scan_record': scan_record,
                            'cloudname': cloudname,
                        }
                        
                        # Add role_config if present
                        if role_config:
                            handler_kwargs['role_config'] = role_config
                        
                        # Add any other provider_specific fields (excluding role_config which we already handled)
                        if provider_specific:
                            for key, value in provider_specific.items():
                                if key != 'role_config' and key not in handler_kwargs:
                                    handler_kwargs[key] = value
                        
                        # Run the async handler
                        result = loop.run_until_complete(handler(**handler_kwargs))
                        logger.info(f"Scan completed: {result}")
                    except Exception as e:
                        logger.error(f"Error in async scan handler: {str(e)}")
                        logger.error(traceback.format_exc())
                        # Update scan record to failed status
                        try:
                            scan_record.status = 'failed'
                            session.commit()
                        except:
                            session.rollback()
                    finally:
                        loop.close()
                        session.close()
                        engine.dispose()
                
                scan_thread = threading.Thread(target=run_async_scan, daemon=True)
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
        """List all scans for a user - optionally filter by provider and workspace"""
        engine = None
        db_session = None
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            
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
            
            engine = create_db_engine()
            SessionFactory = sessionmaker(bind=engine)
            db_session = SessionFactory()
            
            try:
                # Build query
                query = db_session.query(CloudScan).filter(CloudScan.user_id == user_id)
                
                # Filter by workspace_id if provided (workspace-based filtering)
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scans by workspace_id: {workspace_id}")
                
                if provider:
                    query = query.filter(CloudScan.cloud_provider == provider)
                
                # Apply sorting
                if sort_order == 'asc':
                    query = query.order_by(getattr(CloudScan, sort_by).asc())
                else:
                    query = query.order_by(getattr(CloudScan, sort_by).desc())
                
                # Count total scans
                total_scans = query.count()
                
                # Apply pagination
                scans = query.limit(per_page).offset((page - 1) * per_page).all()
                
                # Format response to match old AWS API format
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
                
                # Determine benchmark name based on provider
                benchmark_map = {
                    'aws': 'CIS AWS Foundations Benchmark v1.4',
                    'azure': 'CIS Microsoft Azure Foundations Benchmark',
                    'gcp': 'CIS Google Cloud Platform Foundations Benchmark'
                }
                benchmark = benchmark_map.get(provider or 'aws', 'CIS Cloud Security Benchmark')
                
                return jsonify({
                    'success': True,
                    'data': {
                        'scans': scan_list,
                        'pagination': pagination,
                        'user_id': user_id,
                        'benchmark': benchmark
                    }
                }), 200
                
            finally:
                if db_session:
                    db_session.close()
                if engine:
                    engine.dispose()
                
        except Exception as e:
            logger.error(f"Error listing scans: {str(e)}", exc_info=True)
            return jsonify({
                'success': False,
                'error': {
                    'message': 'Internal server error',
                    'code': 'INTERNAL_ERROR',
                    'details': str(e)
                }
            }), 500
    
    def _handle_get_user_scans(self, user_id: str):
        """Get user scans with filtering by provider, status, and workspace"""
        try:
            provider = self._get_provider_from_request()
            workspace_id = self._get_workspace_id_from_request()
            status = request.args.get('status')
            limit = request.args.get('limit', type=int, default=10)
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.user_id == user_id)
                
                # Filter by workspace_id if provided (workspace-based filtering)
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
                    'provider': provider or 'all',
                    'workspace_id': workspace_id
                }), 200
                
            finally:
                session.close()
                engine.dispose()
                
        except Exception as e:
            logger.error(f"Error getting user scans: {str(e)}")
            return jsonify({'error': str(e)}), 500
    
    def _handle_get_scan_result(self, scan_id: int):
        """Get scan result by scan ID - verify workspace if provided"""
        try:
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.id == scan_id)
                
                # If workspace_id is provided, ensure scan belongs to that workspace
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scan {scan_id} by workspace_id: {workspace_id}")
                
                scan = query.first()
                
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
        """Get reranked findings by scan ID - verify workspace if provided"""
        try:
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.id == scan_id)
                
                # If workspace_id is provided, ensure scan belongs to that workspace
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Filtering scan {scan_id} by workspace_id: {workspace_id}")
                
                scan = query.first()
                
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
    
    def _handle_delete_scan(self, scan_id: int):
        """Delete a scan - verify workspace if provided"""
        try:
            workspace_id = self._get_workspace_id_from_request()
            
            engine = create_db_engine()
            session = Session(engine)
            
            try:
                query = session.query(CloudScan).filter(CloudScan.id == scan_id)
                
                # If workspace_id is provided, ensure scan belongs to that workspace
                if workspace_id:
                    query = query.filter(CloudScan.workspace_id == workspace_id)
                    logger.info(f"Verifying scan {scan_id} belongs to workspace_id: {workspace_id}")
                
                scan = query.first()
                
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
            logger.error(f"Error getting scan result by cloudname: {str(e)}")
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
                    logger.info(f"Filtering scan by workspace_id: {workspace_id}")
                
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
                    logger.info(f"Filtering scan by workspace_id: {workspace_id}")
                
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

