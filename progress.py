from flask import Blueprint, jsonify, request
import logging
from progress_tracking import get_scan_progress

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Create Blueprint
progress_bp = Blueprint('progress', __name__, url_prefix='/api/v1/progress')

@progress_bp.route('/<user_id>/<owner>/<repo>', methods=['GET'])
def get_scan_progress_endpoint(user_id: str, owner: str, repo: str):
    """Get scan progress API endpoint."""
    try:
        repo_name = f"{owner}/{repo}"
        
        # Get progress from centralized tracking module
        progress = get_scan_progress(user_id, repo_name)
        
        if not progress:
            return jsonify({
                'success': False,
                'error': 'No scan in progress'
            }), 404

        return jsonify({
            'success': True,
            'data': progress
        })
    
    except Exception as e:
        logger.error(f"Error getting progress: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Service temporarily unavailable'
        }), 503