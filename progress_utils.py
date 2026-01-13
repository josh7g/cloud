"""
Progress utilities for smooth progress animations
"""
import asyncio
import logging

logger = logging.getLogger(__name__)


async def animate_progress_to_target(
    user_id: str,
    repo_name: str, 
    stage: str,
    target_progress: int,
    scan_type: str = 'repository',
    scan_id: str = None,
    step_delay: float = 0.15
):
    """
    Smoothly animate progress from current position to target.
    
    Sends progress updates in 10% increments of the stage with a delay between each,
    creating a smooth visual progression instead of instant jumps.
    
    Args:
        user_id: User ID
        repo_name: Repository name or resource ID
        stage: Current stage name (e.g., 'initializing', 'cloning')
        target_progress: Target progress within this stage (0-100)
        scan_type: Type of scan ('repository', 'aws', 'gitlab', 'zap')
        scan_id: Optional scan ID for tracking
        step_delay: Delay in seconds between each update (default: 0.15s)
    
    Example:
        # Animate from 0% to 50% of initializing stage over ~0.75 seconds
        await animate_progress_to_target(user_id, repo_name, "initializing", 50)
        # This will send: 0%, 10%, 20%, 30%, 40%, 50% with 0.15s between each
    """
    from progress_tracking import update_scan_progress
    
    current = 0
    while current < target_progress:
        current = min(current + 10, target_progress)
        update_scan_progress(user_id, repo_name, stage, current, scan_type=scan_type, scan_id=scan_id)
        await asyncio.sleep(step_delay)
    
    # Ensure we reach the exact target
    update_scan_progress(user_id, repo_name, stage, target_progress, scan_type=scan_type, scan_id=scan_id)


def calculate_overall_progress(stage: str, stage_progress: float) -> int:
    """
    Calculate overall progress percentage based on stage and stage progress.
    
    Stage weight ranges:
    - initializing: 0-3%
    - cloning: 3-6%
    - analyzing: 6-80% (main work happens here)
    - processing: 80-95%
    - reranking: 95-98%
    - completed: 100%
    
    Args:
        stage: Current stage name
        stage_progress: Progress within the stage (0-100)
    
    Returns:
        Overall progress percentage (0-100)
    """
    STAGE_WEIGHTS = {
        'initializing': {'range': (0, 3)},      # 0-3%
        'validating': {'range': (0, 3)},        # 0-3%
        'cloning': {'range': (3, 6)},           # 3-6%
        'analyzing': {'range': (6, 80)},        # 6-80%
        'processing': {'range': (80, 95)},      # 80-95%
        'reranking': {'range': (95, 98)},       # 95-98%
        'completed': {'range': (100, 100)},     # 100%
        'error': {'range': (100, 100)},         # 100%
    }
    
    if stage not in STAGE_WEIGHTS:
        logger.warning(f"Unknown stage: {stage}, defaulting to 0%")
        return 0
    
    stage_range = STAGE_WEIGHTS[stage]['range']
    stage_start = stage_range[0]
    stage_end = stage_range[1]
    stage_width = stage_end - stage_start
    
    # Calculate overall progress
    # If stage is completed or error, return 100%
    if stage in ['completed', 'error']:
        return 100
    
    # Normalize stage_progress to 0-1 range
    normalized_progress = max(0, min(100, stage_progress)) / 100.0
    
    # Calculate overall progress within the stage range
    overall_progress = stage_start + (normalized_progress * stage_width)
    
    # Round to integer and ensure it's within 0-100
    return int(max(0, min(100, overall_progress)))