import time
import logging
import json
from datetime import datetime
from typing import Optional, Dict, Any, Callable
from progress_tracking import get_redis_client, generate_unique_scan_id
import traceback

logger = logging.getLogger(__name__)


class ZapProgressTracker:
    """
    Dedicated progress tracker for ZAP scans that doesn't interfere with existing system.
    """

    ZAP_STAGE_WEIGHTS = {
        "initializing": 0.05,  # 5%
        "starting_container": 0.05,  # 5%
        "waiting_for_zap": 0.05,  # 5%
        "zap_ready": 0.05,  # 5%
        "spider_starting": 0.05,  # 5%
        "spider_running": 0.25,  # 25%
        "spider_completed": 0.30,  # 30%
        "active_scan_starting": 0.35,  # 35%
        "active_scan_running": 0.60,  # 60%
        "active_scan_completed": 0.65,  # 65%
        "generating_report": 0.85,  # 85%
        "processing_results": 0.95,  # 95%
        "scan_started": 0.10,  # 10%
        "completed": 1.0,  # 100%
        "error": 1.0,  # 100%
    }

    # User-friendly stage names
    STAGE_DISPLAY_NAMES = {
        "initializing": "Initializing ZAP scanner",
        "starting_container": "Starting Docker container",
        "waiting_for_zap": "Waiting for ZAP to start",
        "zap_ready": "ZAP ready, preparing scan",
        "spider_starting": "Starting website crawler",
        "spider_running": "Crawling website structure",
        "spider_completed": "Website crawling completed",
        "active_scan_starting": "Starting security tests",
        "active_scan_running": "Running security vulnerability scans",
        "active_scan_completed": "Security tests completed",
        "generating_report": "Generating security report",
        "processing_results": "Processing scan results",
        "scan_started": "ZAP scan in progress",
        "completed": "ZAP scan completed",
        "error": "ZAP scan failed",
    }

    def __init__(self):
        self.redis_client = get_redis_client()

    def update_zap_progress(
        self,
        user_id: str,
        target_url: str,
        stage: str,
        stage_progress: int,
        scan_id: Optional[str] = None,
        details: Optional[Dict] = None,
    ) -> bool:
        """
        Update ZAP scan progress using dedicated keys to avoid conflicts.

        Args:
            user_id: User ID
            target_url: Target URL being scanned
            stage: Internal ZAP stage name
            stage_progress: Progress within current stage (0-100)
            scan_id: Optional scan ID
            details: Additional progress details

        Returns:
            bool: Success status
        """
        try:
            if not all([user_id, target_url, stage]):
                logger.warning("Invalid ZAP progress update parameters")
                return False

            if not scan_id:
                scan_id = f"zap_{generate_unique_scan_id()}"

            resource_id = self._sanitize_target_id(target_url)
            key = f"zap_scan_progress:{user_id}:{resource_id}"

            stage_progress = max(0, min(100, stage_progress))

            previous_data = self.get_zap_progress(user_id, target_url)
            previous_overall = (
                previous_data.get("overall_progress", 0) if previous_data else 0
            )

            overall_progress = self._calculate_zap_overall_progress(
                stage, stage_progress
            )

            if previous_data and stage not in ["completed", "error"]:
                overall_progress = max(overall_progress, previous_overall)

            if stage in ["completed", "error"]:
                overall_progress = 100
                stage_progress = 100

            progress_data = {
                "stage": stage,
                "stage_progress": stage_progress,
                "overall_progress": overall_progress,
                "timestamp": datetime.utcnow().isoformat(),
                "unix_timestamp": int(time.time()),
                "scan_id": scan_id,
                "target_url": target_url,
                "user_id": user_id,
                "scan_type": "zap",
                "display_stage": self.STAGE_DISPLAY_NAMES.get(stage, stage),
                "details": details or {},
            }

            if stage in ["completed", "error"]:
                self.redis_client.setex(
                    key, 30, json.dumps(progress_data)
                )  # 30 seconds
            else:
                self.redis_client.setex(
                    key, 600, json.dumps(progress_data)
                )  # 10 minutes

            self._publish_progress_update(user_id, resource_id, progress_data)

            logger.info(
                f"ZAP progress: {user_id} -> {target_url} | "
                f"{stage} ({stage_progress}%) | Overall: {overall_progress}%"
            )

            return True

        except Exception as e:
            logger.error(f"Error updating ZAP progress: {str(e)}")
            logger.error(traceback.format_exc())
            return False

    def _calculate_zap_overall_progress(self, stage: str, stage_progress: int) -> int:
        """
        Calculate overall progress based on ZAP-specific stage weights.
        """
        base_progress = self.ZAP_STAGE_WEIGHTS.get(stage, 0.5) * 100

        if stage in ["spider_running", "active_scan_running"]:
            stage_range = 0
            if stage == "spider_running":
                stage_range = (
                    self.ZAP_STAGE_WEIGHTS["spider_completed"]
                    - self.ZAP_STAGE_WEIGHTS["spider_starting"]
                )
            elif stage == "active_scan_running":
                stage_range = (
                    self.ZAP_STAGE_WEIGHTS["active_scan_completed"]
                    - self.ZAP_STAGE_WEIGHTS["active_scan_starting"]
                )

            stage_contribution = (stage_progress / 100.0) * stage_range * 100
            base_progress = (
                self.ZAP_STAGE_WEIGHTS.get(stage + "_starting", 0) * 100
                + stage_contribution
            )

        return int(max(0, min(100, base_progress)))

    def _publish_progress_update(
        self, user_id: str, resource_id: str, progress_data: Dict
    ):
        """
        Publish progress update to WebSocket channel.
        """
        try:
            room = f"zap_scan_{user_id}_{resource_id}"

            ws_data = {
                "s": progress_data["display_stage"],
                "p": progress_data["stage_progress"],
                "o": progress_data["overall_progress"],
                "t": progress_data["unix_timestamp"],
                "id": progress_data["scan_id"],
                "scan_type": "zap",
                "target_url": progress_data["target_url"],
            }

            message = {
                "user_id": user_id,
                "resource_id": resource_id,
                "data": ws_data,
                "scan_type": "zap",
                "room": room,
                "is_zap": True,  
            }

            self.redis_client.publish("scan_updates", json.dumps(message))

        except Exception as e:
            logger.error(f"Error publishing ZAP progress update: {str(e)}")

    def get_zap_progress(self, user_id: str, target_url: str) -> Optional[Dict]:
        """
        Get current ZAP scan progress.

        Args:
            user_id: User ID
            target_url: Target URL

        Returns:
            Optional[Dict]: Progress data or None if not found
        """
        try:
            resource_id = self._sanitize_target_id(target_url)
            key = f"zap_scan_progress:{user_id}:{resource_id}"

            data = self.redis_client.get(key)
            if data:
                progress_data = json.loads(data)

                stage = progress_data.get("stage", "")
                if stage in ["completed", "error"]:
                    return None

                return progress_data

            return None

        except Exception as e:
            logger.error(f"Error getting ZAP progress: {str(e)}")
            return None

    def clear_zap_progress(self, user_id: str, target_url: str) -> bool:
        """
        Clear ZAP scan progress data.

        Args:
            user_id: User ID
            target_url: Target URL

        Returns:
            bool: Success status
        """
        try:
            resource_id = self._sanitize_target_id(target_url)

            # Clear ZAP-specific keys
            keys_to_clear = [
                f"zap_scan_progress:{user_id}:{resource_id}",
                f"zap_scan_complete:{user_id}:{resource_id}",
            ]

            for key in keys_to_clear:
                self.redis_client.delete(key)

            logger.info(f"Cleared ZAP progress data for {user_id}:{target_url}")
            return True

        except Exception as e:
            logger.error(f"Error clearing ZAP progress: {str(e)}")
            return False

    def _sanitize_target_id(self, target: str) -> str:
        """
        Sanitize target URL for use in Redis keys.
        """
        try:
            sanitized = (
                target.replace("://", "_")
                .replace("/", "_")
                .replace("?", "_")
                .replace("&", "_")
                .replace("#", "_")
                .replace("=", "_")
            )
            return sanitized.strip("_")[:100]  
        except Exception:
            return target

    def create_zap_progress_callback(
        self, user_id: str, target_url: str, scan_id: str
    ) -> Callable:
        """
        Create a progress callback function for ZAP scanner.

        Args:
            user_id: User ID
            target_url: Target URL
            scan_id: Scan ID

        Returns:
            Callable: Progress callback function
        """

        def progress_callback(
            stage: str, progress: int, details: Optional[Dict] = None
        ):
            """Callback function for ZAP progress updates"""
            self.update_zap_progress(
                user_id=user_id,
                target_url=target_url,
                stage=stage,
                stage_progress=progress,
                scan_id=scan_id,
                details=details,
            )

        return progress_callback


zap_tracker = ZapProgressTracker()


def update_zap_scan_progress(
    user_id: str,
    target_url: str,
    stage: str,
    progress: int,
    scan_id: Optional[str] = None,
    details: Optional[Dict] = None,
) -> bool:
    """Convenience function to update ZAP scan progress"""
    return zap_tracker.update_zap_progress(
        user_id, target_url, stage, progress, scan_id, details
    )


def get_zap_scan_progress(user_id: str, target_url: str) -> Optional[Dict]:
    """Convenience function to get ZAP scan progress"""
    return zap_tracker.get_zap_progress(user_id, target_url)


def clear_zap_scan_progress(user_id: str, target_url: str) -> bool:
    """Convenience function to clear ZAP scan progress"""
    return zap_tracker.clear_zap_progress(user_id, target_url)


def create_zap_progress_callback(
    user_id: str, target_url: str, scan_id: str
) -> Callable:
    """Convenience function to create ZAP progress callback"""
    return zap_tracker.create_zap_progress_callback(user_id, target_url, scan_id)
