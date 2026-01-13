"""
ECS Task Definition Management
Automatically register ECS task definitions during application startup
"""
import json
import logging
import os
from pathlib import Path
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class ECSTaskManager:
    """Manage ECS task definitions for the scanner service"""
    
    def __init__(self, region=None):
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.ecs_client = None
        self.logs_client = None
        
    def _get_ecs_client(self):
        """Lazy load ECS client"""
        if not self.ecs_client:
            # Use separate credentials for ECS operations if available
            ecs_access_key = os.getenv('ECS_AWS_ACCESS_KEY_ID') or os.getenv('AWS_ACCESS_KEY_ID')
            ecs_secret_key = os.getenv('ECS_AWS_SECRET_ACCESS_KEY') or os.getenv('AWS_SECRET_ACCESS_KEY')
            
            if ecs_access_key and ecs_secret_key:
                self.ecs_client = boto3.client(
                    'ecs',
                    region_name=self.region,
                    aws_access_key_id=ecs_access_key,
                    aws_secret_access_key=ecs_secret_key
                )
            else:
                # Fallback to default credentials (IAM role)
                self.ecs_client = boto3.client('ecs', region_name=self.region)
        return self.ecs_client
    
    def _get_logs_client(self):
        """Lazy load CloudWatch Logs client"""
        if not self.logs_client:
            # Use separate credentials for CloudWatch operations if available
            ecs_access_key = os.getenv('ECS_AWS_ACCESS_KEY_ID') or os.getenv('AWS_ACCESS_KEY_ID')
            ecs_secret_key = os.getenv('ECS_AWS_SECRET_ACCESS_KEY') or os.getenv('AWS_SECRET_ACCESS_KEY')
            
            if ecs_access_key and ecs_secret_key:
                self.logs_client = boto3.client(
                    'logs',
                    region_name=self.region,
                    aws_access_key_id=ecs_access_key,
                    aws_secret_access_key=ecs_secret_key
                )
            else:
                # Fallback to default credentials (IAM role)
                self.logs_client = boto3.client('logs', region_name=self.region)
        return self.logs_client
    
    def create_log_group(self, log_group_name):
        """
        Create CloudWatch log group if it doesn't exist
        
        Args:
            log_group_name (str): Name of the log group
            
        Returns:
            bool: True if created or already exists, False on error
        """
        try:
            logs_client = self._get_logs_client()
            logs_client.create_log_group(logGroupName=log_group_name)
            logger.info(f"âœ… Created CloudWatch log group: {log_group_name}")
            return True
        except logs_client.exceptions.ResourceAlreadyExistsException:
            logger.info(f"âœ… CloudWatch log group already exists: {log_group_name}")
            return True
        except Exception as e:
            logger.error(f"âŒ Error creating log group {log_group_name}: {e}")
            return False
    
    def task_definition_exists(self, family):
        """
        Check if a task definition exists
        
        Args:
            family (str): Task definition family name
            
        Returns:
            bool: True if exists, False otherwise
        """
        try:
            ecs_client = self._get_ecs_client()
            response = ecs_client.describe_task_definition(taskDefinition=family)
            task_def = response['taskDefinition']
            logger.info(f"âœ… Task definition exists: {family}:{task_def['revision']}")
            return True
        except ecs_client.exceptions.ClientException:
            return False
        except Exception as e:
            logger.warning(f"Error checking task definition {family}: {e}")
            return False
    
    def register_task_definition(self, task_def_config):
        """
        Register an ECS task definition
        
        Args:
            task_def_config (dict): Task definition configuration
            
        Returns:
            dict: Response with success status and details
        """
        try:
            ecs_client = self._get_ecs_client()
            
            # Extract family for logging
            family = task_def_config.get('family', 'unknown')
            
            # Register the task definition
            response = ecs_client.register_task_definition(**task_def_config)
            
            task_def = response['taskDefinition']
            logger.info(f"âœ… Registered task definition: {task_def['family']}:{task_def['revision']}")
            
            return {
                'success': True,
                'family': task_def['family'],
                'revision': task_def['revision'],
                'arn': task_def['taskDefinitionArn']
            }
            
        except Exception as e:
            logger.error(f"âŒ Error registering task definition: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def register_from_file(self, taskdef_file):
        """
        Register task definition from a JSON file
        
        Args:
            taskdef_file (str): Path to task definition JSON file
            
        Returns:
            dict: Response with success status and details
        """
        try:
            taskdef_path = Path(taskdef_file)
            
            if not taskdef_path.exists():
                logger.error(f"âŒ Task definition file not found: {taskdef_file}")
                return {'success': False, 'error': 'File not found'}
            
            # Load task definition
            with open(taskdef_path, 'r') as f:
                task_def_config = json.load(f)
            
            family = task_def_config.get('family', 'unknown')
            logger.info(f"Loading task definition from {taskdef_file} (family: {family})")
            
            # Create log group if specified in task definition
            container_defs = task_def_config.get('containerDefinitions', [])
            for container in container_defs:
                log_config = container.get('logConfiguration', {})
                if log_config.get('logDriver') == 'awslogs':
                    log_group = log_config.get('options', {}).get('awslogs-group')
                    if log_group:
                        self.create_log_group(log_group)
            
            # Register the task definition
            return self.register_task_definition(task_def_config)
            
        except json.JSONDecodeError as e:
            logger.error(f"âŒ Invalid JSON in task definition file: {e}")
            return {'success': False, 'error': f'Invalid JSON: {e}'}
        except Exception as e:
            logger.error(f"âŒ Error loading task definition: {e}")
            return {'success': False, 'error': str(e)}
    
    def ensure_task_definition(self, taskdef_file, force_update=False):
        """
        Ensure task definition is registered, register if missing or force_update=True
        
        Args:
            taskdef_file (str): Path to task definition JSON file
            force_update (bool): Force re-registration even if exists
            
        Returns:
            dict: Response with success status and details
        """
        try:
            # Load to get family name
            with open(taskdef_file, 'r') as f:
                task_def_config = json.load(f)
            
            family = task_def_config.get('family')
            
            if not force_update and self.task_definition_exists(family):
                logger.info(f"âœ… Task definition {family} already registered, skipping")
                return {'success': True, 'action': 'skipped', 'family': family}
            
            # Register or update
            result = self.register_from_file(taskdef_file)
            result['action'] = 'updated' if force_update else 'registered'
            return result
            
        except Exception as e:
            logger.error(f"âŒ Error ensuring task definition: {e}")
            return {'success': False, 'error': str(e)}


def initialize_ecs_tasks(taskdef_files=None):
    """
    Initialize all ECS task definitions during application startup
    
    Args:
        taskdef_files (list): List of task definition file paths
                             If None, looks for standard files in current directory
    
    Returns:
        dict: Summary of initialization results
    """
    logger.info("=== Initializing ECS Task Definitions ===")
    
    # Default task definition files to check
    if taskdef_files is None:
        taskdef_files = [
            'taskdef-github-scanner.json',
            # Add more task definitions here as needed
        ]
    
    manager = ECSTaskManager()
    results = []
    
    for taskdef_file in taskdef_files:
        if not Path(taskdef_file).exists():
            logger.warning(f"âš ï¸  Task definition file not found: {taskdef_file}, skipping")
            continue
        
        logger.info(f"Processing {taskdef_file}...")
        result = manager.ensure_task_definition(taskdef_file)
        results.append({
            'file': taskdef_file,
            **result
        })
    
    # Summary
    successful = sum(1 for r in results if r.get('success'))
    failed = len(results) - successful
    
    logger.info("=== ECS Initialization Complete ===")
    logger.info(f"âœ… Successful: {successful}")
    if failed > 0:
        logger.warning(f"âš ï¸  Failed: {failed}")
    
    return {
        'success': failed == 0,
        'total': len(results),
        'successful': successful,
        'failed': failed,
        'results': results
    }


if __name__ == "__main__":
    # Can be run standalone for testing
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )
    
    result = initialize_ecs_tasks()
    sys.exit(0 if result['success'] else 1)