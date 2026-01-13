"""
Common Steampipe/Powerpipe Service - Shared across all cloud providers
"""
import os
import json
import logging
import asyncio
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path
import traceback

logger = logging.getLogger(__name__)


class SteampipeService:
    """
    Common Steampipe/Powerpipe service for all cloud providers.
    Handles plugin installation, mod management, benchmark execution, and config data collection.
    """
    
    def __init__(self, provider_name: str, workspace_dir: Path):
        self.provider_name = provider_name
        self.workspace_dir = workspace_dir
        self.mod_dir = workspace_dir / f'{provider_name}_mod'
        self.mod_dir.mkdir(exist_ok=True)
    
    async def _run_command(self, command: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> str:
        """Run a command and return its output with timeout"""
        try:
            cmd_str = ' '.join(command)
            logger.debug(f"Running command: {cmd_str}")
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
                env=os.environ.copy()
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Command timed out after {timeout} seconds: {cmd_str}")
                raise RuntimeError(f"Command timed out after {timeout} seconds: {cmd_str}")
            
            if stderr:
                stderr_text = stderr.decode()
                if stderr_text.strip():
                    logger.debug(f"Command stderr: {stderr_text}")
            
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else "Unknown error"
                logger.error(f"Command failed with code {process.returncode}: {error_msg}")
                raise RuntimeError(f"Command failed with code {process.returncode}: {error_msg}")
            
            output = stdout.decode() if stdout else ""
            return output
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            logger.error(traceback.format_exc())
            raise
    
    async def initialize_service(self):
        """Initialize Steampipe service"""
        try:
            # Stop any existing Steampipe service
            try:
                logger.info("Stopping any existing Steampipe service")
                await self._run_command(['steampipe', 'service', 'stop'], timeout=30)
                await asyncio.sleep(2)
            except Exception as e:
                logger.warning(f"Steampipe service stop warning (non-critical): {str(e)}")
            
            # Start the Steampipe service
            logger.info("Starting Steampipe service")
            try:
                await self._run_command(['steampipe', 'service', 'start'], timeout=30)
                logger.info("Steampipe service started")
                await asyncio.sleep(5)
            except Exception as e:
                logger.warning(f"Steampipe service start warning: {str(e)}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Steampipe service: {str(e)}")
            return False
    
    async def install_plugin(self, plugin_name: str, version: Optional[str] = None):
        """Install Steampipe plugin for the cloud provider"""
        try:
            logger.info(f"Installing {plugin_name} plugin for Steampipe")
            plugin_cmd = ['steampipe', 'plugin', 'install', plugin_name]
            if version:
                plugin_cmd.append(version)
            
            await self._run_command(plugin_cmd, timeout=180)
            logger.info(f"{plugin_name} plugin installed successfully")
            return True
        except Exception as e:
            logger.warning(f"{plugin_name} plugin installation warning: {str(e)}")
            return False
    
    async def initialize_mod(self):
        """Initialize Powerpipe mod"""
        try:
            logger.info("Initializing Powerpipe mod")
            init_cmd = ['powerpipe', 'mod', 'init']
            await self._run_command(init_cmd, cwd=self.mod_dir, timeout=30)
            logger.info("Powerpipe mod initialized")
            return True
        except Exception as e:
            logger.warning(f"Mod initialization warning: {str(e)}")
            return False
    
    async def install_compliance_mod(self, mod_url: str):
        """Install compliance mod for the cloud provider"""
        try:
            logger.info(f"Installing compliance mod: {mod_url}")
            install_cmd = ['powerpipe', 'mod', 'install', mod_url]
            await self._run_command(install_cmd, cwd=self.mod_dir, timeout=180)
            logger.info("Compliance mod installed successfully")
            return True
        except Exception as e:
            logger.warning(f"Warning installing compliance mod: {str(e)}")
            return False
    
    async def run_benchmark(self, benchmark_name: str, timeout: int = 300) -> Optional[Dict[str, Any]]:
        """Run Powerpipe benchmark"""
        try:
            logger.info(f"Running benchmark: {benchmark_name}")
            benchmark_cmd = ['powerpipe', 'benchmark', 'run', benchmark_name, '--output', 'json']
            
            benchmark_output = await self._run_command_with_debug(benchmark_cmd, cwd=self.mod_dir, timeout=timeout)
            
            if benchmark_output and len(benchmark_output.strip()) > 0:
                try:
                    benchmark_results = json.loads(benchmark_output)
                    logger.info(f"Successfully parsed benchmark results")
                    
                    summary = benchmark_results.get('summary', {}).get('status', {})
                    logger.info(f"Benchmark summary: {summary.get('ok', 0)} ok, "
                              f"{summary.get('alarm', 0)} alarm, {summary.get('info', 0)} info")
                    
                    return benchmark_results
                except json.JSONDecodeError as je:
                    logger.error(f"Failed to parse benchmark output as JSON: {str(je)}")
                    return None
            return None
        except Exception as e:
            logger.error(f"Error running benchmark: {str(e)}")
            return None
    
    async def _run_command_with_debug(self, command: List[str], cwd: Optional[Path] = None, timeout: int = 300) -> str:
        """Run command with debug output handling"""
        try:
            cmd_str = ' '.join(command)
            logger.debug(f"Running command with debug: {cmd_str}")
            
            # For benchmark commands, use file redirection for large outputs
            if 'benchmark run' in cmd_str and '--output json' in cmd_str:
                output_file = self.workspace_dir / f"benchmark_output_{int(asyncio.get_event_loop().time())}.json"
                
                # Use shell to allow redirection
                redirect_cmd = f"{' '.join(command)} > {output_file}"
                
                process = await asyncio.create_subprocess_shell(
                    redirect_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(cwd) if cwd else None,
                    env=os.environ.copy(),
                    shell=True
                )
                
                try:
                    _, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
                except asyncio.TimeoutError:
                    process.kill()
                    raise RuntimeError(f"Command timed out after {timeout} seconds")
                
                if stderr:
                    stderr_text = stderr.decode()
                    if stderr_text:
                        logger.error(f"Command stderr: {stderr_text}")
                
                if os.path.exists(output_file):
                    with open(output_file, 'r') as f:
                        stdout_text = f.read()
                    logger.info(f"Read {len(stdout_text)} bytes from output file")
                    return stdout_text
                else:
                    raise RuntimeError("Output file not created")
            
            # For other commands, use normal approach
            return await self._run_command(command, cwd, timeout)
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            raise
    
    async def query_steampipe(self, query: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
        """Execute a Steampipe query and return results"""
        try:
            query_file = self.workspace_dir / f'query_{int(asyncio.get_event_loop().time())}.sql'
            with open(query_file, 'w') as f:
                f.write(query)
            
            result = await self._run_command([
                'steampipe', 'query', str(query_file), '--output', 'json'
            ], self.workspace_dir, timeout=timeout)
            
            if result and result.strip():
                try:
                    parsed_result = json.loads(result)
                    if isinstance(parsed_result, dict) and 'rows' in parsed_result:
                        return parsed_result['rows']
                    elif isinstance(parsed_result, list):
                        return parsed_result
                    else:
                        return [parsed_result]
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse JSON: {str(e)}")
                    return None
            return None
        except Exception as e:
            logger.warning(f"Query execution failed: {str(e)}")
            return None
    
    async def collect_config_data(self, queries: Dict[str, str]) -> Dict[str, Any]:
        """Collect configuration data using Steampipe queries"""
        config_data = {}
        successful_queries = 0
        
        for config_name, query in queries.items():
            try:
                logger.info(f"Collecting {config_name} configuration data")
                result = await self.query_steampipe(query, timeout=30)
                
                if result:
                    config_data[config_name] = result
                    successful_queries += 1
                    logger.info(f"✓ Collected {config_name}: {len(result)} items")
                else:
                    config_data[config_name] = []
                    logger.warning(f"✗ No data returned for {config_name}")
                    
            except Exception as e:
                logger.warning(f"✗ Failed to collect {config_name}: {str(e)}")
                config_data[config_name] = []
        
        logger.info(f"Config data collection summary: {successful_queries}/{len(queries)} sections collected")
        return config_data


# Provider-specific Steampipe configurations
STEAMPIPE_CONFIGS = {
    'aws': {
        'plugin_name': 'aws',
        'plugin_version': None,  # Use latest
        'compliance_mod': 'github.com/turbot/steampipe-mod-aws-compliance',
        'benchmark_prefix': 'aws_compliance.benchmark',
        'default_benchmark': 'aws_compliance.benchmark.cis_v400'
    },
    'azure': {
        'plugin_name': 'azure',
        'plugin_version': None,
        'compliance_mod': 'github.com/turbot/steampipe-mod-azure-compliance',
        'benchmark_prefix': 'azure_compliance.benchmark',
        'default_benchmark': 'azure_compliance.benchmark.cis_v100'
    },
    'gcp': {
        'plugin_name': 'gcp',
        'plugin_version': None,
        'compliance_mod': 'github.com/turbot/steampipe-mod-gcp-compliance',
        'benchmark_prefix': 'gcp_compliance.benchmark',
        'default_benchmark': 'gcp_compliance.benchmark.cis_v100'
    }
}

