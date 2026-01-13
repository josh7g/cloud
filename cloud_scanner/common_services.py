"""
Common services for cloud scanning - RAG analysis, reranking, etc.
"""
import os
import json
import logging
import asyncio
import aiohttp
import re
from typing import List, Dict, Optional, Any, Union
from datetime import datetime
import traceback

logger = logging.getLogger(__name__)


async def rag_cloud_analysis(
    findings: List[Dict], 
    user_id: str, 
    cloudname: str,
    provider_name: str,
    config_data: Optional[Dict] = None
) -> Dict:
    """
    Send cloud security findings to RAG analysis service.
    
    Args:
        findings: List of security findings
        user_id: User identifier
        cloudname: Cloud name for context
        provider_name: Cloud provider name (aws, azure, gcp, etc.)
        config_data: Optional configuration data from cloud provider
        
    Returns:
        Dict: RAG analysis response
    """
    try:
        logger.info(f"Preparing {len(findings)} {provider_name.upper()} findings for RAG analysis")
        
        rag_url = os.getenv('RAG_URL')
        if not rag_url:
            logger.warning("RAG_URL environment variable not set, skipping RAG analysis")
            return {}
        
        # Use provider-specific endpoint if available, otherwise use generic
        # Use provider-specific endpoint if available, otherwise use generic
        endpoint_suffix = f"rag_{provider_name}_analysis"
        rag_endpoint = f"{rag_url.rstrip('/')}/{endpoint_suffix}"
        
        # Prepare data for RAG API
        rag_data = {
            'user_id': user_id,
            'cloudname': cloudname,
            'file': [{
                "ID": idx + 1,
                "category": finding.get("category", ""),
                "reason": finding.get("reason", ""),
                "severity": finding.get("severity", ""),
                "status": finding.get("status", ""),
                "control_id": finding.get("control_id", ""),
                "resource_id": finding.get("resource_id", "")
            } for idx, finding in enumerate(findings)]
        }
        
        # Add config data if provided
        if config_data:
            processed_config = {}
            for section_name, section_data in config_data.items():
                if section_data and isinstance(section_data, list) and len(section_data) > 0:
                    processed_config[section_name] = {
                        'count': len(section_data),
                        'sample_data': section_data[:3] if len(section_data) > 3 else section_data,
                        'has_data': True
                    }
                else:
                    processed_config[section_name] = {
                        'count': 0,
                        'has_data': False
                    }
            
            rag_data[f'{provider_name}_config'] = processed_config
            logger.info(f"Including {provider_name.upper()} config data with {len(processed_config)} sections")
        
        # Add findings summary
        findings_summary = {
            'total_findings': len(findings),
            'severity_breakdown': {},
            'category_breakdown': {},
            'status_breakdown': {}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            findings_summary['severity_breakdown'][severity] = findings_summary['severity_breakdown'].get(severity, 0) + 1
            
            category = finding.get('category', 'UNKNOWN')
            findings_summary['category_breakdown'][category] = findings_summary['category_breakdown'].get(category, 0) + 1
            
            status = finding.get('status', 'UNKNOWN')
            findings_summary['status_breakdown'][status] = findings_summary['status_breakdown'].get(status, 0) + 1
        
        rag_data['findings_summary'] = findings_summary
        
        # Send to RAG API
        logger.info(f"Sending {len(findings)} findings to RAG analysis: {rag_endpoint}")
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                timeout = aiohttp.ClientTimeout(total=90)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(rag_endpoint, json=rag_data) as response:
                        if response.status == 200:
                            rag_response = await response.json()
                            logger.info(f"RAG analysis completed successfully")
                            
                            if isinstance(rag_response, dict):
                                rag_response['analysis_metadata'] = {
                                    'findings_analyzed': len(findings),
                                    'config_sections_provided': len(config_data) if config_data else 0,
                                    'analysis_timestamp': datetime.now().isoformat(),
                                    'cloudname': cloudname,
                                    'provider': provider_name
                                }
                            
                            return rag_response
                        else:
                            error_text = await response.text()
                            logger.error(f"RAG API error (status {response.status}): {error_text}")
                            
                            if attempt < max_retries - 1:
                                logger.info(f"Retrying RAG analysis (attempt {attempt + 2}/{max_retries})")
                                await asyncio.sleep(2)
                                continue
                            else:
                                return {}
                                
            except asyncio.TimeoutError:
                logger.error(f"RAG analysis timeout (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(3)
                    continue
                else:
                    return {}
                    
            except Exception as e:
                logger.error(f"RAG analysis request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                else:
                    return {}
        
        return {}
    
    except Exception as e:
        logger.error(f"Error in RAG cloud analysis: {str(e)}")
        logger.error(traceback.format_exc())
        return {}


async def rerank_cloud_findings(
    findings: List[Dict], 
    user_id: str, 
    account_id: str,  # noqa: unused parameter - kept for API consistency
    provider_name: str,
    rerank_url: Optional[str] = None
) -> List[Dict]:
    """
    Rerank cloud security findings using the AI reranking service.
    
    Args:
        findings: List of security findings
        user_id: User identifier
        account_id: Cloud account ID
        provider_name: Cloud provider name
        rerank_url: Optional reranking service URL
        
    Returns:
        List[Dict]: Reordered findings based on AI reranking
    """
    def extract_ids_from_llm_response(response_data: Union[Dict, List, str], original_findings: List[Dict] = None) -> Optional[List[int]]:
        """Extract IDs from LLM response text."""
        try:
            logger.info(f"Processing reranking response: {json.dumps(response_data, indent=2)}")
            
            if isinstance(response_data, dict):
                if 'llm_response' in response_data:
                    response = response_data['llm_response']
                    logger.info(f"LLM Response content: {response}")
                    
                    if not response or response == '[]':
                        logger.warning("Empty llm_response, falling back to original order")
                        return list(range(1, len(original_findings) + 1)) if original_findings else None
                        
                    if isinstance(response, list):
                        return response
                        
                    array_match = re.search(r'\[([\d,\s]+)\]', str(response))
                    if array_match:
                        id_string = array_match.group(1)
                        return [int(id.strip()) for id in id_string.split(',')]
            
            elif isinstance(response_data, list):
                if not response_data:
                    logger.warning("Empty list response")
                    return list(range(1, len(original_findings) + 1)) if original_findings else None
                return response_data
            
            logger.warning("Could not extract IDs from response")
            return list(range(1, len(original_findings) + 1)) if original_findings else None
            
        except Exception as e:
            logger.error(f"Error extracting IDs from LLM response: {str(e)}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return list(range(1, len(original_findings) + 1)) if original_findings else None

    try:
        logger.info(f"Preparing {len(findings)} {provider_name.upper()} findings for reranking")
        
        if not rerank_url:
            env_var_name = f'{provider_name.upper()}_RERANK_URL'
            rerank_url = os.getenv(env_var_name)
            if not rerank_url:
                logger.warning(f"{provider_name.upper()}_RERANK_URL environment variable not set, skipping reranking")
                return findings
        
        selected_findings = []
        
        if len(findings) <= 40:
            selected_findings = findings.copy()
            logger.info(f"Processing all {len(selected_findings)} findings (under 40 threshold)")
        else:
            failed_findings = [f for f in findings if f.get('status', '').lower() == 'alarm']
            info_findings = [f for f in findings if f.get('status', '').lower() == 'info']
            ok_findings = [f for f in findings if f.get('status', '').lower() == 'ok']
            skipped_findings = [f for f in findings if f.get('status', '').lower() == 'skip']

            remaining = 40
            for status_findings in [failed_findings, info_findings, ok_findings, skipped_findings]:
                if remaining > 0:
                    to_add = status_findings[:remaining]
                    selected_findings.extend(to_add)
                    remaining -= len(to_add)
                    
            logger.info(f"Selected {len(selected_findings)} findings based on status prioritization")

        rerank_data = {
            'findings': [{
                "ID": idx + 1,
                "category": finding.get("category", ""),
                "reason": finding.get("reason", ""),
                "severity": finding.get("severity"),
                "status": finding.get("status")
            } for idx, finding in enumerate(selected_findings)],
            'metadata': {
                'user_id': user_id,
                'provider': provider_name
            }
        }
        
        logger.info(f"Sending {len(selected_findings)} findings for reranking")
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(rerank_url, json=rerank_data, timeout=60) as response:
                    if response.status == 200:
                        rerank_response = await response.json()
                        logger.info(f"Received reranking response")
                        
                        reranked_ids = extract_ids_from_llm_response(rerank_response, selected_findings)
                        
                        if reranked_ids:
                            findings_map = {idx + 1: finding for idx, finding in enumerate(selected_findings)}
                            reordered_findings = [findings_map[id] for id in reranked_ids if id in findings_map]
                            logger.info(f"Successfully reordered {len(reordered_findings)} findings")
                            return reordered_findings
                        else:
                            logger.warning("No valid reranking IDs returned, using original order")
                            return selected_findings
                    else:
                        error_text = await response.text()
                        logger.error(f"Reranking API error (status {response.status}): {error_text}")
                        return selected_findings
            except Exception as e:
                logger.error(f"Reranking request failed: {str(e)}")
                logger.error(traceback.format_exc())
                return selected_findings
    
    except Exception as e:
        logger.error(f"Error in {provider_name.upper()} findings reranking: {str(e)}")
        logger.error(traceback.format_exc())
        return findings

