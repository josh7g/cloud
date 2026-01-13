#!/usr/bin/env python3
"""
GitHub Scanner ECS Task Entry Point
"""
import os
import sys
import asyncio
import logging
from scanner import scan_repository_handler
from db_utils import create_db_engine
from models import AnalysisResult
from sqlalchemy.orm import sessionmaker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def main():
    # Get environment variables
    repo_url = os.getenv('REPO_URL')
    installation_token = os.getenv('INSTALLATION_TOKEN')
    user_id = os.getenv('USER_ID')
    analysis_id = os.getenv('ANALYSIS_ID')
    
    if not all([repo_url, installation_token, user_id, analysis_id]):
        logger.error("Missing required environment variables")
        return 1
    
    logger.info(f"Starting GitHub scan for {repo_url}")
    
    # Create DB session
    engine = create_db_engine()
    Session = sessionmaker(bind=engine)
    db_session = Session()
    
    try:
        # Get analysis record
        analysis = db_session.query(AnalysisResult).get(int(analysis_id))
        if not analysis:
            logger.error(f"Analysis {analysis_id} not found")
            return 1
        
        # Run scan
        results = await scan_repository_handler(
            repo_url=repo_url,
            installation_token=installation_token,
            user_id=user_id,
            db_session=db_session,
            analysis_record=analysis,
        )
        
        if results.get('success'):
            logger.info("Scan completed successfully")
            return 0
        else:
            logger.error(f"Scan failed: {results.get('error')}")
            return 1
            
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1
    finally:
        db_session.close()
        engine.dispose()

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))