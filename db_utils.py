from urllib.parse import quote_plus
import os
import logging
from sqlalchemy import create_engine, event
from sqlalchemy.pool import QueuePool
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


def create_db_engine(database_url=None):
    """Create an optimized database engine for AWS RDS"""
    try:
        if not database_url:
            # Get credentials from environment variables
            username = quote_plus(os.getenv("DB_USERNAME", ""))
            password = quote_plus(os.getenv("DB_PASSWORD", ""))
            host = os.getenv("DB_HOST", "")
            port = os.getenv("DB_PORT", "5432")
            database = os.getenv("DB_NAME", "")

            # Validate required credentials
            if not all([username, password, host, database]):
                raise ValueError(
                    "Missing required database credentials. Please ensure DB_USERNAME, "
                    "DB_PASSWORD, DB_HOST, and DB_NAME environment variables are set."
                )

            # Construct the URL with encoded credentials
            database_url = (
                f"postgresql://{username}:{password}@{host}:{port}/{database}"
            )

        # Create engine with RDS-specific configurations
        engine = create_engine(
            database_url,
            poolclass=QueuePool,
            pool_size=20,
            max_overflow=40,
            pool_timeout=30,
            pool_recycle=300,
            pool_pre_ping=True,
            connect_args={
                "connect_timeout": 10,
                "keepalives": 1,
                "keepalives_idle": 30,
                "keepalives_interval": 10,
                "keepalives_count": 5,
            },
        )

        @event.listens_for(engine, "connect")
        def set_timeout(dbapi_connection, connection_record):
            with dbapi_connection.cursor() as cursor:
                cursor.execute("SET statement_timeout = '300000';")  # 5 minutes

        return engine

    except Exception as e:
        logger.error(f"Error creating database engine: {str(e)}")
        raise
