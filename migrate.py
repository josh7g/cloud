"""
Database migration utility using Alembic.
This replaces the old create_tables.py migration system.
"""

import os
import sys
import logging
from alembic import command
from alembic.config import Config
from app import app, db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_alembic_config():
    """Get Alembic configuration"""
    alembic_cfg = Config("alembic.ini")
    return alembic_cfg


def init_db():
    """Initialize database and run migrations"""
    with app.app_context():
        try:
            logger.info("🚀 Starting database initialization with Alembic...")

            # Get Alembic config
            alembic_cfg = get_alembic_config()

            # Run migrations to latest version
            logger.info("📋 Running database migrations...")
            command.upgrade(alembic_cfg, "head")

            logger.info("✅ Database initialization completed successfully!")

            # Log environment info
            environment = os.getenv("FLASK_ENV", "unknown")
            db_host = os.getenv("DB_HOST", "unknown")
            logger.info(
                f"📊 Migrations completed in environment: {environment}, DB: {db_host}"
            )

            return True

        except Exception as e:
            logger.error(f"❌ Error initializing database: {str(e)}")
            raise


def create_migration(message):
    """Create a new migration"""
    try:
        logger.info(f"🔧 Creating new migration: {message}")
        alembic_cfg = get_alembic_config()
        command.revision(alembic_cfg, message=message, autogenerate=True)
        logger.info("✅ Migration created successfully!")
        return True
    except Exception as e:
        logger.error(f"❌ Error creating migration: {str(e)}")
        return False


def upgrade_db(revision="head"):
    """Upgrade database to a specific revision"""
    try:
        logger.info(f"⬆️  Upgrading database to {revision}...")
        alembic_cfg = get_alembic_config()
        command.upgrade(alembic_cfg, revision)
        logger.info("✅ Database upgrade completed!")
        return True
    except Exception as e:
        logger.error(f"❌ Error upgrading database: {str(e)}")
        return False


def downgrade_db(revision):
    """Downgrade database to a specific revision"""
    try:
        logger.info(f"⬇️  Downgrading database to {revision}...")
        alembic_cfg = get_alembic_config()
        command.downgrade(alembic_cfg, revision)
        logger.info("✅ Database downgrade completed!")
        return True
    except Exception as e:
        logger.error(f"❌ Error downgrading database: {str(e)}")
        return False


def show_current_revision():
    """Show current database revision"""
    try:
        alembic_cfg = get_alembic_config()
        command.current(alembic_cfg)
        return True
    except Exception as e:
        logger.error(f"❌ Error showing current revision: {str(e)}")
        return False


def show_history():
    """Show migration history"""
    try:
        alembic_cfg = get_alembic_config()
        command.history(alembic_cfg)
        return True
    except Exception as e:
        logger.error(f"❌ Error showing history: {str(e)}")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print(
            "  python migrate.py init              - Initialize database and run migrations"
        )
        print("  python migrate.py create 'message'  - Create new migration")
        print(
            "  python migrate.py upgrade [revision] - Upgrade to revision (default: head)"
        )
        print("  python migrate.py downgrade <revision> - Downgrade to revision")
        print("  python migrate.py current           - Show current revision")
        print("  python migrate.py history           - Show migration history")
        sys.exit(1)

    command_name = sys.argv[1]

    if command_name == "init":
        init_db()
    elif command_name == "create":
        if len(sys.argv) < 3:
            print("Error: Migration message required")
            sys.exit(1)
        create_migration(sys.argv[2])
    elif command_name == "upgrade":
        revision = sys.argv[2] if len(sys.argv) > 2 else "head"
        upgrade_db(revision)
    elif command_name == "downgrade":
        if len(sys.argv) < 3:
            print("Error: Revision required for downgrade")
            sys.exit(1)
        downgrade_db(sys.argv[2])
    elif command_name == "current":
        show_current_revision()
    elif command_name == "history":
        show_history()
    else:
        print(f"Unknown command: {command_name}")
        sys.exit(1)
