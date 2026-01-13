from app import app, db
from sqlalchemy import text, DDL
import logging
import os

# from zap_scanner import ZapDockerScanner
import asyncio
from typing import Dict


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def check_table_exists(table_name):
    """Check if a table exists in the database"""
    with app.app_context():
        result = db.session.execute(
            text(
                """
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public'
                AND table_name = :table_name
            );
        """
            ),
            {"table_name": table_name},
        )
        return result.scalar()


def verify_all_tables():
    """Check status of all migrations"""
    tables_to_check = [
        "analysis_results",
        "azure_devops_analysis_results",
        "github_analysis_results",
        "gitlab_scan_results",  # Changed from gitlab_analysis_results
        "cloud_scans",
        "ignored_findings",
    ]

    for table in tables_to_check:
        exists = check_table_exists(table)
        print(f"Table {table}: {'EXISTS' if exists else 'MISSING'}")

        if exists and table == "gitlab_scan_results":
            has_repo_name = check_column_exists(table, "repository_name")
            print(
                f"  - repository_name column: {'EXISTS' if has_repo_name else 'MISSING'}"
            )


def ensure_column_exists(
    table_name, column_name, column_type, default_value=None, nullable=True
):
    """
    Ensure a column exists in a table, add it if missing.

    Args:
        table_name: Name of the table
        column_name: Name of the column
        column_type: SQL type (e.g., 'VARCHAR(255)', 'INTEGER', 'JSONB', 'TEXT')
        default_value: Default value for the column (optional)
        nullable: Whether the column can be NULL

    Returns:
        True if column was added, False if it already existed
    """
    with app.app_context():
        if not check_column_exists(table_name, column_name):
            logger.info(f"Adding {column_name} column to {table_name}...")

            # For NOT NULL columns with defaults, add as nullable first, then update, then set NOT NULL
            if not nullable and default_value is not None:
                # Step 1: Add column as nullable with default
                alter_stmt = f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {column_type} DEFAULT {default_value}"
                db.session.execute(DDL(alter_stmt))

                # Step 2: Update any NULL values (for safety, though default should prevent this)
                update_stmt = f"UPDATE {table_name} SET {column_name} = {default_value} WHERE {column_name} IS NULL"
                db.session.execute(DDL(update_stmt))

                # Step 3: Set NOT NULL constraint
                not_null_stmt = (
                    f"ALTER TABLE {table_name} ALTER COLUMN {column_name} SET NOT NULL"
                )
                db.session.execute(DDL(not_null_stmt))
            else:
                # Build ALTER TABLE statement for nullable or no-default columns
                alter_stmt = f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {column_name} {column_type}"

                if default_value is not None:
                    alter_stmt += f" DEFAULT {default_value}"

                if not nullable:
                    alter_stmt += " NOT NULL"

                db.session.execute(DDL(alter_stmt))

                # If we added a column with a default, update existing NULL rows
                if default_value is not None:
                    update_stmt = f"UPDATE {table_name} SET {column_name} = {default_value} WHERE {column_name} IS NULL"
                    db.session.execute(DDL(update_stmt))

            db.session.commit()
            logger.info(f"âœ… Added {column_name} column to {table_name}")
            return True
        else:
            logger.info(f"âœ… Column {column_name} already exists in {table_name}")
            return False


def ensure_index_exists(index_name, table_name, columns, unique=False):
    """
    Ensure an index exists, create it if missing.

    Args:
        index_name: Name of the index
        table_name: Name of the table
        columns: List of column names or single column name
        unique: Whether this is a unique index
    """
    with app.app_context():
        if not check_index_exists(index_name):
            if isinstance(columns, str):
                columns = [columns]

            cols_str = ", ".join(columns)
            unique_str = "UNIQUE" if unique else ""

            create_stmt = f"""
                CREATE {unique_str} INDEX IF NOT EXISTS {index_name} 
                ON {table_name} ({cols_str})
            """

            db.session.execute(DDL(create_stmt))
            db.session.commit()
            logger.info(f"âœ… Created index {index_name}")
            return True
        else:
            logger.info(f"âœ… Index {index_name} already exists")
            return False


def ensure_all_columns_and_indexes():
    """
    Comprehensive function to ensure all tables have all required columns and indexes.
    This is the single source of truth for the database schema.
    """
    with app.app_context():
        try:
            logger.info(
                "ðŸ” Ensuring all columns and indexes exist across all tables..."
            )

            # ============================================
            # IGNORED_FINDINGS TABLE
            # ============================================
            if check_table_exists("ignored_findings"):
                logger.info("Checking ignored_findings table...")
                ensure_column_exists("ignored_findings", "cwe_id", "VARCHAR(20)")
                ensure_column_exists("ignored_findings", "workspace_id", "VARCHAR(24)")
                ensure_column_exists("ignored_findings", "repo_type", "VARCHAR(50)")
                ensure_column_exists(
                    "ignored_findings",
                    "worksheet_number",
                    "INTEGER",
                    default_value=1,
                    nullable=False,
                )

                # Indexes
                ensure_index_exists(
                    "idx_ignore_lookup",
                    "ignored_findings",
                    ["user_id", "repo_name", "ignore_type", "finding_id", "file_path"],
                )
                ensure_index_exists(
                    "idx_cwe_lookup",
                    "ignored_findings",
                    ["user_id", "repo_name", "ignore_type", "cwe_id", "file_path"],
                )
                ensure_index_exists(
                    "idx_user_repo", "ignored_findings", ["user_id", "repo_name"]
                )
                ensure_index_exists(
                    "idx_ignore_user_worksheet",
                    "ignored_findings",
                    ["user_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_ignore_user_repo_worksheet",
                    "ignored_findings",
                    ["user_id", "repo_name", "worksheet_number"],
                )

            # ============================================
            # ANALYSIS_RESULTS TABLE
            # ============================================
            if check_table_exists("analysis_results"):
                logger.info("Checking analysis_results table...")
                ensure_column_exists("analysis_results", "user_id", "VARCHAR(255)")
                ensure_column_exists("analysis_results", "rerank", "JSONB")
                ensure_column_exists(
                    "analysis_results", "worksheet_number", "INTEGER", default_value=1
                )
                ensure_column_exists("analysis_results", "workspace_id", "VARCHAR(24)")

                # Indexes
                ensure_index_exists(
                    "ix_analysis_results_user_id", "analysis_results", "user_id"
                )
                ensure_index_exists(
                    "ix_analysis_results_user_worksheet",
                    "analysis_results",
                    ["user_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "ix_analysis_results_repo_user",
                    "analysis_results",
                    ["repository_name", "user_id"],
                )
                ensure_index_exists(
                    "idx_analysis_results_user_workspace_id",
                    "analysis_results",
                    ["user_id", "workspace_id"],
                )
                ensure_index_exists(
                    "idx_analysis_results_user_workspace_worksheet",
                    "analysis_results",
                    ["user_id", "workspace_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_analysis_results_workspace_id",
                    "analysis_results",
                    "workspace_id",
                )

            # ============================================
            # AZURE_DEVOPS_ANALYSIS_RESULTS TABLE
            # ============================================
            if check_table_exists("azure_devops_analysis_results"):
                logger.info("Checking azure_devops_analysis_results table...")
                ensure_column_exists(
                    "azure_devops_analysis_results", "user_id", "VARCHAR(255)"
                )
                ensure_column_exists("azure_devops_analysis_results", "rerank", "JSONB")
                ensure_column_exists(
                    "azure_devops_analysis_results",
                    "worksheet_number",
                    "INTEGER",
                    default_value=1,
                )
                ensure_column_exists(
                    "azure_devops_analysis_results", "workspace_id", "VARCHAR(24)"
                )

                # Indexes
                ensure_index_exists(
                    "idx_azure_org_project_repo",
                    "azure_devops_analysis_results",
                    ["organization_name", "project_name", "repository_name"],
                )
                ensure_index_exists(
                    "idx_azure_user_org",
                    "azure_devops_analysis_results",
                    ["user_id", "organization_name"],
                )
                ensure_index_exists(
                    "idx_azure_user_worksheet",
                    "azure_devops_analysis_results",
                    ["user_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_azure_user_org_worksheet",
                    "azure_devops_analysis_results",
                    ["user_id", "organization_name", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_azure_user_project_worksheet",
                    "azure_devops_analysis_results",
                    ["user_id", "project_name", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_azure_user_workspace_id",
                    "azure_devops_analysis_results",
                    ["user_id", "workspace_id"],
                )
                ensure_index_exists(
                    "idx_azure_user_workspace_worksheet",
                    "azure_devops_analysis_results",
                    ["user_id", "workspace_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_azure_workspace_id",
                    "azure_devops_analysis_results",
                    "workspace_id",
                )

            # ============================================
            # GITHUB_ANALYSIS_RESULTS TABLE
            # ============================================
            if check_table_exists("github_analysis_results"):
                logger.info("Checking github_analysis_results table...")
                ensure_column_exists(
                    "github_analysis_results", "user_id", "VARCHAR(255)"
                )
                ensure_column_exists("github_analysis_results", "rerank", "JSONB")
                ensure_column_exists(
                    "github_analysis_results",
                    "worksheet_number",
                    "INTEGER",
                    default_value=1,
                )
                ensure_column_exists(
                    "github_analysis_results", "repository_url", "VARCHAR(500)"
                )
                ensure_column_exists(
                    "github_analysis_results", "branch_name", "VARCHAR(255)"
                )

                # Indexes
                ensure_index_exists(
                    "idx_github_owner_repo",
                    "github_analysis_results",
                    ["repository_owner", "repository_name"],
                )
                ensure_index_exists(
                    "idx_github_user_owner",
                    "github_analysis_results",
                    ["user_id", "repository_owner"],
                )
                ensure_index_exists(
                    "idx_github_user_worksheet",
                    "github_analysis_results",
                    ["user_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_github_user_owner_worksheet",
                    "github_analysis_results",
                    ["user_id", "repository_owner", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_github_repo_user",
                    "github_analysis_results",
                    ["repository_name", "user_id"],
                )
                ensure_index_exists(
                    "idx_github_status", "github_analysis_results", "status"
                )

            # ============================================
            # GITLAB_SCAN_RESULTS TABLE
            # ============================================
            if check_table_exists("gitlab_scan_results"):
                logger.info("Checking gitlab_scan_results table...")
                ensure_column_exists(
                    "gitlab_scan_results", "repository_name", "VARCHAR(255)"
                )
                ensure_column_exists("gitlab_scan_results", "user_id", "VARCHAR(255)")
                ensure_column_exists("gitlab_scan_results", "rerank", "JSONB")
                ensure_column_exists("gitlab_scan_results", "workspace", "VARCHAR(24)")
                ensure_column_exists(
                    "gitlab_scan_results", "gitlab_instance_url", "VARCHAR(500)"
                )
                ensure_column_exists(
                    "gitlab_scan_results", "branch_name", "VARCHAR(255)"
                )

                # Indexes
                ensure_index_exists(
                    "idx_gitlab_scan_project_id", "gitlab_scan_results", "project_id"
                )
                ensure_index_exists(
                    "idx_gitlab_scan_project_path",
                    "gitlab_scan_results",
                    "project_path",
                )
                ensure_index_exists(
                    "idx_gitlab_scan_user_project",
                    "gitlab_scan_results",
                    ["user_id", "project_id"],
                )
                ensure_index_exists(
                    "idx_gitlab_scan_user_workspace",
                    "gitlab_scan_results",
                    ["user_id", "workspace"],
                )
                ensure_index_exists(
                    "idx_gitlab_scan_user_project_workspace",
                    "gitlab_scan_results",
                    ["user_id", "project_id", "workspace"],
                )
                ensure_index_exists(
                    "idx_gitlab_scan_repo_user",
                    "gitlab_scan_results",
                    ["repository_name", "user_id"],
                )
                ensure_index_exists(
                    "idx_gitlab_scan_status", "gitlab_scan_results", "status"
                )

            # ============================================
            # CLOUD_SCANS TABLE
            # ============================================
            if check_table_exists("cloud_scans"):
                logger.info("Checking cloud_scans table...")
                ensure_column_exists("cloud_scans", "completed_at", "TIMESTAMP")
                ensure_column_exists("cloud_scans", "error", "TEXT")
                ensure_column_exists("cloud_scans", "cloudname", "VARCHAR(255)")
                ensure_column_exists(
                    "cloud_scans", "worksheet_number", "INTEGER", default_value=1
                )
                ensure_column_exists("cloud_scans", "rerank", "JSONB")

                # Indexes
                ensure_index_exists("idx_cloud_scans_user_id", "cloud_scans", "user_id")
                ensure_index_exists(
                    "idx_cloud_scans_user_cloudname",
                    "cloud_scans",
                    ["user_id", "cloudname"],
                )
                ensure_index_exists(
                    "idx_cloud_scans_user_worksheet",
                    "cloud_scans",
                    ["user_id", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_cloud_scans_user_cloudname_worksheet",
                    "cloud_scans",
                    ["user_id", "cloudname", "worksheet_number"],
                )
                ensure_index_exists(
                    "idx_cloud_scans_provider", "cloud_scans", "cloud_provider"
                )
                ensure_index_exists("idx_cloud_scans_status", "cloud_scans", "status")

            # ============================================
            # REPOSITORY_SCAN_RESULTS TABLE
            # ============================================
            if check_table_exists("repository_scan_results"):
                logger.info("Checking repository_scan_results table...")
                ensure_column_exists(
                    "repository_scan_results", "user_id", "VARCHAR(255)"
                )
                ensure_column_exists(
                    "repository_scan_results", "workspace_id", "VARCHAR(24)"
                )
                ensure_column_exists(
                    "repository_scan_results", "branch_name", "VARCHAR(255)"
                )
                ensure_column_exists("repository_scan_results", "rerank", "JSONB")

                # Indexes
                ensure_index_exists(
                    "idx_repo_type_identifier",
                    "repository_scan_results",
                    ["repo_type", "repo_identifier"],
                )
                ensure_index_exists(
                    "idx_repo_user_type",
                    "repository_scan_results",
                    ["user_id", "repo_type"],
                )
                ensure_index_exists(
                    "idx_repo_user_workspace",
                    "repository_scan_results",
                    ["user_id", "workspace_id"],
                )
                ensure_index_exists(
                    "idx_repo_workspace_id", "repository_scan_results", "workspace_id"
                )
                ensure_index_exists(
                    "idx_repo_status", "repository_scan_results", "status"
                )
                ensure_index_exists(
                    "idx_repo_timestamp", "repository_scan_results", "timestamp"
                )

            logger.info("âœ… All columns and indexes verified and updated!")
            # ============================================
            # FIX_REQUESTS TABLE
            # ============================================
            logger.info("Checking fix_requests table...")
            # Create table if it doesn't exist
            if not check_table_exists("fix_requests"):
                logger.info("Creating fix_requests table...")
                db.session.execute(
                    text(
                        """
                    CREATE TABLE fix_requests (
                        id SERIAL PRIMARY KEY,
                        user_id VARCHAR(255) NOT NULL,
                        workspace_id VARCHAR(24),
                        repo_type VARCHAR(50) NOT NULL,
                        repo_identifier VARCHAR(512) NOT NULL,
                        branch_name VARCHAR(255) DEFAULT 'main',
                        finding_id VARCHAR(255) NOT NULL,
                        file_path VARCHAR(500) NOT NULL,
                        line_start INTEGER,
                        cwe_id VARCHAR(200),
                        severity VARCHAR(50),
                        pr_url VARCHAR(500),
                        pr_number VARCHAR(50),
                        pr_title VARCHAR(500),
                        status VARCHAR(50) DEFAULT 'pending',
                        fix_description TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        pr_created_at TIMESTAMP WITH TIME ZONE,
                        pr_merged_at TIMESTAMP WITH TIME ZONE,
                        pr_closed_at TIMESTAMP WITH TIME ZONE,
                        error TEXT,
                        additional_data JSONB,
                        webhook_url VARCHAR(500)
                    )
                """
                    )
                )
                db.session.commit()
                logger.info("✅ Created fix_requests table")

            if check_table_exists("fix_requests"):
                # Ensure all columns exist
                ensure_column_exists("fix_requests", "user_id", "VARCHAR(255)")
                ensure_column_exists("fix_requests", "workspace_id", "VARCHAR(24)")
                ensure_column_exists("fix_requests", "repo_type", "VARCHAR(50)")
                ensure_column_exists("fix_requests", "repo_identifier", "VARCHAR(512)")
                ensure_column_exists("fix_requests", "branch_name", "VARCHAR(255)")
                ensure_column_exists(
                    "fix_requests", "finding_id", "VARCHAR(255)"
                )  # Reduced from 512
                ensure_column_exists("fix_requests", "file_path", "VARCHAR(500)")
                ensure_column_exists(
                    "fix_requests", "line_start", "INTEGER"
                )  # NEW: Line number column
                ensure_column_exists("fix_requests", "cwe_id", "VARCHAR(200)")
                ensure_column_exists("fix_requests", "severity", "VARCHAR(50)")
                ensure_column_exists("fix_requests", "pr_url", "VARCHAR(500)")
                ensure_column_exists("fix_requests", "pr_number", "VARCHAR(50)")
                ensure_column_exists("fix_requests", "pr_title", "VARCHAR(500)")
                ensure_column_exists("fix_requests", "status", "VARCHAR(50)")
                ensure_column_exists("fix_requests", "fix_description", "TEXT")
                ensure_column_exists(
                    "fix_requests", "created_at", "TIMESTAMP WITH TIME ZONE"
                )
                ensure_column_exists(
                    "fix_requests", "updated_at", "TIMESTAMP WITH TIME ZONE"
                )
                ensure_column_exists(
                    "fix_requests", "pr_created_at", "TIMESTAMP WITH TIME ZONE"
                )
                ensure_column_exists(
                    "fix_requests", "pr_merged_at", "TIMESTAMP WITH TIME ZONE"
                )
                ensure_column_exists(
                    "fix_requests", "pr_closed_at", "TIMESTAMP WITH TIME ZONE"
                )
                ensure_column_exists("fix_requests", "error", "TEXT")
                ensure_column_exists("fix_requests", "additional_data", "JSONB")
                ensure_column_exists("fix_requests", "webhook_url", "VARCHAR(500)")

                # MIGRATION: Parse composite finding_id values and extract line_start
                logger.info("Migrating composite finding_id values...")
                migrate_composite_finding_ids()

                # Indexes - updated to include line_start in composite index
                ensure_index_exists(
                    "idx_fix_request_user_id", "fix_requests", "user_id"
                )
                ensure_index_exists(
                    "idx_fix_request_workspace", "fix_requests", "workspace_id"
                )
                ensure_index_exists(
                    "idx_fix_request_user_workspace",
                    "fix_requests",
                    ["user_id", "workspace_id"],
                )
                ensure_index_exists(
                    "idx_fix_request_repo",
                    "fix_requests",
                    ["repo_type", "repo_identifier"],
                )
                # Updated index to include line_start for efficient lookups
                ensure_index_exists(
                    "idx_fix_request_finding",
                    "fix_requests",
                    ["finding_id", "file_path", "line_start"],
                )
                ensure_index_exists("idx_fix_request_status", "fix_requests", "status")
                ensure_index_exists(
                    "idx_fix_request_pr_number",
                    "fix_requests",
                    ["repo_identifier", "pr_number"],
                )

            logger.info("✅ All columns and indexes verified and updated!")
            return True

        except Exception as e:
            logger.error(f"âŒ Error ensuring columns and indexes: {str(e)}")
            db.session.rollback()
            return False

    """Check status of all migrations"""
    tables_to_check = [
        "analysis_results",
        "azure_devops_analysis_results",
        "github_analysis_results",
        "gitlab_scan_results",  # Changed from gitlab_analysis_results
        "cloud_scans",
        "ignored_findings",
    ]

    for table in tables_to_check:
        exists = check_table_exists(table)
        print(f"Table {table}: {'EXISTS' if exists else 'MISSING'}")

        if exists and table == "gitlab_scan_results":
            has_repo_name = check_column_exists(table, "repository_name")
            print(
                f"  - repository_name column: {'EXISTS' if has_repo_name else 'MISSING'}"
            )


def check_column_exists(table_name, column_name):
    """Check if a column exists in a table"""
    with app.app_context():
        result = db.session.execute(
            text(
                """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = :table_name AND column_name = :column_name
        """
            ),
            {"table_name": table_name, "column_name": column_name},
        )
        return bool(result.scalar())


def check_index_exists(index_name):
    """Check if an index exists in the database"""
    with app.app_context():
        result = db.session.execute(
            text(
                """
            SELECT EXISTS (
                SELECT FROM pg_indexes 
                WHERE indexname = :index_name
            );
        """
            ),
            {"index_name": index_name},
        )
        return result.scalar()


def run_ignore_migration():
    """Run the ignore migration with CWE support - creates table or adds missing columns"""
    with app.app_context():
        try:
            # Check if table already exists
            if check_table_exists("ignored_findings"):
                logger.info("âœ… Ignored findings table already exists")
                # Column additions are now handled by ensure_all_columns_and_indexes()
                return True

            logger.info(
                "ðŸš€ Running ignore migration with CWE support for the first time..."
            )

            # Create the ignored_findings table with CWE support
            db.session.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS ignored_findings (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    repo_name VARCHAR(255) NOT NULL,
                    ignore_type VARCHAR(20) NOT NULL DEFAULT 'finding',
                    finding_id VARCHAR(255),
                    file_path VARCHAR(500),
                    code_snippet TEXT,
                    cwe_id VARCHAR(20),
                    workspace_id VARCHAR(24),
                    repo_type VARCHAR(50),
                    reason TEXT,
                    ignored_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ignored_by VARCHAR(255),
                    worksheet_number INTEGER NOT NULL DEFAULT 1
                );
            """
                )
            )

            # Create indexes (IF NOT EXISTS prevents errors on re-run)
            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_ignore_lookup 
                ON ignored_findings (user_id, repo_name, ignore_type, finding_id, file_path);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_cwe_lookup 
                ON ignored_findings (user_id, repo_name, ignore_type, cwe_id, file_path);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_user_repo 
                ON ignored_findings (user_id, repo_name);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_ignore_user_worksheet 
                ON ignored_findings (user_id, worksheet_number);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_ignore_user_repo_worksheet 
                ON ignored_findings (user_id, repo_name, worksheet_number);
            """
                )
            )

            db.session.commit()
            logger.info("âœ… Ignore migration with CWE support completed successfully!")

            # Log environment info for audit trail
            environment = os.getenv("FLASK_ENV", "unknown")
            db_host = os.getenv("DB_HOST", "unknown")
            logger.info(
                f"ðŸ“Š Migration completed in environment: {environment}, DB: {db_host}"
            )

            return True

        except Exception as e:
            logger.error(f"âŒ Ignore migration failed: {str(e)}")
            db.session.rollback()
            # Don't raise - let the app continue to start
            return False


async def backfill_workspace_ids():
    """
    Backfill workspace_id for existing analysis_results records using DASHBOARD_URL/v1/customer endpoint
    """
    with app.app_context():
        try:
            logger.info("ðŸ”„ Starting workspace_id backfill process...")

            # Get DASHBOARD_URL from environment
            dashboard_url = os.getenv("DASHBOARD_URL")
            if not dashboard_url:
                logger.error("DASHBOARD_URL environment variable not set")
                return False

            customer_endpoint = f"{dashboard_url.rstrip('/')}/v1/customer"
            logger.info(f"Using customer endpoint: {customer_endpoint}")

            # Get all records with NULL workspace_id
            null_workspace_records = db.session.execute(
                text(
                    """
                SELECT id, user_id 
                FROM analysis_results 
                WHERE workspace_id IS NULL 
                AND user_id IS NOT NULL
            """
                )
            ).fetchall()

            logger.info(f"Found {len(null_workspace_records)} records to backfill")

            if not null_workspace_records:
                logger.info("No records need backfilling")
                return True

            # Get unique user_ids to minimize processing
            unique_user_ids = list(
                set(record.user_id for record in null_workspace_records)
            )
            logger.info(f"Processing {len(unique_user_ids)} unique users")

            # Fetch all customers from the endpoint (single API call)
            user_workspace_mapping = {}
            failed_users = []

            import aiohttp

            async with aiohttp.ClientSession() as session:
                try:
                    logger.info("Fetching all customers from endpoint...")
                    async with session.get(customer_endpoint) as response:
                        if response.status == 200:
                            data = await response.json()
                            customers = data.get("customers", [])
                            logger.info(
                                f"Retrieved {len(customers)} customers from API"
                            )

                            # Create mapping from the customers data
                            for customer in customers:
                                user_id = customer.get("userId")
                                current_workspace = customer.get("currentWorkspace")

                                if user_id and current_workspace:
                                    # Only map users that we actually need to update
                                    if user_id in unique_user_ids:
                                        user_workspace_mapping[user_id] = (
                                            current_workspace
                                        )
                                        logger.info(
                                            f"Mapped user {user_id} to workspace {current_workspace}"
                                        )

                            # Track users not found in the customer data
                            found_user_ids = set(user_workspace_mapping.keys())
                            not_found_user_ids = set(unique_user_ids) - found_user_ids
                            if not_found_user_ids:
                                logger.warning(
                                    f"Could not find workspace mapping for {len(not_found_user_ids)} users: {list(not_found_user_ids)}"
                                )
                                failed_users.extend(not_found_user_ids)

                        else:
                            error_text = await response.text()
                            logger.error(
                                f"Failed to fetch customers: HTTP {response.status} - {error_text}"
                            )
                            return False

                except Exception as e:
                    logger.error(f"Error fetching customers: {str(e)}")
                    return False

            if not user_workspace_mapping:
                logger.warning("No user-workspace mappings found")
                return False

            # Update records in database
            successful_updates = 0

            for user_id, workspace_id in user_workspace_mapping.items():
                try:
                    result = db.session.execute(
                        text(
                            """
                        UPDATE analysis_results 
                        SET workspace_id = :workspace_id 
                        WHERE user_id = :user_id AND workspace_id IS NULL
                    """
                        ),
                        {"workspace_id": workspace_id, "user_id": user_id},
                    )

                    updated_count = result.rowcount
                    successful_updates += updated_count
                    logger.info(
                        f"Updated {updated_count} records for user {user_id} -> workspace {workspace_id}"
                    )

                except Exception as e:
                    logger.error(
                        f"Failed to update records for user {user_id}: {str(e)}"
                    )
                    failed_users.append(user_id)

            # Commit all updates
            db.session.commit()

            logger.info(f"âœ… Backfill completed successfully!")
            logger.info(f"ðŸ“Š Statistics:")
            logger.info(f"   - Records updated: {successful_updates}")
            logger.info(f"   - Users mapped: {len(user_workspace_mapping)}")
            logger.info(f"   - Users failed: {len(failed_users)}")

            if failed_users:
                logger.warning(f"âŒ Failed to process users: {failed_users}")

            return True

        except Exception as e:
            logger.error(f"âŒ Workspace backfill failed: {str(e)}")
            db.session.rollback()
            return False


def add_analysis_results_workspace_column():
    """Add workspace_id column to analysis_results table"""
    with app.app_context():
        try:
            # Check if workspace_id column exists
            if not check_column_exists("analysis_results", "workspace_id"):
                logger.info("Adding workspace_id column to analysis_results...")

                # Add the workspace_id column as UUID type
                db.session.execute(
                    text(
                        """
                    ALTER TABLE analysis_results 
                    ADD COLUMN IF NOT EXISTS workspace_id UUID
                """
                    )
                )

                # Add index for workspace queries
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_analysis_results_user_workspace_id
                    ON analysis_results (user_id, workspace_id)
                """
                    )
                )

                # Add composite index for user + workspace + worksheet queries
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_analysis_results_user_workspace_worksheet
                    ON analysis_results (user_id, workspace_id, worksheet_number)
                """
                    )
                )

                # Add index for workspace-only queries
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_analysis_results_workspace_id
                    ON analysis_results (workspace_id)
                """
                    )
                )

                db.session.commit()
                logger.info(
                    "Successfully added workspace_id column to analysis_results"
                )
                return True
            else:
                logger.info("workspace_id column already exists in analysis_results")
                return True

        except Exception as e:
            logger.error(
                f"Error adding workspace_id column to analysis_results: {str(e)}"
            )
            db.session.rollback()
            return False


def add_scanned_commit_sha_column():
    """Add scanned_commit_sha column to analysis_results table if it doesn't exist"""
    with app.app_context():
        try:
            result = db.session.execute(
                text(
                    """
                SELECT column_name FROM information_schema.columns 
                WHERE table_name='analysis_results' AND column_name='scanned_commit_sha'
                """
                )
            )
            if not bool(result.scalar()):
                logger.info("Adding scanned_commit_sha column to analysis_results...")
                db.session.execute(
                    text(
                        """
                    ALTER TABLE analysis_results 
                    ADD COLUMN IF NOT EXISTS scanned_commit_sha VARCHAR(64)
                    """
                    )
                )
                db.session.commit()
                logger.info(
                    "Successfully added scanned_commit_sha column to analysis_results"
                )
                return True
            else:
                logger.info(
                    "scanned_commit_sha column already exists in analysis_results"
                )
                return True
        except Exception as e:
            logger.error(f"Error adding scanned_commit_sha column: {str(e)}")
            db.session.rollback()
            return False


def run_analysis_results_workspace_migration():
    """Run the analysis_results workspace migration if it hasn't been run yet"""
    with app.app_context():
        try:
            # Check if the table exists first
            if not check_table_exists("analysis_results"):
                logger.warning("analysis_results table does not exist yet")
                return False
            logger.info("ðŸš€ Running analysis_results workspace migration...")
            success = add_analysis_results_workspace_column()

            sha_col_success = add_scanned_commit_sha_column()
            if success and sha_col_success:
                logger.info(
                    "âœ… Analysis results workspace & scanned_commit_sha migration completed successfully!"
                )
                logger.info(
                    "ðŸ“ Note: Run backfill_workspace_ids() after providing the workspace endpoint"
                )
                environment = os.getenv("FLASK_ENV", "unknown")
                db_host = os.getenv("DB_HOST", "unknown")
                logger.info(
                    f"ðŸ“Š Migration completed in environment: {environment}, DB: {db_host}"
                )
                return True
            else:
                logger.error(
                    "âŒ Analysis results workspace or scanned_commit_sha migration failed"
                )
                return False
        except Exception as e:
            logger.error(
                f"âŒ Analysis results workspace/sha migration failed: {str(e)}"
            )
            db.session.rollback()
            return False


def run_azure_devops_migration():
    """Run the Azure DevOps migration if it hasn't been run yet"""
    with app.app_context():
        try:
            # Check if migration already completed
            if check_table_exists("azure_devops_analysis_results"):
                logger.info(
                    "âœ… Azure DevOps migration already completed, checking columns..."
                )

                # Check if worksheet_number column exists, add if missing
                if not check_column_exists(
                    "azure_devops_analysis_results", "worksheet_number"
                ):
                    logger.info(
                        "Adding worksheet_number column to azure_devops_analysis_results..."
                    )
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE azure_devops_analysis_results 
                        ADD COLUMN IF NOT EXISTS worksheet_number INTEGER DEFAULT 1
                    """
                        )
                    )

                    # Set default value for existing records
                    db.session.execute(
                        text(
                            """
                        UPDATE azure_devops_analysis_results 
                        SET worksheet_number = 1 
                        WHERE worksheet_number IS NULL
                    """
                        )
                    )

                    # Add new indexes
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_user_worksheet 
                        ON azure_devops_analysis_results (user_id, worksheet_number)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_user_org_worksheet 
                        ON azure_devops_analysis_results (user_id, organization_name, worksheet_number)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_user_project_worksheet 
                        ON azure_devops_analysis_results (user_id, project_name, worksheet_number)
                    """
                        )
                    )

                    db.session.commit()
                    logger.info(
                        "Added worksheet_number column to azure_devops_analysis_results"
                    )

                # NEW: Check if workspace_id column exists, add if missing
                if not check_column_exists(
                    "azure_devops_analysis_results", "workspace_id"
                ):
                    logger.info(
                        "Adding workspace_id column to azure_devops_analysis_results..."
                    )
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE azure_devops_analysis_results 
                        ADD COLUMN IF NOT EXISTS workspace_id VARCHAR(24)
                    """
                        )
                    )

                    # Add new indexes for workspace support
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_user_workspace_id 
                        ON azure_devops_analysis_results (user_id, workspace_id)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_user_workspace_worksheet 
                        ON azure_devops_analysis_results (user_id, workspace_id, worksheet_number)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_workspace_id 
                        ON azure_devops_analysis_results (workspace_id)
                    """
                        )
                    )

                    db.session.commit()
                    logger.info(
                        "Added workspace_id column to azure_devops_analysis_results"
                    )
                else:
                    logger.info(
                        "âœ… workspace_id column already exists in azure_devops_analysis_results"
                    )

                if not check_column_exists(
                    "azure_devops_analysis_results", "scanned_commit_sha"
                ):
                    logger.info(
                        "Adding scanned_commit_sha column to azure_devops_analysis_results..."
                    )
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE azure_devops_analysis_results 
                        ADD COLUMN IF NOT EXISTS scanned_commit_sha VARCHAR(64)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_azure_scanned_commit_sha 
                        ON azure_devops_analysis_results (scanned_commit_sha)
                    """
                        )
                    )

                    db.session.commit()
                    logger.info(
                        "Added scanned_commit_sha column to azure_devops_analysis_results"
                    )
                else:
                    logger.info(
                        "âœ… scanned_commit_sha column already exists in azure_devops_analysis_results"
                    )

                return True

            logger.info("ðŸš€ Running Azure DevOps migration for the first time...")

            # Create the azure_devops_analysis_results table with workspace_id
            db.session.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS azure_devops_analysis_results (
                    id SERIAL PRIMARY KEY,
                    repository_name VARCHAR(255) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'pending',
                    results JSONB,
                    error TEXT,
                    user_id VARCHAR(255),
                    rerank JSONB,
                    organization_name VARCHAR(255) NOT NULL,
                    project_name VARCHAR(255) NOT NULL,
                    worksheet_number INTEGER NOT NULL DEFAULT 1,
                    workspace_id VARCHAR(24),
                    scanned_commit_sha VARCHAR(64)
                );
            """
                )
            )

            # Create indexes
            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_org_project_repo 
                ON azure_devops_analysis_results (organization_name, project_name, repository_name);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_user_org 
                ON azure_devops_analysis_results (user_id, organization_name);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_user_worksheet 
                ON azure_devops_analysis_results (user_id, worksheet_number);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_user_org_worksheet 
                ON azure_devops_analysis_results (user_id, organization_name, worksheet_number);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_user_project_worksheet 
                ON azure_devops_analysis_results (user_id, project_name, worksheet_number);
            """
                )
            )

            # NEW: Add workspace indexes
            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_user_workspace_id 
                ON azure_devops_analysis_results (user_id, workspace_id);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_user_workspace_worksheet 
                ON azure_devops_analysis_results (user_id, workspace_id, worksheet_number);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_workspace_id 
                ON azure_devops_analysis_results (workspace_id);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_azure_scanned_commit_sha 
                ON azure_devops_analysis_results (scanned_commit_sha);
            """
                )
            )

            db.session.commit()
            logger.info("âœ… Azure DevOps migration completed successfully!")

            return True

        except Exception as e:
            logger.error(f"âŒ Azure DevOps migration failed: {str(e)}")
            db.session.rollback()
            return False


def run_github_migration():
    """Run the GitHub migration if it hasn't been run yet"""
    with app.app_context():
        try:
            # Check if migration already completed
            if check_table_exists("github_analysis_results"):
                logger.info(
                    "âœ… GitHub migration already completed, checking columns..."
                )

                # Check if worksheet_number column exists, add if missing
                if not check_column_exists(
                    "github_analysis_results", "worksheet_number"
                ):
                    logger.info(
                        "Adding worksheet_number column to github_analysis_results..."
                    )
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE github_analysis_results 
                        ADD COLUMN IF NOT EXISTS worksheet_number INTEGER DEFAULT 1
                    """
                        )
                    )

                    # Set default value for existing records
                    db.session.execute(
                        text(
                            """
                        UPDATE github_analysis_results 
                        SET worksheet_number = 1 
                        WHERE worksheet_number IS NULL
                    """
                        )
                    )

                    # Add new indexes
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_github_user_worksheet 
                        ON github_analysis_results (user_id, worksheet_number)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_github_user_owner_worksheet 
                        ON github_analysis_results (user_id, repository_owner, worksheet_number)
                    """
                        )
                    )

                    db.session.commit()
                    logger.info(
                        "Added worksheet_number column to github_analysis_results"
                    )

                return True

            logger.info("ðŸš€ Running GitHub migration for the first time...")

            # Create the github_analysis_results table
            db.session.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS github_analysis_results (
                    id SERIAL PRIMARY KEY,
                    repository_name VARCHAR(255) NOT NULL,
                    repository_owner VARCHAR(255) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'pending',
                    results JSONB,
                    error TEXT,
                    user_id VARCHAR(255),
                    rerank JSONB,
                    worksheet_number INTEGER NOT NULL DEFAULT 1,
                    repository_url VARCHAR(500),
                    branch_name VARCHAR(255) DEFAULT 'main'
                );
            """
                )
            )

            # Create indexes
            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_github_owner_repo 
                ON github_analysis_results (repository_owner, repository_name);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_github_user_owner 
                ON github_analysis_results (user_id, repository_owner);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_github_user_worksheet 
                ON github_analysis_results (user_id, worksheet_number);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_github_user_owner_worksheet 
                ON github_analysis_results (user_id, repository_owner, worksheet_number);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_github_repo_user 
                ON github_analysis_results (repository_name, user_id);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_github_status 
                ON github_analysis_results (status);
            """
                )
            )

            db.session.commit()
            logger.info("âœ… GitHub migration completed successfully!")

            return True

        except Exception as e:
            logger.error(f"âŒ GitHub migration failed: {str(e)}")
            db.session.rollback()
            return False


def run_gitlab_scan_migration():
    """Create the new gitlab_scan_results table"""
    with app.app_context():
        try:
            # Check if new table already exists
            if check_table_exists("gitlab_scan_results"):
                logger.info("âœ… GitLab scan results table already exists")
                return True

            logger.info("ðŸš€ Creating new gitlab_scan_results table...")

            # Create the new gitlab_scan_results table
            db.session.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS gitlab_scan_results (
                    id SERIAL PRIMARY KEY,
                    repository_name VARCHAR(255) NOT NULL,
                    project_id VARCHAR(255) NOT NULL,
                    project_path VARCHAR(500) NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'pending',
                    results JSONB,
                    error TEXT,
                    user_id VARCHAR(255),
                    rerank JSONB,
                    workspace UUID NOT NULL DEFAULT gen_random_uuid(),
                    gitlab_instance_url VARCHAR(500),
                    branch_name VARCHAR(255) DEFAULT 'main'
                );
            """
                )
            )

            # Create indexes
            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_project_id 
                ON gitlab_scan_results (project_id);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_project_path 
                ON gitlab_scan_results (project_path);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_user_project 
                ON gitlab_scan_results (user_id, project_id);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_user_workspace 
                ON gitlab_scan_results (user_id, workspace);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_user_project_workspace 
                ON gitlab_scan_results (user_id, project_id, workspace);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_repo_user 
                ON gitlab_scan_results (repository_name, user_id);
            """
                )
            )

            db.session.execute(
                text(
                    """
                CREATE INDEX IF NOT EXISTS idx_gitlab_scan_status 
                ON gitlab_scan_results (status);
            """
                )
            )

            db.session.commit()
            logger.info("âœ… GitLab scan results table created successfully!")

            return True

        except Exception as e:
            logger.error(f"âŒ GitLab scan migration failed: {str(e)}")
            db.session.rollback()
            return False


def cleanup_old_gitlab_table():
    """Optional: Drop the old gitlab_analysis_results table after migration"""
    with app.app_context():
        try:
            if check_table_exists("gitlab_analysis_results"):
                logger.info("ðŸ—‘ï¸ Dropping old gitlab_analysis_results table...")
                db.session.execute(
                    text("DROP TABLE IF EXISTS gitlab_analysis_results CASCADE;")
                )
                db.session.commit()
                logger.info("âœ… Old GitLab table dropped successfully")
        except Exception as e:
            logger.error(f"âŒ Error dropping old table: {str(e)}")
            db.session.rollback()


def debug_gitlab_table():
    """Debug function to check GitLab table structure"""
    with app.app_context():
        try:
            # Check if old table exists
            old_table_exists = check_table_exists("gitlab_analysis_results")
            print(
                f"Old GitLab table (gitlab_analysis_results) exists: {old_table_exists}"
            )

            # Check if new table exists
            new_table_exists = check_table_exists("gitlab_scan_results")
            print(f"New GitLab table (gitlab_scan_results) exists: {new_table_exists}")

            if old_table_exists:
                # Get all columns from old table
                result = db.session.execute(
                    text(
                        """
                    SELECT column_name, data_type, is_nullable 
                    FROM information_schema.columns 
                    WHERE table_name = 'gitlab_analysis_results'
                    ORDER BY ordinal_position
                """
                    )
                )
                columns = result.fetchall()
                print("Old table columns:")
                for col in columns:
                    print(f"  - {col[0]} ({col[1]}, nullable: {col[2]})")

            if new_table_exists:
                # Get all columns from new table
                result = db.session.execute(
                    text(
                        """
                    SELECT column_name, data_type, is_nullable 
                    FROM information_schema.columns 
                    WHERE table_name = 'gitlab_scan_results'
                    ORDER BY ordinal_position
                """
                    )
                )
                columns = result.fetchall()
                print("New table columns:")
                for col in columns:
                    print(f"  - {col[0]} ({col[1]}, nullable: {col[2]})")

        except Exception as e:
            print(f"Error checking table: {e}")


debug_gitlab_table()


def fix_workspace_column_type():
    """Fix workspace_id column type from UUID to VARCHAR(24) to support MongoDB ObjectIds"""
    with app.app_context():
        try:
            logger.info("ðŸ”§ Fixing workspace_id column type...")

            # Check if column exists and is UUID type
            result = db.session.execute(
                text(
                    """
                SELECT data_type 
                FROM information_schema.columns 
                WHERE table_name = 'analysis_results' 
                AND column_name = 'workspace_id'
            """
                )
            ).scalar()

            if result == "uuid":
                logger.info("Converting workspace_id from UUID to VARCHAR(24)...")

                # Drop existing indexes that depend on the column
                db.session.execute(
                    text(
                        """
                    DROP INDEX IF EXISTS idx_analysis_results_user_workspace_id;
                """
                    )
                )

                db.session.execute(
                    text(
                        """
                    DROP INDEX IF EXISTS idx_analysis_results_user_workspace_worksheet;
                """
                    )
                )

                db.session.execute(
                    text(
                        """
                    DROP INDEX IF EXISTS idx_analysis_results_workspace_id;
                """
                    )
                )

                # Change column type
                db.session.execute(
                    text(
                        """
                    ALTER TABLE analysis_results 
                    ALTER COLUMN workspace_id TYPE VARCHAR(24);
                """
                    )
                )

                # Recreate indexes
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_analysis_results_user_workspace_id
                    ON analysis_results (user_id, workspace_id);
                """
                    )
                )

                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_analysis_results_user_workspace_worksheet
                    ON analysis_results (user_id, workspace_id, worksheet_number);
                """
                    )
                )

                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_analysis_results_workspace_id
                    ON analysis_results (workspace_id);
                """
                    )
                )

                db.session.commit()
                logger.info(
                    "âœ… Successfully converted workspace_id column to VARCHAR(24)"
                )
                return True

            elif result == "character varying":
                logger.info("âœ… workspace_id column is already VARCHAR type")
                return True
            else:
                logger.warning(f"Unexpected column type for workspace_id: {result}")
                return False

        except Exception as e:
            logger.error(f"âŒ Error fixing workspace_id column type: {str(e)}")
            db.session.rollback()
            return False


def run_workspace_column_fix():
    """Run the workspace column type fix migration"""
    with app.app_context():
        try:
            logger.info("ðŸš€ Running workspace column type fix...")

            success = fix_workspace_column_type()

            if success:
                logger.info("âœ… Workspace column type fix completed successfully!")
                return True
            else:
                logger.error("âŒ Workspace column type fix failed")
                return False

        except Exception as e:
            logger.error(f"âŒ Workspace column fix migration failed: {str(e)}")
            db.session.rollback()
            return False


def add_required_columns():
    """Add required columns if they don't exist"""
    with app.app_context():
        try:
            # Check and add columns to analysis_results table
            if check_table_exists("analysis_results"):
                # Add user_id column
                if not check_column_exists("analysis_results", "user_id"):
                    logger.info("Adding user_id column to analysis_results...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE analysis_results 
                        ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)
                    """
                        )
                    )
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS ix_analysis_results_user_id 
                        ON analysis_results (user_id)
                    """
                        )
                    )
                    db.session.commit()
                    logger.info("Added user_id column to analysis_results")

                # Add rerank column
                if not check_column_exists("analysis_results", "rerank"):
                    logger.info("Adding rerank column to analysis_results...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE analysis_results 
                        ADD COLUMN IF NOT EXISTS rerank JSONB
                    """
                        )
                    )
                    db.session.commit()
                    logger.info("Added rerank column to analysis_results")

                # Add worksheet_number column
                if not check_column_exists("analysis_results", "worksheet_number"):
                    logger.info("Adding worksheet_number column to analysis_results...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE analysis_results 
                        ADD COLUMN IF NOT EXISTS worksheet_number INTEGER DEFAULT 1
                    """
                        )
                    )

                    # Set default value for existing records
                    db.session.execute(
                        text(
                            """
                        UPDATE analysis_results 
                        SET worksheet_number = 1 
                        WHERE worksheet_number IS NULL
                    """
                        )
                    )

                    # Add indexes
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS ix_analysis_results_user_worksheet 
                        ON analysis_results (user_id, worksheet_number)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS ix_analysis_results_repo_user 
                        ON analysis_results (repository_name, user_id)
                    """
                        )
                    )

                    db.session.commit()
                    logger.info("Added worksheet_number column to analysis_results")

            # Check and add columns to cloud_scans table if it exists
            if check_table_exists("cloud_scans"):
                # Check for completed_at column
                if not check_column_exists("cloud_scans", "completed_at"):
                    logger.info("Adding completed_at column to cloud_scans...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP
                    """
                        )
                    )
                    db.session.commit()
                    logger.info("Added completed_at column to cloud_scans")

                # Check for error column
                if not check_column_exists("cloud_scans", "error"):
                    logger.info("Adding error column to cloud_scans...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS error TEXT
                    """
                        )
                    )
                    db.session.commit()
                    logger.info("Added error column to cloud_scans")

                # Check and add cloudname column
                if not check_column_exists("cloud_scans", "cloudname"):
                    logger.info("Adding cloudname column to cloud_scans...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS cloudname VARCHAR(255)
                    """
                        )
                    )
                    # Add index for faster lookups
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_cloud_scans_user_cloudname 
                        ON cloud_scans (user_id, cloudname)
                    """
                        )
                    )
                    db.session.commit()
                    logger.info("Added cloudname column to cloud_scans")

                # Check and add worksheet_number column
                if not check_column_exists("cloud_scans", "worksheet_number"):
                    logger.info("Adding worksheet_number column to cloud_scans...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS worksheet_number INTEGER DEFAULT 1
                    """
                        )
                    )

                    # Set default value for existing records
                    db.session.execute(
                        text(
                            """
                        UPDATE cloud_scans 
                        SET worksheet_number = 1 
                        WHERE worksheet_number IS NULL
                    """
                        )
                    )

                    # Add indexes for faster lookups
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_cloud_scans_user_worksheet 
                        ON cloud_scans (user_id, worksheet_number)
                    """
                        )
                    )

                    # Composite index for cloudname + worksheet queries
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_cloud_scans_user_cloudname_worksheet 
                        ON cloud_scans (user_id, cloudname, worksheet_number)
                    """
                        )
                    )

                    # Additional useful indexes
                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_cloud_scans_user_id 
                        ON cloud_scans (user_id)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_cloud_scans_provider 
                        ON cloud_scans (cloud_provider)
                    """
                        )
                    )

                    db.session.execute(
                        text(
                            """
                        CREATE INDEX IF NOT EXISTS idx_cloud_scans_status 
                        ON cloud_scans (status)
                    """
                        )
                    )

                    db.session.commit()
                    logger.info(
                        "Added worksheet_number column to cloud_scans with default value 1"
                    )

                # Add rerank column to cloud_scans if it doesn't exist
                if not check_column_exists("cloud_scans", "rerank"):
                    logger.info("Adding rerank column to cloud_scans...")
                    db.session.execute(
                        text(
                            """
                        ALTER TABLE cloud_scans 
                        ADD COLUMN IF NOT EXISTS rerank JSONB
                    """
                        )
                    )
                    db.session.commit()
                    logger.info("Added rerank column to cloud_scans")

        except Exception as e:
            logger.error(f"Error adding columns: {str(e)}")
            db.session.rollback()
            raise


def fix_gitlab_workspace_column_type():
    """Fix workspace column type from UUID to VARCHAR(24) in gitlab_scan_results to support MongoDB ObjectIds"""
    with app.app_context():
        try:
            logger.info("ðŸ”§ Fixing workspace column type in gitlab_scan_results...")

            result = db.session.execute(
                text(
                    """
                SELECT data_type 
                FROM information_schema.columns 
                WHERE table_name = 'gitlab_scan_results' 
                AND column_name = 'workspace'
            """
                )
            ).scalar()

            if result == "uuid":
                logger.info(
                    "Dropping NOT NULL constraint on workspace column temporarily..."
                )
                db.session.execute(
                    text(
                        """
                    ALTER TABLE gitlab_scan_results
                    ALTER COLUMN workspace DROP NOT NULL
                """
                    )
                )
                db.session.commit()
                logger.info(
                    "Checking for existing workspace values longer than 24 chars (will be set to NULL)..."
                )
                # Count affected rows
                res = db.session.execute(
                    text(
                        """
                    SELECT COUNT(*) FROM gitlab_scan_results WHERE LENGTH(workspace::text) > 24
                """
                    )
                ).scalar()
                if res > 0:
                    logger.warning(
                        f"Found {res} workspace values longer than 24; will set to NULL."
                    )
                    db.session.execute(
                        text(
                            """
                        UPDATE gitlab_scan_results
                        SET workspace = NULL
                        WHERE LENGTH(workspace::text) > 24
                    """
                        )
                    )
                    db.session.commit()
                    logger.info(
                        "Workspace columns over 24 chars have been set to NULL."
                    )

                logger.info("Converting workspace column from UUID to VARCHAR(24)...")
                # Drop existing indexes that depend on the column
                db.session.execute(
                    text(
                        """
                    DROP INDEX IF EXISTS idx_gitlab_scan_user_workspace;
                """
                    )
                )
                db.session.execute(
                    text(
                        """
                    DROP INDEX IF EXISTS idx_gitlab_scan_user_project_workspace;
                """
                    )
                )

                # Change column type
                db.session.execute(
                    text(
                        """
                    ALTER TABLE gitlab_scan_results 
                    ALTER COLUMN workspace TYPE VARCHAR(24) 
                    USING workspace::text;
                """
                    )
                )

                # Recreate indexes
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_gitlab_scan_user_workspace 
                    ON gitlab_scan_results (user_id, workspace);
                """
                    )
                )
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_gitlab_scan_user_project_workspace 
                    ON gitlab_scan_results (user_id, project_id, workspace);
                """
                    )
                )
                db.session.commit()
                logger.info(
                    "âœ… Successfully converted workspace column to VARCHAR(24) in gitlab_scan_results"
                )
                return True
            elif result == "character varying":
                logger.info(
                    "âœ… workspace column is already VARCHAR type in gitlab_scan_results"
                )
                return True
            else:
                logger.warning(f"Unexpected column type for workspace: {result}")
                return False
        except Exception as e:
            logger.error(
                f"âŒ Error fixing workspace column type in gitlab_scan_results: {str(e)}"
            )
            db.session.rollback()
            return False


def run_gitlab_workspace_column_fix():
    """Run the workspace column type fix for gitlab_scan_results table"""
    with app.app_context():
        try:
            logger.info(
                "ðŸš€ Running workspace column type fix for gitlab_scan_results..."
            )
            success = fix_gitlab_workspace_column_type()
            if success:
                logger.info(
                    "âœ… GitLab scan results workspace column type fix completed successfully!"
                )
                return True
            else:
                logger.error("âŒ GitLab scan results workspace column type fix failed")
                return False
        except Exception as e:
            logger.error(
                f"âŒ GitLab scan results workspace column fix migration failed: {str(e)}"
            )
            db.session.rollback()
            return False


def backfill_missing_commit_shas():
    """Backfill missing scanned_commit_sha values for existing analysis_results records"""
    with app.app_context():
        try:
            logger.info("ðŸ”„ Starting backfill of missing commit SHAs...")

            #  records with missing scanned_commit_sha but with results
            result = db.session.execute(
                text(
                    """
                SELECT id, repository_name, results 
                FROM analysis_results 
                WHERE scanned_commit_sha IS NULL 
                AND results IS NOT NULL 
                AND status = 'completed'
                ORDER BY timestamp DESC
                LIMIT 100
            """
                )
            )

            records_to_fix = result.fetchall()
            logger.info(f"Found {len(records_to_fix)} records with missing commit SHAs")

            if not records_to_fix:
                logger.info("âœ… No records need commit SHA backfill")
                return True

            fixed_count = 0
            for record in records_to_fix:
                try:
                    record_id, repo_name, results = record

                    if results and isinstance(results, dict):
                        metadata = results.get("metadata", {})
                        commit_sha = metadata.get("scanned_commit_sha")

                        if record_id <= 3:
                            logger.info(
                                f"Record {record_id} metadata keys: {list(metadata.keys())}"
                            )
                            logger.info(f"Record {record_id} full metadata: {metadata}")

                        if commit_sha:
                            db.session.execute(
                                text(
                                    """
                                UPDATE analysis_results 
                                SET scanned_commit_sha = :sha 
                                WHERE id = :id
                            """
                                ),
                                {"sha": commit_sha, "id": record_id},
                            )

                            fixed_count += 1
                            logger.info(
                                f"Backfilled commit SHA for record {record_id}: {commit_sha}"
                            )
                        else:
                            logger.warning(
                                f"No commit SHA found in metadata for record {record_id}"
                            )
                    else:
                        logger.warning(f"No valid results data for record {record_id}")

                except Exception as e:
                    logger.error(f"Error backfilling record {record_id}: {str(e)}")
                    continue

            db.session.commit()
            logger.info(f"âœ… Successfully backfilled {fixed_count} commit SHAs")
            return True

        except Exception as e:
            logger.error(f"âŒ Error during commit SHA backfill: {str(e)}")
            db.session.rollback()
            return False


def add_gitlab_scanned_commit_sha_column():
    """Add scanned_commit_sha column to gitlab_scan_results table"""
    with app.app_context():
        try:
            if not check_column_exists("gitlab_scan_results", "scanned_commit_sha"):
                logger.info(
                    "Adding scanned_commit_sha column to gitlab_scan_results..."
                )
                db.session.execute(
                    text(
                        """
                    ALTER TABLE gitlab_scan_results
                    ADD COLUMN IF NOT EXISTS scanned_commit_sha VARCHAR(64)
                """
                    )
                )
                db.session.execute(
                    text(
                        """
                    CREATE INDEX IF NOT EXISTS idx_gitlab_scan_commit_sha
                    ON gitlab_scan_results (scanned_commit_sha)
                """
                    )
                )
                db.session.commit()
                logger.info(
                    "Successfully added scanned_commit_sha column to gitlab_scan_results"
                )
                return True
            else:
                logger.info(
                    "scanned_commit_sha column already exists in gitlab_scan_results"
                )
                return True
        except Exception as e:
            logger.error(
                f"Error adding scanned_commit_sha column to gitlab_scan_results: {str(e)}"
            )
            db.session.rollback()
            return False


def backfill_gitlab_missing_commit_shas():
    """Backfill missing scanned_commit_sha values for existing gitlab_scan_results records"""
    with app.app_context():
        try:
            logger.info("ðŸ”„ Starting backfill of missing commit SHAs for GitLab...")

            result = db.session.execute(
                text(
                    """
                SELECT id, project_path, results 
                FROM gitlab_scan_results 
                WHERE scanned_commit_sha IS NULL 
                AND results IS NOT NULL 
                AND status = 'completed'
                ORDER BY timestamp DESC
                LIMIT 100
            """
                )
            )

            records_to_fix = result.fetchall()
            logger.info(
                f"Found {len(records_to_fix)} GitLab records with missing commit SHAs"
            )

            if not records_to_fix:
                logger.info("âœ… No GitLab records need commit SHA backfill")
                return True

            fixed_count = 0
            for record in records_to_fix:
                try:
                    record_id, project_path, results = record

                    if results and isinstance(results, dict):
                        metadata = results.get("metadata", {})
                        commit_sha = metadata.get("scanned_commit_sha")

                        if record_id <= 3:
                            logger.info(
                                f"GitLab Record {record_id} metadata keys: {list(metadata.keys())}"
                            )
                            logger.info(
                                f"GitLab Record {record_id} full metadata: {metadata}"
                            )

                        if commit_sha:
                            db.session.execute(
                                text(
                                    """
                                UPDATE gitlab_scan_results 
                                SET scanned_commit_sha = :sha 
                                WHERE id = :id
                            """
                                ),
                                {"sha": commit_sha, "id": record_id},
                            )

                            fixed_count += 1
                            logger.info(
                                f"Backfilled commit SHA for GitLab record {record_id}: {commit_sha}"
                            )
                        else:
                            logger.warning(
                                f"No commit SHA found in metadata for GitLab record {record_id}"
                            )
                    else:
                        logger.warning(
                            f"No valid results data for GitLab record {record_id}"
                        )

                except Exception as e:
                    logger.error(
                        f"Error backfilling GitLab record {record_id}: {str(e)}"
                    )
                    continue

            db.session.commit()
            logger.info(f"âœ… Successfully backfilled {fixed_count} GitLab commit SHAs")
            return True

        except Exception as e:
            logger.error(f"âŒ Error during GitLab commit SHA backfill: {str(e)}")
            db.session.rollback()
            return False


def run_zap_scan_migration():
    """Create the zap_scan_results table and ensure report_path column exists"""
    with app.app_context():
        try:
            if check_table_exists("zap_scan_results"):
                # Ensure report_path exists
                if not check_column_exists("zap_scan_results", "report_path"):
                    db.session.execute(
                        text(
                            "ALTER TABLE zap_scan_results ADD COLUMN IF NOT EXISTS report_path VARCHAR(1024);"
                        )
                    )
                    db.session.commit()
                logger.info(
                    "âœ… ZAP scan results table already exists (checked report_path column)"
                )
                return True
            logger.info("ðŸš€ Creating zap_scan_results table...")

            db.session.execute(
                text(
                    """
                CREATE TABLE IF NOT EXISTS zap_scan_results (
                    id SERIAL PRIMARY KEY,
                    target_url VARCHAR(500) NOT NULL,
                    scan_type VARCHAR(20) NOT NULL DEFAULT 'baseline',
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) DEFAULT 'pending',
                    results JSONB,
                    error TEXT,
                    user_id VARCHAR(255) NOT NULL,
                    workspace_id VARCHAR(24),
                    worksheet_number INTEGER NOT NULL DEFAULT 1,
                    rerank JSONB,
                    completed_at TIMESTAMP,
                    scan_duration_seconds INTEGER,
                    findings_count INTEGER DEFAULT 0,
                    severity_counts JSONB,
                    zap_version VARCHAR(50),
                    zap_exit_code INTEGER,
                    report_path VARCHAR(1024)
                );
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_user_id 
                ON zap_scan_results (user_id);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_user_workspace 
                ON zap_scan_results (user_id, workspace_id);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_user_worksheet 
                ON zap_scan_results (user_id, worksheet_number);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_user_workspace_worksheet 
                ON zap_scan_results (user_id, workspace_id, worksheet_number);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_target_url 
                ON zap_scan_results (target_url);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_scan_type 
                ON zap_scan_results (scan_type);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_status 
                ON zap_scan_results (status);
            """
                )
            )

            db.session.execute(
                DDL(
                    """
                CREATE INDEX IF NOT EXISTS idx_zap_scan_timestamp 
                ON zap_scan_results (timestamp);
            """
                )
            )

            db.session.commit()
            logger.info("âœ… ZAP scan results table created successfully!")

            return True

        except Exception as e:
            logger.error(f"âŒ ZAP scan migration failed: {str(e)}")
            db.session.rollback()
            return False


def init_tables():
    """Initialize tables if they don't exist and add necessary columns"""
    with app.app_context():
        try:
            logger.info("ðŸš€ Starting comprehensive database initialization...")

            # Run all migrations in order
            logger.info("ðŸ“‹ Running migrations...")

            # 1. Ignored findings migration
            run_ignore_migration()

            # 2. Azure DevOps migration
            run_azure_devops_migration()

            # 3. GitHub migration
            run_github_migration()

            # 4. NEW: Analysis results workspace migration (run after basic GitHub migration)
            run_analysis_results_workspace_migration()

            run_workspace_column_fix()

            # 5. New GitLab scan migration (instead of old gitlab migration)
            run_gitlab_scan_migration()
            # 5b. GitLab scan results workspace column type fix
            run_gitlab_workspace_column_fix()

            # 6. ZAP scan migration
            run_zap_scan_migration()

            # 6. Run normal table creation (this will create any remaining tables)
            logger.info("ðŸ—ƒï¸ Creating remaining tables with SQLAlchemy...")

            db.create_all()
            logger.info("Database tables created or confirmed to exist")

            # 7. COMPREHENSIVE: Ensure all columns and indexes exist
            logger.info(
                "ðŸ”§ Ensuring all required columns and indexes exist across all tables..."
            )
            ensure_all_columns_and_indexes()

            # 8. Add GitLab scanned_commit_sha column
            logger.info("ðŸ”§ Adding GitLab scanned_commit_sha column...")
            add_gitlab_scanned_commit_sha_column()

            # 9. Backfill missing commit SHAs
            logger.info("ðŸ”„ Backfilling missing commit SHAs...")
            backfill_missing_commit_shas()

            # 10. Backfill missing GitLab commit SHAs
            logger.info("ðŸ”„ Backfilling missing GitLab commit SHAs...")
            backfill_gitlab_missing_commit_shas()

            # 9. Optional cleanup of old table (uncomment if you want to remove it)
            # cleanup_old_gitlab_table()

            # Log completion
            environment = os.getenv("FLASK_ENV", "unknown")
            db_host = os.getenv("DB_HOST", "unknown")
            logger.info(
                f"ðŸ“Š Database initialization completed in environment: {environment}, DB: {db_host}"
            )
            logger.info("âœ… Database initialization completed successfully!")

        except Exception as e:
            logger.error(f"âŒ Error initializing database: {str(e)}")
            db.session.rollback()
            raise


def verify_tables():
    """Verify that all tables exist and have the correct structure"""
    with app.app_context():
        try:
            logger.info("ðŸ” Verifying table structure...")

            expected_tables = [
                "analysis_results",
                "azure_devops_analysis_results",
                "github_analysis_results",
                "gitlab_scan_results",  # Changed from gitlab_analysis_results
                "cloud_scans",
                "ignored_findings",
            ]

            for table in expected_tables:
                if check_table_exists(table):
                    logger.info(f"âœ… Table '{table}' exists")

                    # Check for workspace/worksheet_number column in each table
                    if table == "gitlab_scan_results":
                        if check_column_exists(table, "workspace"):
                            logger.info(f"âœ… Table '{table}' has workspace column")
                        else:
                            logger.warning(
                                f"âš ï¸ Table '{table}' missing workspace column"
                            )
                    else:
                        if check_column_exists(table, "worksheet_number"):
                            logger.info(
                                f"âœ… Table '{table}' has worksheet_number column"
                            )
                        else:
                            logger.warning(
                                f"âš ï¸ Table '{table}' missing worksheet_number column"
                            )
                else:
                    logger.error(f"âŒ Table '{table}' does not exist")

            logger.info("ðŸ” Table verification completed")

        except Exception as e:
            logger.error(f"âŒ Error verifying tables: {str(e)}")


async def pre_download_zap_images(docker_binary: str = "docker") -> Dict:
    """Pre-download all ZAP images to avoid timeouts during scanning"""
    scanner = ZapDockerScanner(docker_binary)

    docker_available, docker_message = await scanner._check_docker_available()
    if not docker_available:
        print(f"âŒ Docker is not available: {docker_message}")
        return {"success": False, "error": docker_message}

    images = set(scanner.BASELINE_IMAGES + scanner.FULL_SCAN_IMAGES)
    results = {}

    print("ðŸ” Pre-downloading ZAP Docker images...")
    print(
        "ðŸ’¡ Tip: If this fails, try manual download with 'docker pull zaproxy/zap-stable:lite'"
    )

    for image in images:
        print(f"ðŸ“¥ Attempting to download {image}...")
        success, message = await scanner._test_docker_image(image)
        results[image] = {"success": success, "message": message}
        if success:
            print(f"âœ… Successfully downloaded {image}")
        else:
            print(f"âŒ Failed to download {image}: {message}")

    successful_downloads = [img for img, result in results.items() if result["success"]]

    if successful_downloads:
        print(
            f"ðŸŽ‰ Pre-download complete! {len(successful_downloads)} images available"
        )
        return {
            "success": True,
            "available_images": successful_downloads,
            "all_results": results,
        }
    else:
        print("ðŸ’¥ All downloads failed! Please check:")
        print("  1. Docker is running: Run 'docker info'")
        print("  2. Network connectivity")
        print("  3. Try manual download: 'docker pull ghcr.io/zaproxy/zaproxy:stable'")
        return {"success": False, "all_results": results}


def initialize_ecs_infrastructure():
    """
    Initialize ECS task definitions during application startup
    This ensures task definitions are registered before the API starts
    """
    logger.info("ðŸ”§ Initializing ECS infrastructure...")

    try:
        # Import the ECS initialization module
        from ecs_init import initialize_ecs_tasks

        # Register all task definitions
        result = initialize_ecs_tasks()

        if result["success"]:
            logger.info(
                f"âœ… ECS initialization complete: {result['successful']} task(s) registered"
            )
        else:
            logger.warning(
                f"âš ï¸ ECS initialization had issues: {result['failed']} failed"
            )

        return result

    except ImportError:
        logger.warning("âš ï¸ ecs_init module not found, skipping ECS initialization")
        logger.info(
            "ðŸ’¡ To enable ECS initialization, add ecs_init.py to your project"
        )
        return {"success": True, "skipped": True}
    except Exception as e:
        logger.error(f"âŒ Error during ECS initialization: {e}")
        logger.info("âš ï¸ Continuing without ECS initialization...")
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    logger.info("ðŸš€ Starting database initialization process...")
    init_tables()
    verify_tables()

    # Initialize ECS infrastructure
    logger.info("ðŸ”§ Initializing ECS infrastructure...")
    ecs_result = initialize_ecs_infrastructure()

    if ecs_result.get("success") or ecs_result.get("skipped"):
        logger.info("âœ… ECS infrastructure ready")
    else:
        logger.warning(
            "âš ï¸ ECS infrastructure initialization had issues, but continuing..."
        )

    logger.info("ðŸŽ‰ Database initialization process completed successfully!")
    # async def test_scanner():
    #     await pre_download_zap_images()

    # asyncio.run(test_scanner())
