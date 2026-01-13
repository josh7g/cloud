#!/bin/bash
set -e

echo "=== Starting AWS CIS Benchmark Scanner Service ==="

test_docker() {
    echo "Testing Docker accessibility..."
    if docker --version > /dev/null 2>&1; then
        echo "✅ Docker CLI is available"
        if docker info > /dev/null 2>&1; then
            echo "✅ Docker daemon is accessible"
            if docker run --rm hello-world > /dev/null 2>&1; then
                echo "✅ Docker containers can be executed"
                return 0
            else
                echo "⚠️ Docker CLI works but cannot run containers"
                return 1
            fi
        else
            echo "❌ Docker CLI available but cannot connect to daemon"
            return 1
        fi
    else
        echo "❌ Docker CLI not available"
        return 1
    fi
}

# Function to wait for RDS connection (simplified)
wait_for_database() {
    if [ -z "$DB_HOST" ]; then
        echo "⚠️ DB_HOST not set, skipping database check"
        return 0
    fi
    
    echo "Waiting for PostgreSQL database to be ready..."
    pg_isready -h "$DB_HOST" -p "${DB_PORT:-5432}" || true
}

test_docker || echo "⚠️ Docker not fully functional - ZAP scans may fail"

# Continue with application startup
wait_for_database

echo "Initializing application database (includes auto-migration)..."
if [ -f create_tables.py ]; then
    python create_tables.py
    echo "✅ Database initialization completed"
else
    echo "⚠️ create_tables.py not found, skipping database initialization"
fi

# Ensure ZAP reports directory exists and is writable
ZAP_REPORTS_DIR=${ZAP_REPORTS_DIR:-/app/results/zap_reports}
if ! mkdir -p "$ZAP_REPORTS_DIR" 2>/dev/null; then
  echo "⚠️ Failed to create $ZAP_REPORTS_DIR, falling back to /home/steampipe/zap_reports"
  ZAP_REPORTS_DIR=/home/steampipe/zap_reports
  mkdir -p "$ZAP_REPORTS_DIR" || true
fi
chown -R steampipe:steampipe "$ZAP_REPORTS_DIR" 2>/dev/null || true
chmod 755 "$ZAP_REPORTS_DIR" 2>/dev/null || true
export ZAP_REPORTS_DIR
echo "ZAP reports directory: $ZAP_REPORTS_DIR"

echo "=== Starting application ==="
exec gunicorn --config gunicorn_config.py "app:app"