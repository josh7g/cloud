# Use Python 3.11 slim as base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    FLASK_ENV=development \
    PORT=10000 \
    STEAMPIPE_DIR=/home/steampipe/.steampipe \
    PATH="/home/steampipe/.steampipe/bin:/home/steampipe/.local/bin:$PATH"

# Set working directory
WORKDIR /app

# Install system dependencies with SSL certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
    unzip \
    sudo \
    postgresql-client \
    ca-certificates \
    openssl \
    procps \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI for direct access testing
RUN apt-get update && apt-get install -y \
    curl \
    unzip && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash steampipe && \
    mkdir -p ${STEAMPIPE_DIR}/bin && \
    mkdir -p /home/steampipe/.local/bin && \
    mkdir -p /app/results && \
    chown -R steampipe:steampipe ${STEAMPIPE_DIR} /home/steampipe/.local /app/results

# Create scripts directory with proper permissions
RUN mkdir -p /home/steampipe/scripts && \
    chown -R steampipe:steampipe /home/steampipe/scripts

# Switch to steampipe user for installation
USER steampipe
WORKDIR /home/steampipe

# Download and install Steampipe
RUN curl -fsSL https://github.com/turbot/steampipe/releases/latest/download/steampipe_linux_amd64.tar.gz -o steampipe.tar.gz && \
    mkdir -p steampipe-install && \
    tar -xzf steampipe.tar.gz -C steampipe-install && \
    mv steampipe-install/steampipe ${STEAMPIPE_DIR}/bin/ && \
    chmod +x ${STEAMPIPE_DIR}/bin/steampipe && \
    rm -rf steampipe.tar.gz steampipe-install

# Switch to root for installation
USER root

# Install Powerpipe (ensure it installs to a location the steampipe user can access)
RUN curl -fsSL https://powerpipe.io/install/powerpipe.sh | sh && \
    mv /usr/local/bin/powerpipe /home/steampipe/.local/bin/powerpipe && \
    chmod +x /home/steampipe/.local/bin/powerpipe && \
    chown -R steampipe:steampipe /home/steampipe/.local/bin/powerpipe

# Create dashboards directory with correct permissions
RUN mkdir -p /home/steampipe/dashboards && \
    chown -R steampipe:steampipe /home/steampipe/dashboards

# Switch back to steampipe user
USER steampipe

RUN steampipe --version

# Install AWS Plugin
RUN steampipe plugin install aws@1.10.0

# Create default AWS connection config directory and file
RUN mkdir -p ${STEAMPIPE_DIR}/config && \
    echo 'connection "aws" {' > ${STEAMPIPE_DIR}/config/aws.spc && \
    echo '  plugin = "aws"' >> ${STEAMPIPE_DIR}/config/aws.spc && \
    echo '}' >> ${STEAMPIPE_DIR}/config/aws.spc && \
    chmod 600 ${STEAMPIPE_DIR}/config/aws.spc

# Install AWS Compliance Mod (contains CIS benchmarks)
RUN powerpipe mod install github.com/turbot/steampipe-mod-aws-compliance

# Create and configure workspace directory for Steampipe
RUN mkdir -p /home/steampipe/workspace/queries
WORKDIR /home/steampipe/workspace

# Initialize a proper Steampipe mod
RUN echo 'mod "local" { title = "AWS CIS Benchmark Scan" }' > mod.sp

# Create AWS CIS benchmark query files (fallback queries)
WORKDIR /home/steampipe/workspace/queries
RUN echo '-- Check IAM users with interactive access' > iam_users.sql && \
    echo 'SELECT' >> iam_users.sql && \
    echo "  'IAM.1 - IAM User Root Check' as control," >> iam_users.sql && \
    echo '  u.name as user_name,' >> iam_users.sql && \
    echo '  u.user_id as resource_id,' >> iam_users.sql && \
    echo '  u.arn,' >> iam_users.sql && \
    echo '  CASE ' >> iam_users.sql && \
    echo "    WHEN u.name = 'root' AND u.password_last_used IS NOT NULL THEN 'FAIL: Root account in use'" >> iam_users.sql && \
    echo "    WHEN u.name = 'root' THEN 'PASS: Root account not recently used'" >> iam_users.sql && \
    echo "    WHEN u.mfa_enabled THEN 'PASS: MFA enabled'" >> iam_users.sql && \
    echo "    ELSE 'FAIL: MFA not enabled'" >> iam_users.sql && \
    echo '  END as status,' >> iam_users.sql && \
    echo "  'IAM' as category" >> iam_users.sql && \
    echo 'FROM' >> iam_users.sql && \
    echo '  aws_iam_user as u;' >> iam_users.sql

# Create a simple benchmark discovery script
RUN echo '#!/bin/bash' > /home/steampipe/.local/bin/discover-benchmarks.sh && \
    echo 'echo "Available CIS benchmarks:"' >> /home/steampipe/.local/bin/discover-benchmarks.sh && \
    echo 'steampipe check list | grep -i cis' >> /home/steampipe/.local/bin/discover-benchmarks.sh && \
    chmod +x /home/steampipe/.local/bin/discover-benchmarks.sh

RUN echo '#!/bin/bash' > /home/steampipe/.local/bin/steampipe-healthcheck.sh && \
    echo 'set -e' >> /home/steampipe/.local/bin/steampipe-healthcheck.sh && \
    echo 'steampipe --version > /dev/null' >> /home/steampipe/.local/bin/steampipe-healthcheck.sh && \
    echo 'steampipe service status > /dev/null' >> /home/steampipe/.local/bin/steampipe-healthcheck.sh && \
    echo 'curl -f http://localhost:${PORT}/health || exit 1' >> /home/steampipe/.local/bin/steampipe-healthcheck.sh && \
    chmod +x /home/steampipe/.local/bin/steampipe-healthcheck.sh

# Create the AWS connection update script directly in the image
RUN mkdir -p /home/steampipe/scripts && \
    echo '#!/bin/bash' > /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'set -e' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Create or update the AWS connection with provided credentials' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'CONNECTION_FILE="/home/steampipe/.steampipe/config/aws.spc"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'CONNECTION_DIR=$(dirname "$CONNECTION_FILE")' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Ensure directory exists' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'mkdir -p "$CONNECTION_DIR"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Create connection file' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'cat > ${CONNECTION_FILE} << EOF' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'connection "aws" {' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  plugin = "aws"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  aws_access_key_id     = "${AWS_ACCESS_KEY_ID}"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  aws_secret_access_key = "${AWS_SECRET_ACCESS_KEY}"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  regions               = ["us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1"]' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  default_region        = "us-east-1"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'EOF' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Add session token if provided' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'if [ ! -z "${AWS_SESSION_TOKEN}" ]; then' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  echo "  aws_session_token = \\"${AWS_SESSION_TOKEN}\\"" >> ${CONNECTION_FILE}' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'fi' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Close the connection block' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'echo "}" >> ${CONNECTION_FILE}' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Set proper permissions' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'chmod 600 ${CONNECTION_FILE}' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'chown steampipe:steampipe ${CONNECTION_FILE}' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Restart Steampipe service to apply new credentials' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'steampipe service restart' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Wait for service to be ready' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'sleep 3' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '# Verify connection by querying account ID' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'echo "Testing AWS connection..."' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'ACCOUNT_ID=$(steampipe query "select account_id from aws_account limit 1" --output csv 2>/dev/null | tail -1)' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'if [ ! -z "$ACCOUNT_ID" ]; then' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  echo "✅ Successfully connected to AWS account: $ACCOUNT_ID"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  exit 0' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'else' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  echo "❌ Failed to connect to AWS account"' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo '  exit 1' >> /home/steampipe/scripts/update_aws_connection.sh && \
    echo 'fi' >> /home/steampipe/scripts/update_aws_connection.sh && \
    chmod +x /home/steampipe/scripts/update_aws_connection.sh && \
    chown steampipe:steampipe /home/steampipe/scripts/update_aws_connection.sh

# Switch back to root before copying the file 
USER root

# Install Java and ZAP CLI
# Install Java and ZAP CLI
RUN apt-get update && \
    apt-get install -y openjdk-21-jre-headless wget && \
    wget --no-check-certificate -O /tmp/ZAP_2.15.0_Linux.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz && \
    mkdir -p /opt && \
    tar -xzf /tmp/ZAP_2.15.0_Linux.tar.gz -C /opt && \
    mv /opt/ZAP_* /opt/zap && \
    rm /tmp/ZAP_2.15.0_Linux.tar.gz && \
    chmod +x /opt/zap/zap.sh && \
    ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh && \
    ln -s /opt/zap/zap /usr/local/bin/zaproxy

# Copy the AWS connection update script
COPY update_aws_connection.sh /home/steampipe/scripts/update_aws_connection.sh
RUN chmod +x /home/steampipe/scripts/update_aws_connection.sh && \
    chown steampipe:steampipe /home/steampipe/scripts/update_aws_connection.sh

# Then switch back to steampipe user
USER steampipe

# Switch back to root to copy application files
USER root
WORKDIR /app

# Copy application files
COPY --chown=steampipe:steampipe . .

# Install build dependencies for Python packages that need compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Remove build dependencies to reduce image size
RUN apt-get update && \
    apt-get remove -y \
    gcc \
    g++ \
    python3-dev \
    build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy entrypoint script and update it
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD /home/steampipe/.local/bin/steampipe-healthcheck.sh

# Create volumes for persistent data and results
VOLUME ["/home/steampipe/.steampipe", "/app/results"]

# Default location for ZAP reports; can be overridden at runtime
ENV ZAP_REPORTS_DIR=/app/results/zap_reports

# Create zap_reports directory with proper permissions
RUN mkdir -p /app/zap_reports "$ZAP_REPORTS_DIR" && \
    chown -R steampipe:steampipe /app/zap_reports "$ZAP_REPORTS_DIR" && \
    chmod 755 /app/zap_reports "$ZAP_REPORTS_DIR"

# Switch back to the steampipe user before running
USER steampipe
WORKDIR /app

# Use entrypoint to start services properly
ENTRYPOINT ["/docker-entrypoint.sh"]