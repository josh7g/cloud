 #!/bin/bash
set -e

echo "=== STEAMPIPE AWS CONNECTION REPAIR SCRIPT ==="

# Clean up existing configuration
echo "Removing existing AWS connection config..."
rm -f ~/.steampipe/config/aws.spc

# Create proper AWS credentials files
echo "Setting up AWS credential files..."
mkdir -p ~/.aws

# AWS credentials file
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id=${AWS_ACCESS_KEY_ID}
aws_secret_access_key=${AWS_SECRET_ACCESS_KEY}
EOF

if [ ! -z "${AWS_SESSION_TOKEN}" ]; then
  echo "aws_session_token=${AWS_SESSION_TOKEN}" >> ~/.aws/credentials
fi

# AWS config file
cat > ~/.aws/config << EOF
[default]
region=us-east-1
output=json
EOF

chmod 600 ~/.aws/credentials
chmod 600 ~/.aws/config

# Create Steampipe connection that uses AWS profiles
echo "Creating profile-based AWS connection..."
mkdir -p ~/.steampipe/config

cat > ~/.steampipe/config/aws.spc << EOF
connection "aws" {
  plugin  = "aws"
  profile = "default"
  regions = ["us-east-1"]
}
EOF

chmod 600 ~/.steampipe/config/aws.spc

# Restart Steampipe service to apply changes
echo "Restarting Steampipe service..."
steampipe service restart
sleep 5

# Test AWS connection
echo "Testing AWS connection..."
ACCOUNT_ID=$(steampipe query "select account_id from aws_account limit 1" --output csv 2>/dev/null | tail -1)

if [ ! -z "$ACCOUNT_ID" ]; then
  echo "✅ Successfully connected to AWS account: $ACCOUNT_ID"
  exit 0
else
  echo "❌ AWS connection test failed, trying direct credential approach..."
  
  # Try direct credential approach as fallback
  cat > ~/.steampipe/config/aws.spc << EOF
connection "aws" {
  plugin  = "aws"
  regions = ["us-east-1"]
}
EOF

  # Export credentials directly
  export AWS_ACCESS_KEY_ID
  export AWS_SECRET_ACCESS_KEY
  if [ ! -z "$AWS_SESSION_TOKEN" ]; then
    export AWS_SESSION_TOKEN
  fi
  
  # Restart and test again
  steampipe service restart
  sleep 5
  
  ACCOUNT_ID=$(steampipe query "select account_id from aws_account limit 1" --output csv 2>/dev/null | tail -1)
  
  if [ ! -z "$ACCOUNT_ID" ]; then
    echo "✅ Successfully connected to AWS account using environment variables: $ACCOUNT_ID"
    exit 0
  else
    echo "❌ All connection attempts failed"
    echo "Continuing with boto3 fallback"
    exit 1
  fi
fi
