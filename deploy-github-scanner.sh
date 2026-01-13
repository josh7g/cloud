#!/bin/bash
# Deploy GitHub Scanner to ECS

set -e

# Configuration
AWS_REGION="us-east-1"
AWS_ACCOUNT_ID="767828720428"  # Main account
ECR_REPO="github-scanner"
TASK_FAMILY="github-scanner"

echo "=== Checking ECR Repository ==="

# Check if ECR repository exists, create if not
aws ecr describe-repositories --repository-names ${ECR_REPO} --region ${AWS_REGION} 2>/dev/null || \
{
    echo "Creating ECR repository: ${ECR_REPO}"
    aws ecr create-repository --repository-name ${ECR_REPO} --region ${AWS_REGION}
    echo "âœ… ECR repository created"
}

echo "=== Building GitHub Scanner ==="

# Build Docker image
docker build -f Dockerfile.github-scanner -t ${ECR_REPO}:latest .

# Tag for ECR
docker tag ${ECR_REPO}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest

echo "=== Logging into ECR ==="
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

echo "=== Pushing to ECR ==="
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest

echo "=== Creating CloudWatch Log Group ==="
aws logs create-log-group --log-group-name /ecs/github-scanner --region ${AWS_REGION} 2>/dev/null || echo "Log group already exists"

echo "=== Registering Task Definition ==="
aws ecs register-task-definition --cli-input-json file://taskdef-github-scanner.json

echo "=== Deployment Complete ==="
echo "Task Definition: ${TASK_FAMILY}"
echo "Image: ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}:latest"