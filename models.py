from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import JSONB, UUID
import uuid


db = SQLAlchemy()


class AnalysisResult(db.Model):
    __tablename__ = "analysis_results"

    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)
    worksheet_number = db.Column(db.Integer, nullable=False, default=1)
    workspace_id = db.Column(
        db.String(24), nullable=True
    )  # Changed from UUID to String
    scanned_commit_sha = db.Column(db.String(64), nullable=True)

    # Indexes for efficient lookups
    __table_args__ = (
        db.Index("ix_analysis_results_user_id", "user_id"),
        db.Index("ix_analysis_results_user_worksheet", "user_id", "worksheet_number"),
        db.Index("ix_analysis_results_repo_user", "repository_name", "user_id"),
        # NEW INDEXES FOR WORKSPACE SUPPORT
        db.Index("idx_analysis_results_user_workspace_id", "user_id", "workspace_id"),
        db.Index(
            "idx_analysis_results_user_workspace_worksheet",
            "user_id",
            "workspace_id",
            "worksheet_number",
        ),
        db.Index("idx_analysis_results_workspace_id", "workspace_id"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "repository_name": self.repository_name,
            "user_id": self.user_id,
            "worksheet_number": self.worksheet_number,
            "workspace_id": (
                str(self.workspace_id) if self.workspace_id else None
            ),  # NEW FIELD
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "rerank": self.rerank,
        }


class AzureDevOpsAnalysisResult(db.Model):
    __tablename__ = "azure_devops_analysis_results"

    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)
    organization_name = db.Column(db.String(255), nullable=False)
    project_name = db.Column(db.String(255), nullable=False)
    worksheet_number = db.Column(db.Integer, nullable=False, default=1)
    workspace_id = db.Column(db.String(24), nullable=True)  # Added workspace ID
    scanned_commit_sha = db.Column(db.String(64), nullable=True)

    # Composite indexes for efficient lookups
    __table_args__ = (
        db.Index(
            "idx_azure_org_project_repo",
            "organization_name",
            "project_name",
            "repository_name",
        ),
        db.Index("idx_azure_user_org", "user_id", "organization_name"),
        db.Index("idx_azure_user_worksheet", "user_id", "worksheet_number"),
        db.Index(
            "idx_azure_user_org_worksheet",
            "user_id",
            "organization_name",
            "worksheet_number",
        ),
        db.Index(
            "idx_azure_user_project_worksheet",
            "user_id",
            "project_name",
            "worksheet_number",
        ),
        # NEW INDEXES FOR WORKSPACE SUPPORT
        db.Index("idx_azure_user_workspace_id", "user_id", "workspace_id"),
        db.Index(
            "idx_azure_user_workspace_worksheet",
            "user_id",
            "workspace_id",
            "worksheet_number",
        ),
        db.Index("idx_azure_workspace_id", "workspace_id"),
        db.Index(
            "idx_azure_scanned_commit_sha", "scanned_commit_sha"
        ),  # Added for incremental scanning
    )

    def to_dict(self):
        return {
            "id": self.id,
            "organization_name": self.organization_name,
            "project_name": self.project_name,
            "repository_name": self.repository_name,
            "user_id": self.user_id,
            "worksheet_number": self.worksheet_number,
            "workspace_id": (
                str(self.workspace_id) if self.workspace_id else None
            ),  # Added workspace ID
            "scanned_commit_sha": self.scanned_commit_sha,  # Added for incremental scanning
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "rerank": self.rerank,
        }


class CloudScan(db.Model):
    __tablename__ = "cloud_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)
    cloud_provider = db.Column(db.String(50), nullable=False)
    account_id = db.Column(db.String(255), nullable=False)
    cloudname = db.Column(db.String(255), nullable=True)
    worksheet_number = db.Column(db.Integer, nullable=False, default=1)
    status = db.Column(db.String(50), default="pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    findings = db.Column(JSONB)
    rerank = db.Column(JSONB)
    error = db.Column(db.Text)

    # Indexes for efficient lookups
    __table_args__ = (
        db.Index("idx_cloud_scans_user_id", "user_id"),
        db.Index("idx_cloud_scans_user_cloudname", "user_id", "cloudname"),
        db.Index("idx_cloud_scans_user_worksheet", "user_id", "worksheet_number"),
        db.Index(
            "idx_cloud_scans_user_cloudname_worksheet",
            "user_id",
            "cloudname",
            "worksheet_number",
        ),
        db.Index("idx_cloud_scans_provider", "cloud_provider"),
        db.Index("idx_cloud_scans_status", "status"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "cloud_provider": self.cloud_provider,
            "account_id": self.account_id,
            "cloudname": self.cloudname,
            "worksheet_number": self.worksheet_number,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "findings": self.findings,
            "rerank": self.rerank,
            "error": self.error,
        }


class IgnoredFinding(db.Model):
    __tablename__ = "ignored_findings"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(255), nullable=False)
    repo_name = db.Column(db.String(255), nullable=False)

    # Type of ignore: 'finding', 'file', 'rule_in_file', 'rule_in_repo', 'cwe_in_file', 'cwe_in_repo'
    ignore_type = db.Column(db.String(20), nullable=False, default="finding")

    # These fields are nullable for broader ignore types
    finding_id = db.Column(db.String(255), nullable=True)
    file_path = db.Column(db.String(500), nullable=True)
    code_snippet = db.Column(db.Text, nullable=True)
    cwe_id = db.Column(db.String(20), nullable=True)

    # New columns for workspace and repository type support
    workspace_id = db.Column(db.String(24), nullable=True)
    repo_type = db.Column(
        db.String(50), nullable=True
    )  # 'git', 'github', 'gitlab', 'azure', etc.

    # Metadata
    reason = db.Column(db.Text)
    ignored_at = db.Column(db.DateTime, default=datetime.utcnow)
    ignored_by = db.Column(db.String(255))
    worksheet_number = db.Column(db.Integer, nullable=False, default=1)

    # Update the composite indexes to include cwe_id
    __table_args__ = (
        db.Index(
            "idx_ignore_lookup",
            "user_id",
            "repo_name",
            "ignore_type",
            "finding_id",
            "file_path",
        ),
        # ADD THIS NEW INDEX for CWE lookups
        db.Index(
            "idx_cwe_lookup",
            "user_id",
            "repo_name",
            "ignore_type",
            "cwe_id",
            "file_path",
        ),
        db.Index("idx_user_repo", "user_id", "repo_name"),
        db.Index("idx_ignore_user_worksheet", "user_id", "worksheet_number"),
        db.Index(
            "idx_ignore_user_repo_worksheet", "user_id", "repo_name", "worksheet_number"
        ),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "repo_name": self.repo_name,
            "ignore_type": self.ignore_type,
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "code_snippet": self.code_snippet,
            "cwe_id": self.cwe_id,  # ADD THIS LINE
            "reason": self.reason,
            "ignored_at": self.ignored_at.isoformat(),
            "ignored_by": self.ignored_by,
            "worksheet_number": self.worksheet_number,
        }


class GitHubAnalysisResult(db.Model):
    __tablename__ = "github_analysis_results"

    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    repository_owner = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)
    worksheet_number = db.Column(db.Integer, nullable=False, default=1)
    repository_url = db.Column(db.String(500))
    branch_name = db.Column(db.String(255), default="main")

    # Composite indexes for efficient lookups
    __table_args__ = (
        db.Index(
            "idx_github_owner_repo",
            "repository_owner",
            "repository_name",
        ),
        db.Index("idx_github_user_owner", "user_id", "repository_owner"),
        db.Index("idx_github_user_worksheet", "user_id", "worksheet_number"),
        db.Index(
            "idx_github_user_owner_worksheet",
            "user_id",
            "repository_owner",
            "worksheet_number",
        ),
        db.Index("idx_github_repo_user", "repository_name", "user_id"),
        db.Index("idx_github_status", "status"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "repository_name": self.repository_name,
            "repository_owner": self.repository_owner,
            "repository_url": self.repository_url,
            "branch_name": self.branch_name,
            "user_id": self.user_id,
            "worksheet_number": self.worksheet_number,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "rerank": self.rerank,
        }


class GitLabAnalysisResult(db.Model):
    __tablename__ = "gitlab_scan_results"

    id = db.Column(db.Integer, primary_key=True)
    repository_name = db.Column(db.String(255), nullable=False)
    project_id = db.Column(db.String(255), nullable=False)
    project_path = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255))
    rerank = db.Column(JSONB)
    workspace = db.Column(db.String(24), nullable=True)
    gitlab_instance_url = db.Column(db.String(500))
    branch_name = db.Column(db.String(255), default="main")
    scanned_commit_sha = db.Column(db.String(64), nullable=True)

    # Composite indexes for efficient lookups
    __table_args__ = (
        db.Index("idx_gitlab_scan_project_id", "project_id"),
        db.Index("idx_gitlab_scan_project_path", "project_path"),
        db.Index("idx_gitlab_scan_user_project", "user_id", "project_id"),
        db.Index("idx_gitlab_scan_user_workspace", "user_id", "workspace"),
        db.Index(
            "idx_gitlab_scan_user_project_workspace",
            "user_id",
            "project_id",
            "workspace",
        ),
        db.Index("idx_gitlab_scan_repo_user", "repository_name", "user_id"),
        db.Index("idx_gitlab_scan_status", "status"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "repository_name": self.repository_name,
            "project_id": self.project_id,
            "project_path": self.project_path,
            "gitlab_instance_url": self.gitlab_instance_url,
            "branch_name": self.branch_name,
            "user_id": self.user_id,
            "workspace": self.workspace,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "rerank": self.rerank,
        }


class ZapScanResult(db.Model):
    __tablename__ = "zap_scan_results"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(500), nullable=False)
    scan_type = db.Column(
        db.String(20), nullable=False, default="baseline"
    )  # baseline, full, ajax
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="pending")
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    user_id = db.Column(db.String(255), nullable=False)
    workspace_id = db.Column(db.String(24), nullable=True)
    worksheet_number = db.Column(db.Integer, nullable=False, default=1)
    rerank = db.Column(JSONB)
    completed_at = db.Column(db.DateTime)
    scan_duration_seconds = db.Column(db.Integer)
    findings_count = db.Column(db.Integer, default=0)
    severity_counts = db.Column(JSONB)  #  severity breakdown
    zap_version = db.Column(db.String(50))  # ZAP version used
    zap_exit_code = db.Column(db.Integer, nullable=True)  # ZAP exit code for debugging
    report_path = db.Column(db.String(1024))

    __table_args__ = (
        db.Index("idx_zap_scan_user_id", "user_id"),
        db.Index("idx_zap_scan_user_workspace", "user_id", "workspace_id"),
        db.Index("idx_zap_scan_user_worksheet", "user_id", "worksheet_number"),
        db.Index(
            "idx_zap_scan_user_workspace_worksheet",
            "user_id",
            "workspace_id",
            "worksheet_number",
        ),
        db.Index("idx_zap_scan_target_url", "target_url"),
        db.Index("idx_zap_scan_scan_type", "scan_type"),
        db.Index("idx_zap_scan_status", "status"),
        db.Index("idx_zap_scan_timestamp", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "user_id": self.user_id,
            "workspace_id": str(self.workspace_id) if self.workspace_id else None,
            "worksheet_number": self.worksheet_number,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "rerank": self.rerank,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "scan_duration_seconds": self.scan_duration_seconds,
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts,
            "zap_version": self.zap_version,
            "zap_exit_code": self.zap_exit_code,
            "report_path": self.report_path,
        }


class FixRequest(db.Model):
    """
    Track status of fix PRs created for security findings.
    """

    __tablename__ = "fix_requests"

    id = db.Column(db.Integer, primary_key=True)

    # User and workspace context
    user_id = db.Column(db.String(255), nullable=False)
    workspace_id = db.Column(db.String(24), nullable=True)

    # Repository information
    repo_type = db.Column(
        db.String(50), nullable=False
    )  # github, gitlab, azure_devops, etc.
    repo_identifier = db.Column(db.String(512), nullable=False)  # Full repo URL or path
    branch_name = db.Column(db.String(255), default="main")

    # Finding information
    finding_id = db.Column(
        db.String(255), nullable=False
    )  # Rule ID of the security finding (e.g., "javascript.express.security.sql-injection")
    file_path = db.Column(db.String(500), nullable=False)
    line_start = db.Column(
        db.Integer, nullable=True
    )  # Starting line number of the finding
    cwe_id = db.Column(
        db.String(200), nullable=True
    )  # Increased to handle full CWE descriptions
    severity = db.Column(db.String(50), nullable=True)  # critical, high, medium, low

    # PR/Fix details
    pr_url = db.Column(db.String(500), nullable=True)  # URL to the pull request
    pr_number = db.Column(db.String(50), nullable=True)  # PR number/ID
    pr_title = db.Column(db.String(500), nullable=True)

    # Status tracking
    status = db.Column(
        db.String(50), default="pending"
    )  # pending, pr_created, pr_merged, pr_closed, failed
    fix_description = db.Column(db.Text, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )
    pr_created_at = db.Column(db.DateTime, nullable=True)
    pr_merged_at = db.Column(db.DateTime, nullable=True)
    pr_closed_at = db.Column(db.DateTime, nullable=True)

    # Additional metadata
    error = db.Column(db.Text, nullable=True)
    additional_data = db.Column(
        JSONB, nullable=True
    )  # For any additional data (renamed from metadata to avoid SQLAlchemy conflict)

    # Webhook tracking
    webhook_url = db.Column(db.String(500), nullable=True)  # If set, webhook is enabled

    # Indexes for efficient lookups
    __table_args__ = (
        db.Index("idx_fix_request_user_id", "user_id"),
        db.Index("idx_fix_request_workspace", "workspace_id"),
        db.Index("idx_fix_request_user_workspace", "user_id", "workspace_id"),
        db.Index("idx_fix_request_repo", "repo_type", "repo_identifier"),
        db.Index(
            "idx_fix_request_finding", "finding_id", "file_path", "line_start"
        ),  # Composite index for finding lookup
        db.Index("idx_fix_request_status", "status"),
        db.Index("idx_fix_request_pr_number", "repo_identifier", "pr_number"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": str(self.workspace_id) if self.workspace_id else None,
            "repo_type": self.repo_type,
            "repo_identifier": self.repo_identifier,
            "branch_name": self.branch_name,
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "cwe_id": self.cwe_id,
            "severity": self.severity,
            "pr_url": self.pr_url,
            "pr_number": self.pr_number,
            "pr_title": self.pr_title,
            "status": self.status,
            "fix_description": self.fix_description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "pr_created_at": (
                self.pr_created_at.isoformat() if self.pr_created_at else None
            ),
            "pr_merged_at": (
                self.pr_merged_at.isoformat() if self.pr_merged_at else None
            ),
            "pr_closed_at": (
                self.pr_closed_at.isoformat() if self.pr_closed_at else None
            ),
            "error": self.error,
            "additional_data": self.additional_data,
            "webhook_enabled": bool(self.webhook_url),  # Derived from webhook_url
            "webhook_url": self.webhook_url,
        }


class RepositoryScanResult(db.Model):
    """
    Unified table for all repository scan results across different platforms.

    repo_identifier format by platform:
    - GitHub: https://github.com/{owner}/{repo}
    - GitLab: https://gitlab.com/{owner}/{repo}
    - Azure DevOps: https://dev.azure.com/{org}/{project}/_git/{repo}
    - AWS CodeCommit: https://git-codecommit.{region}.amazonaws.com/v1/repos/{repo}
    """

    __tablename__ = "repository_scan_results"

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.String(255))
    workspace_id = db.Column(db.String(24), nullable=True)

    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc))

    repo_type = db.Column(
        db.String(50), nullable=False
    )  # github, gitlab, azure_devops, codecommit
    repo_identifier = db.Column(db.String(512), nullable=False)  # Full URL or path
    branch_name = db.Column(db.String(255), default="main")

    status = db.Column(db.String(50), default="pending")
    results = db.Column(JSONB)
    error = db.Column(db.Text)
    rerank = db.Column(JSONB)

    # Composite indexes for efficient lookups
    __table_args__ = (
        db.Index("idx_repo_type_identifier", "repo_type", "repo_identifier"),
        db.Index("idx_repo_user_type", "user_id", "repo_type"),
        db.Index("idx_repo_user_workspace", "user_id", "workspace_id"),
        db.Index("idx_repo_workspace_id", "workspace_id"),
        db.Index("idx_repo_status", "status"),
        db.Index("idx_repo_timestamp", "timestamp"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "repo_type": self.repo_type,
            "repo_identifier": self.repo_identifier,
            "repository_name": self.repository_name,
            "branch_name": self.branch_name,
            "user_id": self.user_id,
            "workspace_id": (str(self.workspace_id) if self.workspace_id else None),
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "results": self.results,
            "error": self.error,
            "rerank": self.rerank,
        }
