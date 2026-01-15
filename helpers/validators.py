from pydantic import BaseModel, ValidationError, model_validator


# scan endpoints
class ScanRepoCommon(BaseModel):
    repo_type: str
    org_name: str
    repo_name: str
    hosted_git_url: str | None = None
    workspace_id: str
    user_id: str


class ScanRepoGithub(ScanRepoCommon):
    installation_id: str


class ScanRepoAzureDevops(ScanRepoCommon):
    project_name: str
    PAT: str


class ScanRepoGitlab(ScanRepoCommon):
    access_token: str


class ScanRepoCodecommit(ScanRepoCommon):
    aws_access_key_id: str
    aws_secret_access_key: str
