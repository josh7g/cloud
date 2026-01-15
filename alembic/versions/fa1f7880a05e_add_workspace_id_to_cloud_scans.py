"""add_workspace_id_to_cloud_scans

Revision ID: fa1f7880a05e
Revises: 6a406f3fdfd1
Create Date: 2026-01-15 08:51:42.486666

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'fa1f7880a05e'
down_revision: Union[str, None] = '6a406f3fdfd1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add workspace_id column to cloud_scans
    op.add_column(
        "cloud_scans",
        sa.Column("workspace_id", sa.String(length=24), nullable=True),
    )

    # Create indexes for workspace-based filtering
    op.create_index(
        "idx_cloud_scans_workspace_id",
        "cloud_scans",
        ["workspace_id"],
        unique=False,
    )
    op.create_index(
        "idx_cloud_scans_user_workspace",
        "cloud_scans",
        ["user_id", "workspace_id"],
        unique=False,
    )
    op.create_index(
        "idx_cloud_scans_user_workspace_cloudname",
        "cloud_scans",
        ["user_id", "workspace_id", "cloudname"],
        unique=False,
    )


def downgrade() -> None:
    # Drop indexes first (reverse order of creation is safest)
    op.drop_index(
        "idx_cloud_scans_user_workspace_cloudname",
        table_name="cloud_scans",
    )
    op.drop_index(
        "idx_cloud_scans_user_workspace",
        table_name="cloud_scans",
    )
    op.drop_index(
        "idx_cloud_scans_workspace_id",
        table_name="cloud_scans",
    )

    # Drop workspace_id column
    op.drop_column("cloud_scans", "workspace_id")
