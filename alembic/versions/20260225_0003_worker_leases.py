"""Add worker lease/heartbeat columns to scans

Revision ID: 20260225_0003
Revises: 20260225_0002
Create Date: 2026-02-25 03:25:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260225_0003"
down_revision: Union[str, None] = "20260225_0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("worker_lease_owner", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("worker_heartbeat_at", sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column("worker_lease_expires_at", sa.DateTime(), nullable=True))
        batch_op.create_index("ix_scans_worker_lease_owner", ["worker_lease_owner"], unique=False)
        batch_op.create_index("ix_scans_worker_heartbeat_at", ["worker_heartbeat_at"], unique=False)
        batch_op.create_index("ix_scans_worker_lease_expires_at", ["worker_lease_expires_at"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_index("ix_scans_worker_lease_expires_at")
        batch_op.drop_index("ix_scans_worker_heartbeat_at")
        batch_op.drop_index("ix_scans_worker_lease_owner")
        batch_op.drop_column("worker_lease_expires_at")
        batch_op.drop_column("worker_heartbeat_at")
        batch_op.drop_column("worker_lease_owner")
