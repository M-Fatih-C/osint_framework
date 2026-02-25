"""Add case management tables and scan-case link

Revision ID: 20260225_0002
Revises: 20260224_0001
Create Date: 2026-02-25 02:55:00
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "20260225_0002"
down_revision: Union[str, None] = "20260224_0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("priority", sa.String(), nullable=False, server_default="normal"),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cases_title", "cases", ["title"], unique=False)
    op.create_index("ix_cases_status", "cases", ["status"], unique=False)

    op.create_table(
        "case_targets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("target_value", sa.String(), nullable=False),
        sa.Column("target_type", sa.String(), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "case_id", "target_value", "target_type", name="uq_case_targets_case_value_type"
        ),
    )
    op.create_index("ix_case_targets_case_id", "case_targets", ["case_id"], unique=False)

    op.create_table(
        "case_notes",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("content", sa.String(), nullable=False),
        sa.Column("author", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_notes_case_id", "case_notes", ["case_id"], unique=False)

    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.add_column(sa.Column("case_id", sa.Integer(), nullable=True))
        batch_op.create_index("ix_scans_case_id", ["case_id"], unique=False)
        batch_op.create_foreign_key("fk_scans_case_id_cases", "cases", ["case_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("scans", schema=None) as batch_op:
        batch_op.drop_constraint("fk_scans_case_id_cases", type_="foreignkey")
        batch_op.drop_index("ix_scans_case_id")
        batch_op.drop_column("case_id")

    op.drop_index("ix_case_notes_case_id", table_name="case_notes")
    op.drop_table("case_notes")

    op.drop_index("ix_case_targets_case_id", table_name="case_targets")
    op.drop_table("case_targets")

    op.drop_index("ix_cases_status", table_name="cases")
    op.drop_index("ix_cases_title", table_name="cases")
    op.drop_table("cases")
