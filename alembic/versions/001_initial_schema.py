"""Initial Schema Migration

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-20 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("username", sa.String(length=100), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.String(length=50), nullable=False),
        sa.Column("updated_at", sa.String(length=50), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    op.create_index(op.f("ix_users_id"), "users", ["id"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=True)
    op.create_index(op.f("ix_users_username"), "users", ["username"], unique=True)

    # 2. tracked_files
    op.create_table(
        "tracked_files",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("file_type", sa.String(length=100), nullable=False),
        sa.Column("created_at", sa.String(length=50), nullable=False),
        sa.Column("updated_at", sa.String(length=50), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tracked_files_id"), "tracked_files", ["id"], unique=False)
    op.create_index(op.f("ix_tracked_files_user_id"), "tracked_files", ["user_id"], unique=False)
    op.create_index(op.f("ix_tracked_files_filename"), "tracked_files", ["filename"], unique=False)

    # 3. file_versions
    op.create_table(
        "file_versions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("file_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("version_num", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.String(length=50), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("size_human", sa.String(length=50), nullable=False),
        sa.Column("md5", sa.String(length=32), nullable=False),
        sa.Column("sha1", sa.String(length=40), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("sha512", sa.String(length=128), nullable=False),
        sa.Column("chunk_size", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("chunk_fingerprints_json", sa.Text(), nullable=False),
        sa.Column("metadata_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("integrity_status", sa.String(length=50), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["file_id"], ["tracked_files.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_file_versions_id"), "file_versions", ["id"], unique=False)
    op.create_index(op.f("ix_file_versions_file_id"), "file_versions", ["file_id"], unique=False)
    op.create_index(op.f("ix_file_versions_user_id"), "file_versions", ["user_id"], unique=False)
    op.create_index(op.f("ix_file_versions_sha256"), "file_versions", ["sha256"], unique=False)

    # 4. integrity_chain
    op.create_table(
        "integrity_chain",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("record_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("sequence_num", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.String(length=50), nullable=False),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("file_id", sa.String(length=64), nullable=True),
        sa.Column("file_hash", sa.String(length=64), nullable=False),
        sa.Column("previous_record_hash", sa.String(length=64), nullable=False),
        sa.Column("current_record_hash", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("record_id"),
    )
    op.create_index(op.f("ix_integrity_chain_id"), "integrity_chain", ["id"], unique=False)
    op.create_index(op.f("ix_integrity_chain_record_id"), "integrity_chain", ["record_id"], unique=True)
    op.create_index(op.f("ix_integrity_chain_user_id"), "integrity_chain", ["user_id"], unique=False)
    op.create_index(op.f("ix_integrity_chain_sequence_num"), "integrity_chain", ["sequence_num"], unique=False)
    op.create_index(op.f("ix_integrity_chain_event_type"), "integrity_chain", ["event_type"], unique=False)
    op.create_index(op.f("ix_integrity_chain_file_id"), "integrity_chain", ["file_id"], unique=False)

    # 5. evidence_reports
    op.create_table(
        "evidence_reports",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("generated_at", sa.String(length=50), nullable=False),
        sa.Column("file_id", sa.String(length=64), nullable=True),
        sa.Column("report_hash", sa.String(length=64), nullable=False),
        sa.Column("report_json", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id"),
    )
    op.create_index(op.f("ix_evidence_reports_id"), "evidence_reports", ["id"], unique=False)
    op.create_index(op.f("ix_evidence_reports_report_id"), "evidence_reports", ["report_id"], unique=True)
    op.create_index(op.f("ix_evidence_reports_user_id"), "evidence_reports", ["user_id"], unique=False)
    op.create_index(op.f("ix_evidence_reports_file_id"), "evidence_reports", ["file_id"], unique=False)
    op.create_index(op.f("ix_evidence_reports_report_hash"), "evidence_reports", ["report_hash"], unique=False)


def downgrade() -> None:
    op.drop_table("evidence_reports")
    op.drop_table("integrity_chain")
    op.drop_table("file_versions")
    op.drop_table("tracked_files")
    op.drop_table("users")
