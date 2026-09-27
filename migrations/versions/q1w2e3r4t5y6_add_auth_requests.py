"""Add auth_requests table and key provenance columns for OAuth key requests.

Revision ID: q1w2e3r4t5y6
Revises: d0e1f2a3b4c5
"""

import sqlalchemy as sa
from alembic import op

revision = "q1w2e3r4t5y6"
down_revision = "d0e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "auth_requests",
        sa.Column("id", sa.Integer(), primary_key=True, comment="Primary key"),
        sa.Column("flow", sa.String(16), nullable=False, comment="Request flow: device or code"),
        sa.Column("client_id", sa.String(128), nullable=False, comment="Free-form application label supplied by the requester (unverified)"),
        sa.Column("requested_name", sa.String(128), nullable=False, comment="Name the requester wants for the API key"),
        sa.Column("author", sa.String(128), nullable=True, comment="Free-form requester label supplied by the request (unverified)"),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending", comment="pending, approved, denied, or claimed"),
        sa.Column("created_at", sa.DateTime(), nullable=False, comment="UTC creation timestamp"),
        sa.Column("expires_at", sa.DateTime(), nullable=False, comment="UTC functional expiry; approval may extend it by the claim window"),
        sa.Column("device_code_hash", sa.String(64), nullable=True, comment="SHA-256 hash of the device-flow polling secret"),
        sa.Column("user_code", sa.String(9), nullable=True, comment="Human-echoed XXXX-XXXX confirmation code shown on the consent page (cannot fetch a key)"),
        sa.Column("last_polled_at", sa.DateTime(), nullable=True, comment="UTC timestamp of the most recent token poll; drives slow_down"),
        sa.Column("redirect_uri", sa.Text(), nullable=True, comment="Code-flow destination the user approved; must match exactly at redemption"),
        sa.Column("code_challenge", sa.String(128), nullable=True, comment="Code-flow S256 challenge binding redemption to the client that holds the verifier"),
        sa.Column("auth_code_hash", sa.String(64), nullable=True, comment="SHA-256 hash of the short-lived authorization code, set at approval"),
        sa.Column("auth_code_expires_at", sa.DateTime(), nullable=True, comment="UTC expiry of the authorization code (60s after approval)"),
        sa.Column("entity_id", sa.Integer(), sa.ForeignKey("entities.id", ondelete="CASCADE"), nullable=True, comment="Approving entity; set at approval"),
        sa.Column("overwrite", sa.Boolean(), nullable=False, server_default=sa.false(), comment="Approver agreed to replace an existing same-name key (executed at mint)"),
        sa.Column("approved_at", sa.DateTime(), nullable=True, comment="UTC approval timestamp"),
        sa.Column("api_key_id", sa.Integer(), sa.ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True, comment="Key minted at claim; retained to revoke on authorization-code replay"),
        sa.CheckConstraint("flow IN ('device', 'code')", name="ck_auth_requests_flow"),
        sa.CheckConstraint("status IN ('pending', 'approved', 'denied', 'claimed')", name="ck_auth_requests_status"),
        comment="OAuth key requests (device flow and PKCE authorization-code flow) from creation to claim",
    )
    op.create_index("ix_auth_requests_expires_at", "auth_requests", ["expires_at"])
    op.create_index("uq_auth_requests_device_code_hash", "auth_requests", ["device_code_hash"], unique=True)
    op.create_index("uq_auth_requests_auth_code_hash", "auth_requests", ["auth_code_hash"], unique=True)
    # A user code identifies exactly one live request; handled/expired rows keep
    # their codes until the janitor removes them.
    op.create_index(
        "uq_auth_requests_pending_user_code",
        "auth_requests",
        ["user_code"],
        unique=True,
        postgresql_where=sa.text("status = 'pending'"),
        sqlite_where=sa.text("status = 'pending'"),
    )

    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.add_column(sa.Column(
            "client_id", sa.String(128), nullable=True,
            comment="Application label from the OAuth request that minted this key; null for manually created keys",
        ))
        batch_op.add_column(sa.Column(
            "requested_by", sa.String(128), nullable=True,
            comment="Requester label from the OAuth request that minted this key; null for manually created keys",
        ))


def downgrade():
    with op.batch_alter_table("api_keys") as batch_op:
        batch_op.drop_column("requested_by")
        batch_op.drop_column("client_id")
    op.drop_index("uq_auth_requests_pending_user_code", table_name="auth_requests")
    op.drop_index("uq_auth_requests_auth_code_hash", table_name="auth_requests")
    op.drop_index("uq_auth_requests_device_code_hash", table_name="auth_requests")
    op.drop_index("ix_auth_requests_expires_at", table_name="auth_requests")
    op.drop_table("auth_requests")
