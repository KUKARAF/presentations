"""add oidc_subject to user for OpenID Connect sign-in

Revision ID: a3c5e7f9b1d2
Revises: 026c0ba8b35c
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "a3c5e7f9b1d2"
down_revision: str | None = "026c0ba8b35c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "user" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("user")}
    if "oidc_subject" not in columns:
        with op.batch_alter_table("user") as batch:
            batch.add_column(sa.Column("oidc_subject", sa.String(length=512), nullable=True))

    indexes = {index["name"] for index in sa.inspect(op.get_bind()).get_indexes("user")}
    if "uq_user_oidc_subject" not in indexes:
        op.create_index(
            "uq_user_oidc_subject",
            "user",
            ["oidc_subject"],
            unique=True,
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if "user" not in inspector.get_table_names():
        return
    indexes = {index["name"] for index in inspector.get_indexes("user")}
    if "uq_user_oidc_subject" in indexes:
        op.drop_index("uq_user_oidc_subject", table_name="user")
    columns = {column["name"] for column in inspector.get_columns("user")}
    if "oidc_subject" in columns:
        with op.batch_alter_table("user") as batch:
            batch.drop_column("oidc_subject")
