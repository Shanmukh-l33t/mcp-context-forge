# -*- coding: utf-8 -*-
# pylint: disable=no-member
"""Location: ./mcpgateway/alembic/versions/r4t7y9u1o3p5_add_gateway_reachability_reason.py
Copyright contributors to the MCP-CONTEXT-FORGE project
SPDX-License-Identifier: Apache-2.0

Add the enumerated reachability_reason column to gateways.

Revision ID: r4t7y9u1o3p5
Revises: e5c2a7b91f4d

``reachability_reason`` on gateways records why a gateway is in its current
reachability state as an enumeration instead of free text: ``auth_failed``
(the probe answered 401/403 - the server is reachable but rejected the
credential) or ``unreachable`` (the health-check failure threshold was
reached). NULL means healthy or not yet probed. It is surfaced on
``GatewayRead`` so clients can branch on the value instead of pattern
matching error strings.
"""

# Standard
from typing import Sequence, Union

# Third-Party
from alembic import op
import sqlalchemy as sa

revision: str = "r4t7y9u1o3p5"  # pragma: allowlist secret
down_revision: Union[str, Sequence[str], None] = "e5c2a7b91f4d"  # pragma: allowlist secret
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "gateways"
COLUMN = "reachability_reason"


def upgrade() -> None:
    """Add the nullable column to gateways when the table exists and lacks it."""
    inspector = sa.inspect(op.get_bind())
    if TABLE not in inspector.get_table_names():
        return
    present = {column["name"] for column in inspector.get_columns(TABLE)}
    if COLUMN not in present:
        op.add_column(TABLE, sa.Column(COLUMN, sa.String(32), nullable=True))


def downgrade() -> None:
    """Drop the column from gateways when it is present."""
    inspector = sa.inspect(op.get_bind())
    if TABLE not in inspector.get_table_names():
        return
    present = {column["name"] for column in inspector.get_columns(TABLE)}
    if COLUMN in present:
        op.drop_column(TABLE, COLUMN)
