"""add claim gate to agents

Revision ID: dc68a8b7ce70
Revises: 0d3836d351ae
Create Date: 2026-07-03 18:18:36.505909

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'dc68a8b7ce70'
down_revision: Union[str, Sequence[str], None] = '0d3836d351ae'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('claim_token', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('claimed_at', sa.Float(), nullable=True))
        batch_op.create_index(batch_op.f('ix_agents_claim_token'), ['claim_token'], unique=True)

    # Pre-existing agents predate the claim gate — backfill claimed_at from
    # created_at so they aren't retroactively locked out of /auth/challenge.
    # claim_token stays NULL for them; they never had one and don't need one.
    op.execute('UPDATE agents SET claimed_at = created_at WHERE claimed_at IS NULL')


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agents_claim_token'))
        batch_op.drop_column('claimed_at')
        batch_op.drop_column('claim_token')
