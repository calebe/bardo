"""add account deletion gate to agents

Revision ID: 381a2951cd04
Revises: 74124cae03c0
Create Date: 2026-07-05 15:17:07.537920

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '381a2951cd04'
down_revision: Union[str, Sequence[str], None] = '74124cae03c0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('deletion_confirmations_json', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('deletion_confirmed_at', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('deletion_scheduled_at', sa.Float(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_column('deletion_scheduled_at')
        batch_op.drop_column('deletion_confirmed_at')
        batch_op.drop_column('deletion_confirmations_json')
