"""add feedback table and agent root encryption key

Revision ID: b5a46ee31843
Revises: 381a2951cd04
Create Date: 2026-07-06 22:17:23.145954

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5a46ee31843'
down_revision: Union[str, Sequence[str], None] = '381a2951cd04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('feedback',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('agent_id', sa.String(), nullable=False),
    sa.Column('kind', sa.String(), nullable=False),
    sa.Column('message', sa.LargeBinary(), nullable=False),
    sa.Column('handled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.Float(), nullable=False),
    sa.ForeignKeyConstraint(['agent_id'], ['agents.identifier'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_feedback_agent_id'), ['agent_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_feedback_created_at'), ['created_at'], unique=False)

    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('root_encryption_public_key', sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('agents', schema=None) as batch_op:
        batch_op.drop_column('root_encryption_public_key')

    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_feedback_created_at'))
        batch_op.drop_index(batch_op.f('ix_feedback_agent_id'))

    op.drop_table('feedback')
