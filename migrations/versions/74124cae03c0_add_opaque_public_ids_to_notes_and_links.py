"""add opaque public ids to notes and links

Revision ID: 74124cae03c0
Revises: dc68a8b7ce70
Create Date: 2026-07-05 09:50:26.501846

"""
import base64
import os
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '74124cae03c0'
down_revision: Union[str, Sequence[str], None] = 'dc68a8b7ce70'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _new_public_id() -> str:
    # Matches crypto.b64e's shape (urlsafe base64, no padding) without
    # importing the app package from a migration.
    return base64.urlsafe_b64encode(os.urandom(12)).rstrip(b"=").decode("ascii")


def upgrade() -> None:
    """Upgrade schema.

    The raw auto-incrementing `id` stays exactly as-is internally (every FK,
    the supersession chain, link storage all keep referencing it) — this
    only adds an opaque, externally-facing alias. Sequential ids leak
    aggregate note/link counts platform-wide to anyone who can see their own;
    an unguessable token carries no information about anything but itself.
    """
    bind = op.get_bind()

    with op.batch_alter_table('notes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('public_id', sa.String(), nullable=True))
    for (row_id,) in bind.execute(sa.text('SELECT id FROM notes')):
        bind.execute(
            sa.text('UPDATE notes SET public_id = :pid WHERE id = :id'),
            {'pid': _new_public_id(), 'id': row_id},
        )
    with op.batch_alter_table('notes', schema=None) as batch_op:
        batch_op.alter_column('public_id', nullable=False)
        batch_op.create_index(batch_op.f('ix_notes_public_id'), ['public_id'], unique=True)

    with op.batch_alter_table('links', schema=None) as batch_op:
        batch_op.add_column(sa.Column('public_id', sa.String(), nullable=True))
    for (row_id,) in bind.execute(sa.text('SELECT id FROM links')):
        bind.execute(
            sa.text('UPDATE links SET public_id = :pid WHERE id = :id'),
            {'pid': _new_public_id(), 'id': row_id},
        )
    with op.batch_alter_table('links', schema=None) as batch_op:
        batch_op.alter_column('public_id', nullable=False)
        batch_op.create_index(batch_op.f('ix_links_public_id'), ['public_id'], unique=True)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('links', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_links_public_id'))
        batch_op.drop_column('public_id')

    with op.batch_alter_table('notes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_notes_public_id'))
        batch_op.drop_column('public_id')
