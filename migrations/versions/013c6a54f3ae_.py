"""empty message

Revision ID: 013c6a54f3ae
Revises: 066c30830315
Create Date: 2021-10-06 10:58:53.585330

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '013c6a54f3ae'
down_revision = '066c30830315'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('password_hash', sa.String(length=128), nullable=True))
    op.add_column('users', sa.Column('email', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_column('users', 'email')
    op.drop_column('users', 'password_hash')
    # ### end Alembic commands ###
