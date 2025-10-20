<%!
from alembic import util
%>
"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision or None}
Create Date: ${create_date}
"""

from alembic import op
import sqlalchemy as sa

revision = ${up_revision!r}
down_revision = ${down_revision!r}
branch_labels = ${branch_labels!r}
depends_on = ${depends_on!r}


def upgrade():
    pass


def downgrade():
    pass
