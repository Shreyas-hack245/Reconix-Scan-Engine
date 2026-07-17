"""
SQLAlchemy declarative base for Reconix Scan Engine.

All ORM models inherit from `Base` defined here. This module also
imports all model modules so that Alembic autogeneration and
`Base.metadata.create_all` can discover every mapped class.
"""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Base class for all ORM models in Reconix Scan Engine."""
    pass


# Import models so they are registered on Base.metadata.
# These imports are intentionally placed at the bottom to avoid circular imports.
from app.models import user  # noqa: E402,F401
from app.models import scan  # noqa: E402,F401
from app.models import endpoint  # noqa: E402,F401
from app.models import finding  # noqa: E402,F401
from app.models import audit_log  # noqa: E402,F401