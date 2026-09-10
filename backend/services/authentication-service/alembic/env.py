import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Make the auth-service package importable regardless of CWD
_AUTH_SERVICE_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, _AUTH_SERVICE_DIR)

# Modular service packages + shared contracts live beside the auth service.
# Migrations import the composed model metadata, which now spans packages.
_BACKEND_ROOT = os.path.dirname(os.path.dirname(_AUTH_SERVICE_DIR))
for _mod in ("shared", "services/tenant-service", "services/notification-service"):
    sys.path.insert(0, os.path.join(_BACKEND_ROOT, _mod))

from app.core.config import settings  # noqa: E402
from app.db.base import Base  # noqa: E402
from app import models as _models_import  # noqa: E402,F401

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Override the sqlalchemy.url from the app settings if provided
if settings.DATABASE_URL:
    config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
