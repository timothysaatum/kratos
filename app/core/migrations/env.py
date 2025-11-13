import sys
import os
from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context

# Add app to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))
from app.core.config import Settings
from app.core.database import Base

# Import all models to ensure they are registered with Base.metadata
from app.models.electorates import Electorate, VotingToken, DeviceRegistration, RegistrationLink, VotingSession

settings = Settings()

# Alembic Config object
config = context.config
fileConfig(config.config_file_name)

target_metadata = Base.metadata


# Always use a synchronous driver for Alembic migrations
def get_url():
    return os.getenv("ALEMBIC_DATABASE_URL", "sqlite:///./db.sqlite3")


def run_migrations_offline():
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        url=get_url(),
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
