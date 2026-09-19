"""
HashLens Database Layer
SQLAlchemy engine, session factory, and schema initialization.
Configured for SQLite development with PostgreSQL production compatibility.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.app.core.config import settings

# SQLite needs connect_args check_same_thread=False
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    future=True,
)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for yielding database session with automated cleanup."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Creates database tables if they do not exist and applies lightweight SQLite column migrations."""
    # Ensure directory exists for sqlite file
    if settings.DATABASE_URL.startswith("sqlite:///"):
        sqlite_path = settings.DATABASE_URL.replace("sqlite:///", "")
        from pathlib import Path
        Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)

    # Lightweight SQLite schema auto-migration for user_id columns on existing databases
    if settings.DATABASE_URL.startswith("sqlite"):
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        with engine.begin() as conn:
            for table in ["tracked_files", "file_versions", "integrity_chain", "evidence_reports"]:
                if table in tables:
                    columns = [c["name"] for c in inspector.get_columns(table)]
                    if "user_id" not in columns:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)"))


