"""
HashLens Database Layer
SQLAlchemy engine, session factory, and schema initialization.
Configured for SQLite development with PostgreSQL production compatibility.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from backend.app.core.config import settings

def get_normalized_database_url(url: str) -> str:
    """Normalizes database connection URLs (e.g. postgres:// -> postgresql+psycopg://)."""
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://") and not url.startswith("postgresql+"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


normalized_db_url = get_normalized_database_url(settings.DATABASE_URL)

engine_kwargs = {"echo": False, "future": True}
if normalized_db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = 5
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_recycle"] = 1800

engine = create_engine(normalized_db_url, **engine_kwargs)

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
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Creates database tables if they do not exist and applies lightweight SQLite column migrations."""
    db_url = get_normalized_database_url(settings.DATABASE_URL)

    # Ensure directory exists for sqlite file
    if db_url.startswith("sqlite:///"):
        sqlite_path = db_url.replace("sqlite:///", "")
        from pathlib import Path
        Path(sqlite_path).parent.mkdir(parents=True, exist_ok=True)

    Base.metadata.create_all(bind=engine)

    # Lightweight SQLite schema auto-migration for user_id columns and index fixes on existing databases
    if db_url.startswith("sqlite"):
        from sqlalchemy import inspect, text
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        with engine.begin() as conn:
            for table in ["tracked_files", "file_versions", "integrity_chain", "evidence_reports"]:
                if table in tables:
                    columns = [c["name"] for c in inspector.get_columns(table)]
                    if "user_id" not in columns:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id)"))
            
            # Ensure sequence_num index on integrity_chain is non-unique for per-user sequencing
            if "integrity_chain" in tables:
                try:
                    conn.execute(text("DROP INDEX IF EXISTS ix_integrity_chain_sequence_num"))
                    conn.execute(text("CREATE INDEX IF NOT EXISTS ix_integrity_chain_sequence_num ON integrity_chain (sequence_num)"))
                except Exception:
                    pass



