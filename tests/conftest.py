"""
Pytest configuration and global fixtures for HashLens.
Configures an isolated temporary SQLite test database and client fixture.
"""

import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.db.database import Base, get_db
from backend.app.main import app

TEST_DB_URL = "sqlite:///./data/test_hashlens.db"
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False}, future=True)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine, future=True)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def clean_test_db():
    """Drops and recreates all tables before each test to guarantee test isolation."""
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    """Provides a fresh test client connected to the isolated database."""
    with TestClient(app) as c:
        yield c
