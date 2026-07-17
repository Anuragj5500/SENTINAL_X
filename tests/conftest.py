"""
Shared test fixtures for SentinelX test suite.
Provides test database, test client, and authenticated user helpers.
"""
import asyncio
import pytest
import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from backend.models import Base, User, UserRole, generate_uuid
from backend.database import get_db
from backend.main import app
import bcrypt


TEST_DB_URL = "sqlite+aiosqlite:///./test_sentinelx.db"

engine = create_async_engine(TEST_DB_URL, echo=False)
TestSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(scope="session", autouse=True)
def setup_db():
    """Create all tables once per test session."""
    loop = asyncio.new_event_loop()
    async def create_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    loop.run_until_complete(create_tables())
    yield
    async def drop_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    loop.run_until_complete(drop_tables())
    loop.close()


@pytest.fixture
async def db_session():
    """Provide a transactional test database session."""
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client(db_session):
    """Provide an authenticated async test client."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


def make_test_user(
    username: str = "testuser",
    role: UserRole = UserRole.super_admin,
    password: str = "TestPass123!",
) -> User:
    """Create a User object for testing."""
    return User(
        id=generate_uuid(),
        username=username,
        email=f"{username}@test.com",
        full_name=f"Test {username.title()}",
        role=role,
        hashed_password=bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        is_active=True,
    )


@pytest.fixture
async def test_user(db_session) -> User:
    """Insert a test user into the database."""
    user = make_test_user()
    db_session.add(user)
    await db_session.flush()
    return user
