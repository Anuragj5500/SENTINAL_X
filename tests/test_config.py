from backend.config import Settings

def test_database_url_conversion():
    # Test SQLite URL remains unchanged
    settings = Settings(DATABASE_URL="sqlite+aiosqlite:///./sentinelx.db")
    assert settings.DATABASE_URL == "sqlite+aiosqlite:///./sentinelx.db"

    # Test postgres:// url converts to postgresql+asyncpg://
    settings = Settings(DATABASE_URL="postgres://user:pass@host:5432/dbname")
    assert settings.DATABASE_URL == "postgresql+asyncpg://user:pass@host:5432/dbname"

    # Test postgresql:// url converts to postgresql+asyncpg://
    settings = Settings(DATABASE_URL="postgresql://user:pass@host:5432/dbname")
    assert settings.DATABASE_URL == "postgresql+asyncpg://user:pass@host:5432/dbname"

    # Test postgresql+asyncpg:// url remains unchanged
    settings = Settings(DATABASE_URL="postgresql+asyncpg://user:pass@host:5432/dbname")
    assert settings.DATABASE_URL == "postgresql+asyncpg://user:pass@host:5432/dbname"
