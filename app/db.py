import os
import tempfile
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

DATABASE_URL = os.environ.get("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL and DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

if DATABASE_URL:
    engine = create_engine(
        DATABASE_URL, pool_pre_ping=True, pool_size=1, max_overflow=2,
    )
else:
    if os.environ.get("VERCEL"):
        default_db = Path(tempfile.gettempdir()) / "fareguard.db"
    else:
        DATA_DIR.mkdir(exist_ok=True)
        default_db = DATA_DIR / "fareguard.db"
    DB_PATH = Path(os.environ.get("FAREGUARD_DB", default_db))
    engine = create_engine(
        f"sqlite:///{DB_PATH}",
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
    )
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
