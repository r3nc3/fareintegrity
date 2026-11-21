import os
import tempfile
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _normalize_database_url(url):
    parts = urlsplit(url)
    scheme = parts.scheme
    if scheme in {"postgres", "postgresql", "postgresql+psycopg2"}:
        scheme = "postgresql+psycopg"

    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    pooler_flag = query.pop("pgbouncer", "").lower() in {"1", "true", "yes", "on"}
    transaction_pooler = pooler_flag or parts.port == 6543

    host = (parts.hostname or "").lower()
    if host.endswith((".supabase.com", ".supabase.co")):
        query.setdefault("sslmode", "require")

    normalized = urlunsplit(
        (scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )
    return normalized, transaction_pooler


DATABASE_URL = os.environ.get("DATABASE_URL") or os.environ.get("SUPABASE_DATABASE_URL")
TRANSACTION_POOLER = False
if DATABASE_URL:
    DATABASE_URL, TRANSACTION_POOLER = _normalize_database_url(DATABASE_URL)

if DATABASE_URL:
    engine_options = {"pool_pre_ping": True}
    if TRANSACTION_POOLER:
        engine_options["poolclass"] = NullPool
        engine_options["connect_args"] = {"prepare_threshold": None}
    else:
        engine_options["pool_size"] = 1
        engine_options["max_overflow"] = 2
    engine = create_engine(DATABASE_URL, **engine_options)
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
