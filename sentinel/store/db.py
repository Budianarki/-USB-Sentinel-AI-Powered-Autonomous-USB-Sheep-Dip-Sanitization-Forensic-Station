"""Database connection manager and schema initialization (SQLite WAL mode)."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

MODELS_SQL_PATH = Path(__file__).parent / "models.sql"


def get_connection(db_path: Path | str) -> sqlite3.Connection:
    """Open and configure an SQLite connection with WAL mode and foreign keys."""
    db_file = Path(db_path)
    db_file.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        str(db_file),
        timeout=30.0,
    )
    conn.row_factory = sqlite3.Row

    # Enforce SQLite WAL mode and foreign key integrity
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


@contextmanager
def db_session(db_path: Path | str) -> Generator[sqlite3.Connection, None, None]:
    """Context manager for SQLite database operations with transactional safety."""
    conn = get_connection(db_path)
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_database(db_path: Path | str) -> None:
    """Initialize database tables from models.sql."""
    if not MODELS_SQL_PATH.exists():
        raise FileNotFoundError(f"models.sql not found at {MODELS_SQL_PATH}")

    sql_script = MODELS_SQL_PATH.read_text(encoding="utf-8")
    conn = get_connection(db_path)
    try:
        conn.executescript(sql_script)
    finally:
        conn.close()
