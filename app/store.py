from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(os.getenv("APP_DB", "/var/lib/http-proxy-control/proxy.db"))


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"scrypt${salt.hex()}${digest.hex()}"


def password_matches(password: str, encoded: str) -> bool:
    try:
        scheme, salt_hex, digest_hex = encoded.split("$", 2)
        if scheme != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


class Store:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connect().close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def initialize(self) -> None:
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS listeners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                port INTEGER NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                tls_enabled INTEGER NOT NULL DEFAULT 1,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(listeners)")}
            if "tls_enabled" not in columns:
                db.execute("ALTER TABLE listeners ADD COLUMN tls_enabled INTEGER NOT NULL DEFAULT 1")

    def list_listeners(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT id,port,username,tls_enabled,enabled,created_at FROM listeners ORDER BY port").fetchall()
            return [dict(row) for row in rows]

    def get_listener(self, listener_id: int) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM listeners WHERE id=?", (listener_id,)).fetchone()
            return dict(row) if row else None

    def get_listener_by_port(self, port: int) -> dict[str, Any] | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM listeners WHERE port=?", (port,)).fetchone()
            return dict(row) if row else None

    def create_listener(self, port: int, username: str, password: str, tls_enabled: bool = True) -> int:
        with self._connect() as db:
            cur = db.execute(
                "INSERT INTO listeners(port,username,password_hash,tls_enabled,enabled) VALUES(?,?,?,?,1)",
                (port, username, password_hash(password), int(tls_enabled)),
            )
            return int(cur.lastrowid)

    def set_enabled(self, listener_id: int, enabled: bool) -> None:
        with self._connect() as db:
            db.execute("UPDATE listeners SET enabled=? WHERE id=?", (int(enabled), listener_id))

    def update_credentials(self, listener_id: int, username: str, password: str | None) -> None:
        with self._connect() as db:
            if password:
                db.execute("UPDATE listeners SET username=?,password_hash=? WHERE id=?",
                           (username, password_hash(password), listener_id))
            else:
                db.execute("UPDATE listeners SET username=? WHERE id=?", (username, listener_id))

    def delete_listener(self, listener_id: int) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM listeners WHERE id=?", (listener_id,))
