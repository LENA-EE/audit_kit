"""
SQLite-хранилище PPI-индекса.

Атомарная замена: новый индекс пишется во временный файл,
затем os.replace() — читающие запросы не видят полуготовый индекс.
"""

import gzip
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

INDEX_DB_PATH = Path(__file__).parent.parent / "data" / "index.db"


def db_exists() -> bool:
    return INDEX_DB_PATH.exists()


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS meta (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE TABLE IF NOT EXISTS functions (
            name       TEXT,
            file       TEXT,
            package    TEXT,
            line_start INTEGER,
            line_end   INTEGER
        );
        CREATE TABLE IF NOT EXISTS imports (
            file   TEXT,
            module TEXT,
            type   TEXT,
            line   INTEGER
        );
        CREATE TABLE IF NOT EXISTS globals (
            file    TEXT,
            varname TEXT
        );
        CREATE TABLE IF NOT EXISTS calls (
            caller_file TEXT,
            caller_line INTEGER,
            callee_name TEXT,
            callee_full TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_function_name ON functions(name);
        CREATE INDEX IF NOT EXISTS idx_function_file ON functions(file);
        CREATE INDEX IF NOT EXISTS idx_callee_name   ON calls(callee_name);
    """)


def load_index(raw: bytes, compressed: bool = False) -> Dict:
    """Загружает JSON-индекс в SQLite атомарно."""
    data = gzip.decompress(raw) if compressed else raw
    index = json.loads(data)

    INDEX_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = str(INDEX_DB_PATH) + ".new"

    conn = sqlite3.connect(tmp_path)
    try:
        _init_db(conn)

        # meta
        meta = index.get("meta", {})
        conn.executemany(
            "INSERT INTO meta VALUES (?, ?)",
            [(k, str(v)) for k, v in meta.items()]
        )

        # functions + imports + globals
        for filepath, fdata in index.get("files", {}).items():
            pkg = fdata.get("package")
            for fn in fdata.get("functions", []):
                conn.execute(
                    "INSERT INTO functions VALUES (?, ?, ?, ?, ?)",
                    (fn["name"], filepath, pkg, fn["line_start"], fn["line_end"])
                )
            for imp in fdata.get("imports", []):
                conn.execute(
                    "INSERT INTO imports VALUES (?, ?, ?, ?)",
                    (filepath, imp["module"], imp["type"], imp["line"])
                )
            for var in fdata.get("globals", []):
                conn.execute("INSERT INTO globals VALUES (?, ?)", (filepath, var))

        # calls
        for call in index.get("calls", []):
            conn.execute(
                "INSERT INTO calls VALUES (?, ?, ?, ?)",
                (call["caller_file"], call["caller_line"],
                 call["callee_name"], call.get("callee_full", ""))
            )

        conn.commit()
    finally:
        conn.close()

    # Атомарная замена
    os.replace(tmp_path, str(INDEX_DB_PATH))

    return {
        "file_count":   meta.get("file_count", 0),
        "failed_count": meta.get("failed_count", 0),
        "built_at":     meta.get("built_at", ""),
        "project":      meta.get("project", ""),
    }


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(INDEX_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def lookup_symbol(name: str) -> List[Dict]:
    """Где определена функция с таким именем."""
    if not db_exists():
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT name, file, package, line_start, line_end "
            "FROM functions WHERE name = ?", (name,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_file_structure(filepath: str) -> Dict:
    """Карта файла: функции, импорты, глобальные переменные."""
    if not db_exists():
        return {}
    with _connect() as conn:
        functions = conn.execute(
            "SELECT name, line_start, line_end FROM functions WHERE file = ?",
            (filepath,)
        ).fetchall()
        imports = conn.execute(
            "SELECT module, type, line FROM imports WHERE file = ?",
            (filepath,)
        ).fetchall()
        globals_ = conn.execute(
            "SELECT varname FROM globals WHERE file = ?",
            (filepath,)
        ).fetchall()
    return {
        "file":      filepath,
        "functions": [dict(r) for r in functions],
        "imports":   [dict(r) for r in imports],
        "globals":   [r["varname"] for r in globals_],
    }


def get_callers(name: str) -> List[Dict]:
    """Где реально вызывается функция с таким именем."""
    if not db_exists():
        return []
    with _connect() as conn:
        rows = conn.execute(
            "SELECT caller_file, caller_line, callee_full "
            "FROM calls WHERE callee_name = ? "
            "ORDER BY caller_file, caller_line",
            (name,)
        ).fetchall()
    return [dict(r) for r in rows]


def index_status() -> Dict:
    """Метаданные последнего загруженного индекса."""
    if not db_exists():
        return {"available": False}
    with _connect() as conn:
        rows = conn.execute("SELECT key, value FROM meta").fetchall()
    meta = {r["key"]: r["value"] for r in rows}
    meta["available"] = True
    return meta
