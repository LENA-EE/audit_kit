#!/usr/bin/env python3
"""
Загрузка чанкового индекса в ту же SQLite-базу, что и load_index().

Схема БД не меняется — значит audit_report.py и get_callers() в MCP
работают поверх результата без единой правки.

Понимает три формы (определяет сама):
  1. цельный JSON  {"meta":…, "files":{…}, "calls":[…]}      — формат v0
  2. JSON Lines    по объекту на строку: либо кусок вида (1),
                   либо запись про один файл {"file":…, "functions":[…]},
                   либо одна запись о вызове
  3. несколько файлов-частей: index.part-001.json.gz, …       — просто перечисли их

Запуск:
    python3 tools/load_index_chunked.py index.json.gz
    python3 tools/load_index_chunked.py chunks/*.json.gz --out data/index.db
"""

import argparse
import gzip
import json
import os
import sqlite3
import sys
from pathlib import Path

from typing import Dict, Iterable, Iterator, List, Tuple

sys.path.insert(0, str(Path(__file__).parent))
from index_store import INDEX_DB_PATH, _init_db  # та же схема, один источник правды
# Консоль Windows часто в cp1251 — не даём ей уронить скрипт на юникоде
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

FILE_PATH_KEYS = ("file", "path", "filepath", "relpath")
CALL_KEYS = {"caller_file", "caller_line", "callee_name"}


# ---------- чтение ----------

def read_text(path: Path) -> bytes:
    raw = path.read_bytes()
    return gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw


def iter_objects(path: Path) -> Iterator[dict]:
    """Отдаёт объекты из файла, чем бы он ни был: JSON, JSON Lines, массив."""
    data = read_text(path)
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        for lineno, line in enumerate(data.split(b"\n"), 1):
            if not line.strip():
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"  пропущена строка {lineno} в {path.name}: {exc.msg}", file=sys.stderr)
        return
    if isinstance(obj, list):
        yield from (o for o in obj if isinstance(o, dict))
    elif isinstance(obj, dict):
        yield obj


# ---------- нормализация ----------

def normalize(obj: dict) -> Tuple[Dict[str, dict], List[dict], dict]:
    """Приводит любой объект к тройке (файлы, вызовы, meta)."""
    files: Dict[str, dict] = {}
    calls: List[dict] = []
    meta: dict = {}

    if isinstance(obj.get("meta"), dict):
        meta = obj["meta"]

    raw_files = obj.get("files")
    if isinstance(raw_files, dict):
        files.update(raw_files)
    elif isinstance(raw_files, list):
        for entry in raw_files:
            path = next((entry[k] for k in FILE_PATH_KEYS if k in entry), None)
            if path:
                files[path] = entry

    raw_calls = obj.get("calls")
    if isinstance(raw_calls, list):
        calls.extend(c for c in raw_calls if isinstance(c, dict))

    # объект сам по себе — запись про один файл
    if not files and not calls:
        path = next((obj[k] for k in FILE_PATH_KEYS if k in obj), None)
        if path and any(k in obj for k in ("functions", "imports", "globals", "package")):
            files[path] = obj
            inner = obj.get("calls")
            if isinstance(inner, list):
                calls.extend(dict(c, caller_file=c.get("caller_file", path)) for c in inner)
        elif CALL_KEYS <= set(obj):
            calls.append(obj)

    return files, calls, meta


def line_bounds(fn: dict) -> Tuple:
    """Терпим и line_start/line_end, и start/end, и одну строку."""
    start = fn.get("line_start", fn.get("start", fn.get("line")))
    end = fn.get("line_end", fn.get("end", start))
    return start, end


# ---------- загрузка ----------

def load(paths: Iterable[Path], out: Path) -> Dict:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(out) + ".new"
    if os.path.exists(tmp):
        os.remove(tmp)

    conn = sqlite3.connect(tmp)
    seen_files: set = set()
    meta_all: dict = {}
    n_fn = n_imp = n_glob = n_call = 0
    skipped: List[str] = []

    try:
        _init_db(conn)
        for path in paths:
            chunks = 0
            for obj in iter_objects(path):
                files, calls, meta = normalize(obj)
                if not files and not calls and not meta:
                    continue
                chunks += 1
                meta_all.update(meta)

                for filepath, fdata in files.items():
                    if not isinstance(fdata, dict):
                        continue
                    seen_files.add(filepath)
                    pkg = fdata.get("package")
                    for fn in fdata.get("functions") or []:
                        name = fn.get("name") if isinstance(fn, dict) else fn
                        if not name:
                            continue
                        start, end = line_bounds(fn if isinstance(fn, dict) else {})
                        conn.execute("INSERT INTO functions VALUES (?,?,?,?,?)",
                                     (name, filepath, pkg, start, end))
                        n_fn += 1
                    for imp in fdata.get("imports") or []:
                        if not isinstance(imp, dict):
                            continue
                        conn.execute("INSERT INTO imports VALUES (?,?,?,?)",
                                     (filepath, imp.get("module"), imp.get("type"), imp.get("line")))
                        n_imp += 1
                    for var in fdata.get("globals") or []:
                        conn.execute("INSERT INTO globals VALUES (?,?)", (filepath, var))
                        n_glob += 1

                for call in calls:
                    callee = call.get("callee_name") or call.get("callee")
                    if not callee:
                        continue
                    conn.execute("INSERT INTO calls VALUES (?,?,?,?)",
                                 (call.get("caller_file"), call.get("caller_line"),
                                  callee, call.get("callee_full", "")))
                    n_call += 1
            print(f"  {path.name}: кусков — {chunks}")
            if chunks == 0:
                skipped.append(path.name)

        # meta пишем после всех кусков: file_count считаем по факту,
        # а не доверяем заголовку отдельного чанка
        meta_all["file_count"] = len(seen_files)
        meta_all.setdefault("failed_count", 0)
        conn.executemany("INSERT OR REPLACE INTO meta VALUES (?,?)",
                         [(k, str(v)) for k, v in meta_all.items()])
        conn.commit()
    finally:
        conn.close()

    os.replace(tmp, str(out))
    return {
        "file_count": len(seen_files),
        "failed_count": meta_all.get("failed_count", 0),
        "functions": n_fn, "imports": n_imp, "globals": n_glob, "calls": n_call,
        "built_at": meta_all.get("built_at", ""),
        "project": meta_all.get("project", ""),
        "skipped_files": skipped,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Загрузка чанкового индекса в SQLite")
    ap.add_argument("paths", nargs="+", help="части индекса (.json / .json.gz / .jsonl)")
    ap.add_argument("--out", default=str(INDEX_DB_PATH),
                    help=f"куда писать базу (по умолчанию {INDEX_DB_PATH})")
    args = ap.parse_args()

    paths = [Path(p) for p in args.paths]
    missing = [p for p in paths if not p.exists()]
    for p in missing:
        print(f"нет файла: {p}", file=sys.stderr)
    paths = [p for p in paths if p.exists()]
    if not paths:
        return 1

    print(f"Читаю {len(paths)} файл(ов):")
    stats = load(paths, Path(args.out))

    print(f"\nБаза: {args.out}")
    print(f"  файлов        {stats['file_count']}")
    print(f"  не разобрано  {stats['failed_count']}")
    print(f"  функций       {stats['functions']}")
    print(f"  вызовов       {stats['calls']}")
    print(f"  импортов      {stats['imports']}")
    print(f"  globals       {stats['globals']}")
    if stats["project"]:
        print(f"  проект        {stats['project']}  ({stats['built_at']})")
    if stats["skipped_files"]:
        print(f"\n  ВНИМАНИЕ: ничего не извлечено из {stats['skipped_files']} —"
              f" прогони их через tools/index_probe.py")
    if stats["functions"] == 0:
        print("\n  Функций ноль — формат не совпал. Смотри index_probe.py, "
              "правь normalize().")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
