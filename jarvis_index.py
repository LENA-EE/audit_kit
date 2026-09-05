#!/usr/bin/env python3
"""
Одна команда на всю цепочку: чанки -> индекс -> база -> отчёт -> MCP.

    python3 jarvis_index.py status     что уже сделано, а что нет
    python3 jarvis_index.py merge      склеить чанки в index.json.gz
    python3 jarvis_index.py db         собрать базу data/index.db
    python3 jarvis_index.py report     построить отчёт.md
    python3 jarvis_index.py upload     залить индекс в MCP
    python3 jarvis_index.py verify ИМЯ спросить у MCP, кто вызывает функцию
    python3 jarvis_index.py all        merge + db + report подряд

Каждый шаг сам проверяет, что нужное на месте, и в конце пишет,
какая команда следующая. Если шаг уже сделан — скажет и не станет
переделывать (переделать принудительно: --force).

Зависимости: только стандартная библиотека Python 3.
Настройки — флагами или переменными окружения:
    MCP_URL           адрес MCP, по умолчанию http://localhost:8000
    MCP_INDEX_TOKEN   токен для заливки индекса
"""

import argparse
import gzip
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(ROOT / "tools"))

OK, NO, WARN = "[ГОТОВО]", "[НЕТ]   ", "[!]     "


# ---------- вспомогательное ----------

def say(step: str, text: str = "") -> None:
    print(f"{step} {text}" if text else step, flush=True)


def next_hint(cmd: str) -> None:
    print(f"\n  Дальше:  python3 jarvis_index.py {cmd}")


def human(n: int) -> str:
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024 or unit == "ГБ":
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n / 1:.1f} {unit}".replace(".0 ", " ")
        n /= 1024
    return str(n)


def size_of(p: Path) -> str:
    return human(p.stat().st_size) if p.exists() else "—"


def find_chunks(chunks_dir: Path) -> list:
    if not chunks_dir.exists():
        return []
    return sorted(chunks_dir.glob("chunk_*.json")) + sorted(chunks_dir.glob("chunk_*.json.gz"))


def read_json(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw)


# ---------- шаги ----------

def step_status(a) -> int:
    chunks = find_chunks(a.chunks)
    print("\nГДЕ Я В ЦЕПОЧКЕ\n")

    print(f"  {OK if chunks else NO} 1. чанки           {a.chunks}: {len(chunks)} шт.")
    if a.all_json.exists():
        try:
            declared = read_json(a.all_json).get("meta", {}).get("file_count", "?")
        except Exception:
            declared = "не читается"
        print(f"  {OK} 2. опись           {a.all_json.name}: заявлено файлов {declared}")
    else:
        print(f"  {NO} 2. опись           {a.all_json} не найден")

    print(f"  {OK if a.index.exists() else NO} 3. склеенный индекс {a.index.name}: {size_of(a.index)}")
    print(f"  {OK if a.db.exists() else NO} 4. база            {a.db}: {size_of(a.db)}")
    if a.db.exists():
        try:
            import sqlite3
            with sqlite3.connect(f"file:{a.db}?mode=ro", uri=True) as c:
                nf = c.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
                nc = c.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
                meta = dict(c.execute("SELECT key, value FROM meta").fetchall())
            print(f"                        функций {nf}, вызовов {nc},"
                  f" файлов {meta.get('file_count', '?')}, проект {meta.get('project', '—')}")
        except Exception as exc:
            print(f"      {WARN} база не читается: {exc}")
    print(f"  {OK if a.report.exists() else NO} 5. отчёт           {a.report}: {size_of(a.report)}")

    token = os.environ.get("MCP_INDEX_TOKEN")
    print(f"  {OK if token else NO} 6. токен MCP       "
          f"{'MCP_INDEX_TOKEN задан' if token else 'MCP_INDEX_TOKEN не задан в окружении'}")
    print(f"          адрес MCP        {a.mcp_url}")

    if not chunks:
        print(f"\n  Сначала положи чанки в {a.chunks}/ и опись в {a.all_json}.")
    elif not a.index.exists():
        next_hint("merge")
    elif not a.db.exists():
        next_hint("db")
    elif not a.report.exists():
        next_hint("report")
    else:
        next_hint("upload   (и потом verify ИМЯ_ФУНКЦИИ)")
    return 0


def step_merge(a) -> int:
    chunks = find_chunks(a.chunks)
    if not chunks:
        say(WARN, f"в {a.chunks} нет файлов chunk_*.json — положи их туда")
        return 1
    if a.index.exists() and not a.force:
        say(OK, f"{a.index} уже собран ({size_of(a.index)}). Переделать: --force")
        next_hint("db")
        return 0

    sources = chunks + ([a.all_json] if a.all_json.exists() else [])
    if not a.all_json.exists():
        say(WARN, f"{a.all_json} не найден — в индексе не будет даты, проекта"
                  f" и числа сбойных файлов")

    cmd = [sys.executable, str(ROOT / "tools" / "merge_chunks.py"),
           *[str(p) for p in sources], "--out", str(a.index)]
    return run(cmd, "склейка", "db")


def step_db(a) -> int:
    if not a.index.exists():
        say(WARN, f"нет {a.index} — сначала склей чанки")
        next_hint("merge")
        return 1
    if a.db.exists() and not a.force:
        say(OK, f"{a.db} уже собрана ({size_of(a.db)}). Пересобрать: --force")
        next_hint("report")
        return 0

    cmd = [sys.executable, str(ROOT / "tools" / "load_index_chunked.py"),
           str(a.index), "--out", str(a.db)]
    return run(cmd, "сборка базы", "report")


def step_report(a) -> int:
    if not a.db.exists():
        say(WARN, f"нет {a.db} — сначала собери базу")
        next_hint("db")
        return 1
    if a.report.exists() and not a.force:
        say(OK, f"{a.report} уже построен ({size_of(a.report)}). Перестроить: --force")
        next_hint("upload")
        return 0

    cmd = [sys.executable, str(ROOT / "audit_report.py"), str(a.db), "--out", str(a.report)]
    if a.src:
        cmd += ["--src", a.src, "--top", str(a.top)]
    rc = run(cmd, "отчёт", "upload")
    if rc == 0:
        print(f"\n  Прочитай в отчёте строку «Покрытие отчёта» под шапкой —"
              f" она говорит, чего в отчёт не попало.")
    return rc


def step_upload(a) -> int:
    if not a.index.exists():
        say(WARN, f"нет {a.index} — сначала склей чанки")
        next_hint("merge")
        return 1
    token = a.token or os.environ.get("MCP_INDEX_TOKEN")
    url = a.mcp_url.rstrip("/") + "/index/upload"

    if not token:
        say(WARN, "не задан токен. Возьми MCP_INDEX_TOKEN из окружения контейнера MCP:")
        print("      export MCP_INDEX_TOKEN=...")
        print(f"\n  Проверить, принимает ли эта сборка индекс вообще:")
        print(f"      curl -i -X POST {url}")
        print("      401 — умеет, нужен только токен;  404 — сборка старая, без этой фичи")
        return 1

    body = a.index.read_bytes()
    print(f"  Заливаю {a.index.name} ({size_of(a.index)}) на {url}")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Encoding": "gzip",
                 "Content-Type": "application/octet-stream"})
    try:
        with urllib.request.urlopen(req, timeout=a.timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
            print(f"  HTTP {resp.status}: {text[:500]}")
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        print(f"  HTTP {exc.code}: {text[:500]}")
        hints = {401: "неверный токен — сверь MCP_INDEX_TOKEN с окружением контейнера",
                 404: "в этой сборке MCP нет эндпоинта — нужна версия с index_store",
                 400: "сервер не принял тело — проверь, что index.json.gz не побился",
                 503: "на сервере не настроен токен или не подгрузился index_store"}
        if exc.code in hints:
            say(WARN, hints[exc.code])
        return 1
    except urllib.error.URLError as exc:
        say(WARN, f"MCP недоступен по {a.mcp_url}: {exc.reason}")
        print("      проверь адрес и порт: с самой VM это localhost,"
              " с другой машины — имя хоста VM")
        return 1

    print("\n  Рестарт MCP не нужен — get_callers появляется сразу.")
    next_hint("verify ИМЯ_ФУНКЦИИ")
    return 0


def step_verify(a) -> int:
    name = a.name
    url = a.mcp_url.rstrip("/") + "/sse"
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "get_callers",
                                     "arguments": {"name": name}}}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=a.timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        print(f"  HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:400]}")
        return 1
    except urllib.error.URLError as exc:
        say(WARN, f"MCP недоступен по {a.mcp_url}: {exc.reason}")
        return 1

    print(f"  Кто вызывает {name}:\n")
    print(text[:4000])
    if '"caller_file"' not in text:
        print(f"\n  {WARN} пусто. Либо индекс не залит, либо имя другое —"
              f" проверь точное написание функции.")
    return 0


def step_all(a) -> int:
    for fn in (step_merge, step_db, step_report):
        rc = fn(a)
        if rc != 0:
            say(WARN, "цепочка остановлена — разберись с этим шагом и запусти снова")
            return rc
        print()
    print("Готово: индекс, база и отчёт на месте.")
    print("Заливка в MCP — отдельно, ей нужен токен:")
    next_hint("upload")
    return 0


def run(cmd: list, what: str, then: str) -> int:
    print(f"  --- {what} ---", flush=True)
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        say(WARN, f"{what}: код возврата {proc.returncode}")
        return proc.returncode
    next_hint(then)
    return 0


# ---------- разбор аргументов ----------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Цепочка: чанки -> индекс -> база -> отчёт -> MCP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Начни с:  python3 jarvis_index.py status")
    ap.add_argument("command",
                    choices=["status", "merge", "db", "report", "upload", "verify", "all"])
    ap.add_argument("name", nargs="?", help="для verify — имя функции")
    ap.add_argument("--chunks", type=Path, default=Path("chunks"), help="папка с чанками")
    ap.add_argument("--all-json", dest="all_json", type=Path, default=Path("all.json"))
    ap.add_argument("--index", type=Path, default=Path("index.json.gz"))
    ap.add_argument("--db", type=Path, default=Path("data/index.db"))
    ap.add_argument("--report", type=Path, default=Path("отчёт.md"))
    ap.add_argument("--src", help="чекаут кода — включает уровень 3 отчёта (нужен Феникс)")
    ap.add_argument("--top", type=int, default=15, help="сколько функций объяснять на уровне 3")
    ap.add_argument("--mcp-url", default=os.environ.get("MCP_URL", "http://localhost:8000"))
    ap.add_argument("--token", help="MCP_INDEX_TOKEN, если не задан в окружении")
    ap.add_argument("--timeout", type=int, default=300, help="таймаут запросов к MCP, сек")
    ap.add_argument("--force", action="store_true", help="переделать шаг, даже если уже сделан")
    a = ap.parse_args()

    if a.command == "verify" and not a.name:
        ap.error("verify требует имя функции: jarvis_index.py verify ИМЯ")

    return {"status": step_status, "merge": step_merge, "db": step_db,
            "report": step_report, "upload": step_upload,
            "verify": step_verify, "all": step_all}[a.command](a)


if __name__ == "__main__":
    raise SystemExit(main())
