#!/usr/bin/env python3
"""
Разведка формата индекса: что именно прислал коллега.

Ничего не грузит и не меняет — только читает и печатает структуру.
Запуск:
    python3 tools/index_probe.py index.json.gz
    python3 tools/index_probe.py chunks/*.json.gz
"""

import argparse
import gzip
import json
import sys
from pathlib import Path

# Консоль Windows часто в cp1251 — не даём ей уронить скрипт на юникоде
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(errors="replace")
    except Exception:
        pass

V0_FILE_KEYS = {"functions", "imports", "globals", "package"}
V0_CALL_KEYS = {"caller_file", "caller_line", "callee_name"}


# ---------- безопасный режим ----------

SAFE = False
_seen: dict = {}
SENSITIVE_KEYS = {"file", "path", "filepath", "relpath", "name", "package",
                  "module", "varname", "caller_file", "callee_name",
                  "callee_full", "project", "root", "failed_files"}


def mask(value, key=None):
    """Заменяет содержательные значения плейсхолдерами, сохраняя тип и форму."""
    if not SAFE:
        return value
    if isinstance(value, dict):
        return {k: mask(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v, key) for v in value]
    if isinstance(value, str) and key in SENSITIVE_KEYS:
        kind = {"file": "ФАЙЛ", "path": "ФАЙЛ", "filepath": "ФАЙЛ",
                "relpath": "ФАЙЛ", "caller_file": "ФАЙЛ",
                "package": "ПАКЕТ", "module": "МОДУЛЬ", "varname": "ПЕРЕМЕННАЯ",
                "project": "ПРОЕКТ", "root": "ПУТЬ"}.get(key, "ИМЯ")
        slot = _seen.setdefault((kind, value), f"<{kind}_{len([k for k in _seen if k[0] == kind]) + 1}>")
        return slot
    return value


def dump(obj, key=None, limit=180) -> str:
    return json.dumps(mask(obj, key), ensure_ascii=False)[:limit]


def read_bytes(path: Path) -> bytes:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        return gzip.decompress(raw)
    return raw


def shape_of(obj) -> str:
    """Как называется то, на что мы смотрим."""
    if isinstance(obj, list):
        return f"список из {len(obj)} элементов"
    if not isinstance(obj, dict):
        return type(obj).__name__
    keys = set(obj)
    if "files" in keys or "calls" in keys:
        return "чанк формата v0 (files/calls/meta)"
    if V0_FILE_KEYS & keys and ({"file", "path", "filepath"} & keys):
        return "запись про один файл"
    if V0_CALL_KEYS <= keys:
        return "одна запись о вызове"
    return "неизвестный объект"


def describe(obj, indent="    "):
    if isinstance(obj, dict):
        for k, v in list(obj.items())[:12]:
            if isinstance(v, dict):
                sample = next(iter(v.items()), None)
                print(f"{indent}{k}: словарь, {len(v)} ключей"
                      + (f", первый ключ — {mask(sample[0], k if k in SENSITIVE_KEYS else 'name')!r}" if sample else ""))
                if sample and isinstance(sample[1], (dict, list)):
                    print(f"{indent}    значение: {dump(sample[1], k)}")
            elif isinstance(v, list):
                print(f"{indent}{k}: список, {len(v)} элементов")
                if v:
                    print(f"{indent}    первый: {dump(v[0], k)}")
            else:
                print(f"{indent}{k}: {mask(v, k)!r}")


def probe(path: Path) -> None:
    print(f"\n=== {path.name}  ({path.stat().st_size:,} байт на диске)")
    try:
        data = read_bytes(path)
    except Exception as exc:
        print(f"    не читается: {exc}")
        return
    print(f"    после распаковки: {len(data):,} байт")

    # Попытка 1 — цельный JSON
    try:
        obj = json.loads(data)
    except json.JSONDecodeError as exc:
        print(f"    цельным JSON не разбирается ({exc.msg} на позиции {exc.pos})")
        probe_lines(data)
        return

    print(f"    цельный JSON: {shape_of(obj)}")
    if isinstance(obj, dict):
        print(f"    ключи верхнего уровня: {sorted(obj)}")
        describe(obj)
        check_v0(obj)
    elif isinstance(obj, list) and obj:
        print(f"    первый элемент: {shape_of(obj[0])}")
        describe(obj[0], indent="        ")


def probe_lines(data: bytes) -> None:
    """Возможно, это JSON Lines — по объекту на строку."""
    lines = [ln for ln in data.split(b"\n") if ln.strip()]
    print(f"    пробую построчно: {len(lines)} непустых строк")
    ok = 0
    first = None
    for ln in lines[:200]:
        try:
            obj = json.loads(ln)
        except json.JSONDecodeError:
            continue
        ok += 1
        if first is None:
            first = obj
    if not ok:
        print("    построчно тоже не разбирается — покажи первые 300 байт коллеге:")
        print("    (в безопасном режиме сырой фрагмент не печатается)" if SAFE else f"    {data[:300]!r}")
        return
    print(f"    разобралось строк (из первых 200): {ok}")
    print(f"    первая строка: {shape_of(first)}")
    if isinstance(first, dict):
        print(f"    её ключи: {sorted(first)}")
        describe(first, indent="        ")


def check_v0(obj: dict) -> None:
    """Совпадает ли с тем, что ждёт load_index()."""
    print("    --- сверка с контрактом v0:")
    files = obj.get("files")
    if isinstance(files, dict) and files:
        path, fdata = next(iter(files.items()))
        print(f"        files: словарь путь -> данные, пример пути {mask(path, 'file')!r}")
        if isinstance(fdata, dict):
            missing = V0_FILE_KEYS - set(fdata)
            print(f"        поля файла: {sorted(fdata)}"
                  + (f"; НЕТ: {sorted(missing)}" if missing else "; все на месте"))
            fns = fdata.get("functions") or []
            if fns:
                print(f"        функция: {dump(fns[0], 'name', 400)}")
    elif isinstance(files, list):
        print("        ВНИМАНИЕ: files — список, а load_index() ждёт словарь. Нужен конвертер.")
    else:
        print("        ключа files нет — формат изменился, смотри вывод выше")

    calls = obj.get("calls")
    if isinstance(calls, list) and calls:
        missing = V0_CALL_KEYS - set(calls[0])
        print(f"        calls: {len(calls)} шт., поля {sorted(calls[0])}"
              + (f"; НЕТ: {sorted(missing)}" if missing else "; все на месте"))
    meta = obj.get("meta")
    if isinstance(meta, dict):
        print(f"        meta: {dump(meta, None, 300)}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Разведка формата индекса")
    ap.add_argument("paths", nargs="+", help="файлы индекса (.json / .json.gz / .jsonl)")
    ap.add_argument("--safe", action="store_true",
                    help="скрыть пути, имена функций и пакетов — вывод можно выносить из контура")
    args = ap.parse_args()

    global SAFE
    SAFE = args.safe
    if SAFE:
        print("РЕЖИМ SAFE: значения заменены плейсхолдерами, структура сохранена")

    paths = [Path(p) for p in args.paths]
    missing = [p for p in paths if not p.exists()]
    for p in missing:
        print(f"нет файла: {p}", file=sys.stderr)
    for p in paths:
        if p.exists():
            probe(p)
    print()
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
