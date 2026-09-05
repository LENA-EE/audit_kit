#!/usr/bin/env python3
"""
Склейка чанков коллеги в один index.json.gz — формат, который понимают
и load_index(), и эндпоинт MCP POST /index/upload.

34 коробки + опись  ->  одна коробка.

Запуск:
    python3 tools/merge_chunks.py chunks/chunk_*.json all.json --out index.json.gz

Только читает исходные файлы. Проверяет по дороге:
  - не встречается ли один и тот же файл в двух чанках (были бы дубли);
  - сходится ли итог с file_count из all.json.
"""

import argparse
import gzip
import json
import sys
from pathlib import Path


def read_json(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw)


def main() -> int:
    ap = argparse.ArgumentParser(description="Склейка чанков индекса в один файл")
    ap.add_argument("paths", nargs="+", help="chunk_*.json и all.json")
    ap.add_argument("--out", default="index.json.gz", help="куда писать результат")
    ap.add_argument("--plain", action="store_true", help="не сжимать (для отладки)")
    args = ap.parse_args()

    files: dict = {}
    calls: list = []
    meta: dict = {}
    duplicates: list = []

    paths = [Path(p) for p in args.paths]
    missing = [p for p in paths if not p.exists()]
    for p in missing:
        print(f"нет файла: {p}", file=sys.stderr)
    if missing:
        return 1

    for path in sorted(paths):
        try:
            obj = read_json(path)
        except Exception as exc:
            print(f"  {path.name}: не читается — {exc}", file=sys.stderr)
            return 1

        chunk_files = obj.get("files") or {}
        chunk_calls = obj.get("calls") or []
        if isinstance(obj.get("meta"), dict):
            meta.update(obj["meta"])

        for filepath, fdata in chunk_files.items():
            if filepath in files:
                duplicates.append(filepath)
            files[filepath] = fdata
        calls.extend(chunk_calls)

        print(f"  {path.name}: файлов {len(chunk_files)}, вызовов {len(chunk_calls)}")

    # meta приводим к правде: считаем по факту, а не по заголовку
    declared = meta.get("file_count")
    meta["file_count"] = len(files)
    meta.pop("chunks", None)          # список коробок больше не актуален
    meta.pop("chunks_dir", None)
    meta.setdefault("failed_count", 0)

    index = {"meta": meta, "files": files, "calls": calls}
    payload = json.dumps(index, ensure_ascii=False).encode("utf-8")

    out = Path(args.out)
    if args.plain:
        out.write_bytes(payload)
    else:
        out.write_bytes(gzip.compress(payload, mtime=0))

    print(f"\nСклеено в {out}  ({out.stat().st_size:,} байт на диске)")
    print(f"  файлов        {len(files)}")
    print(f"  вызовов       {len(calls)}")
    print(f"  не разобрано  {meta.get('failed_count')}")
    if meta.get("project"):
        print(f"  проект        {meta['project']}  ({meta.get('built_at', '')})")

    if duplicates:
        print(f"\n  ВНИМАНИЕ: {len(duplicates)} путей встретились в двух чанках,"
              f" оставлена последняя версия. Первые пять: {duplicates[:5]}")
    if declared is not None and int(declared) != len(files):
        print(f"\n  ВНИМАНИЕ: в all.json заявлено {declared} файлов, склеилось {len(files)}."
              f" Похоже, часть коробок не доехала.")
        return 2
    if declared is not None:
        print(f"\n  Сходится с all.json: {declared} файлов.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
