# audit_kit — сборка индекса Perl-кода и отчёт «Карта легаси»

Три скрипта, которых достаточно, чтобы по кодовой базе на Perl получить
отчёт: объём, топ рисков, кандидаты в мёртвый код, циклы зависимостей,
дубли имён.

**Исходный код никуда не передаётся.** Индексатор выгружает только имена
функций, пути файлов, номера строк и связи вызовов.

## Состав

| Файл | Что делает | Требует |
|---|---|---|
| `build_index.pl` | обходит `.pm`/`.pl`, разбирает парсером PPI, выдаёт JSON | Perl + PPI |
| `tools/index_store.py` | превращает JSON в SQLite (`data/index.db`) | Python 3, только stdlib |
| `audit_report.py` | строит отчёт по базе | Python 3, только stdlib |

Подкаталог `tools/` обязателен: `index_store.py` вычисляет путь к базе как
`../data/index.db` относительно самого себя.

## Как запустить

```bash
# 1. индекс (там, где лежит код)
perl build_index.pl /path/to/project | gzip > index.json.gz

# 2. база
python3 -c "from tools.index_store import load_index; \
print(load_index(open('index.json.gz','rb').read(), compressed=True))"

# 3. отчёт
python3 audit_report.py data/index.db --out отчёт.md
```

Шаги 2–3 зависимостей не требуют. Модель не вызывается, токены не тратятся,
сеть не нужна.

### Если PPI не установлен

PPI — чистый Perl, ставить его не обязательно:

```bash
curl -sL https://cpan.metacpan.org/authors/id/M/MI/MITHALDU/PPI-1.279.tar.gz | tar xz
curl -sL https://cpan.metacpan.org/authors/id/A/AD/ADAMK/Params-Util-1.07.tar.gz | tar xz
mkdir plib && cp -r PPI-1.279/lib/* Params-Util-1.07/lib/* plib/
PERL5LIB=$PWD/plib perl build_index.pl /path/to/project | gzip > index.json.gz
```

### Объяснения модели (опционально)

```bash
export FENIX_URL=... FENIX_TOKEN=...
python3 audit_report.py data/index.db --src /path/to/checkout --top 15 --out отчёт.md
```

Добавляет колонку «почему опасна / что делать» к топу рисков. Требует
`requests` и чекаут кода. Без них шаг пропускается, отчёт выходит без
этих колонок.

## Ограничения (важно при чтении отчёта)

- Каталоги `t` и файлы вне `.pm`/`.pl` не обходятся.
- Не распознаются вызовы `&func()`, через `eval`-строку и динамическую
  диспетчеризацию — поэтому раздел «кандидаты в мёртвый код» **завышен**.
  Это кандидаты на проверку человеком, не приговор.
- Файлы, которые не разобрал парсер, в отчёт не попадают. Их число и имена
  печатаются в строке «Покрытие отчёта» под шапкой — читать в первую очередь.

## Что скрипты НЕ делают

Не пишут в индексируемый репозиторий, не ходят в сеть (кроме опционального
шага с моделью), не требуют прав администратора. `audit_report.py` открывает
базу в режиме `mode=ro`.
