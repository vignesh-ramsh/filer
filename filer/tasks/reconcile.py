"""Daily backstop for FILE/MULTIFILE cascade cleanup (docs
§4). The after_save/after_delete hooks filer registers per watched
table (filer/__init__.py's _reap_after_save/_reap_after_delete) handle
the common case immediately; this exists only for what they can't see —
file references written while filer was disabled or not yet installed.

A file is an orphan only when NOTHING refers to it, and "refers to it"
means every way a table can point at a file:
  * a FILE column (holds the file's `file_id`),
  * a MULTIFILE column (a JSON list of `{label, fileid}`),
  * an ordinary REFERENCE column whose target is `filerfile` (holds the
    row's own key — the admin import/export jobs keep their source and
    result files this way).
An earlier version counted only the first two, so every import source file
and export result was moved to the trash on the next run and its download
link stopped working; it also had no age limit, so a file uploaded a moment
before 03:00 and not yet attached to its record was lost too. Files younger
than `filer_orphan_grace_hours` are never touched.

The whole question is asked of the database in one statement (an anti-join
against everything that refers to a file) instead of reading every row of
every watched table into Python.
"""

from __future__ import annotations

import re

import arc
from filer import _FILE_FIELDS

# Rows moved to the trash per round: each round's rows leave the candidate
# set once marked, so memory stays bounded however many orphans there are.
_BATCH_SIZE = 500
# Table/column names come from registered schemas, never from a request, but
# they are interpolated into SQL, so they are still checked before use.
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _quote(name: str) -> str:
    if not _IDENTIFIER.match(name):
        raise ValueError(f"refusing to build SQL with the identifier {name!r} from a schema")
    return f'"{name}"'


def unreferenced_files_sql() -> str:
    """The statement that finds files nothing refers to. Parameters: $1 the
    newest `created_at` a file may have (the grace period), $2 the batch size.
    Returns `id` and `file_id` of each such file, oldest key first."""
    sources: list[str] = []
    for table, fields in _FILE_FIELDS.items():
        owner = _quote(table)
        for name, kind in fields.items():
            column = _quote(name)
            if kind == "FILE":
                sources.append(f"SELECT {column}::text AS file_id FROM {owner} WHERE {column} IS NOT NULL")
            else:  # MULTIFILE: a JSON list of {label, fileid}; anything else holds no references
                sources.append(
                    f"SELECT entry ->> 'fileid' AS file_id FROM {owner} AS r, "
                    f"LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(r.{column}::jsonb) = 'array' "
                    f"THEN r.{column}::jsonb ELSE '[]'::jsonb END) AS entry"
                )

    cte = ""
    conditions = ["f.status IN ('clean', 'pending', 'skipped')", "f.created_at < $1"]
    if sources:
        cte = "WITH referenced AS MATERIALIZED (" + " UNION ".join(sources) + ") "
        conditions.append("NOT EXISTS (SELECT 1 FROM referenced x WHERE x.file_id = f.file_id)")

    for (table, field), target in sorted(arc.pgdb.ref_columns().items()):
        if target.table == "filerfile":
            conditions.append(
                f"NOT EXISTS (SELECT 1 FROM {_quote(table)} AS r "
                f"WHERE r.{_quote(field)} = f.{_quote(target.column)})"
            )

    return (
        f'{cte}SELECT f.id, f.file_id FROM "filerfile" AS f WHERE '
        + " AND ".join(conditions)
        + " ORDER BY f.id LIMIT $2"
    )


@arc.relay.task(queue="default", cron="0 3 * * *")
async def reconcile_orphaned_files() -> None:
    newest_allowed = arc.tz.ago(hours=arc.filer.orphan_grace_hours())
    sql = unreferenced_files_sql()
    seen: set[str] = set()
    while True:
        orphans = await arc.relay.sql(sql, newest_allowed, _BATCH_SIZE)
        fresh = [row for row in orphans if str(row["id"]) not in seen]
        if not fresh:
            return  # nothing left, or the same rows came back (never loop forever)
        for row in fresh:
            seen.add(str(row["id"]))
            await arc.relay.save(
                "filerfile", {"id": row["id"], "status": "deleted", "deleted_at": arc.tz.utcnow()}
            )
