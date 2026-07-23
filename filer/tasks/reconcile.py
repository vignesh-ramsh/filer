"""Daily backstop for FILE/MULTIFILE cascade cleanup (docs
§4). The after_save/after_delete hooks filer registers per watched
table (filer/__init__.py's _reap_after_save/_reap_after_delete) handle
the common case immediately; this exists only for what they can't see —
file references written while filer was disabled or not yet installed.
Correct, not cheap: a full scan of every watched table plus every
un-purged filerfile row.
"""

from __future__ import annotations

import arc

from filer import _FILE_FIELDS, _collect, utcnow


@arc.relay.task(queue="default", cron="0 3 * * *")
async def reconcile_orphaned_files() -> None:
    referenced: set[str] = set()
    for table, fields in _FILE_FIELDS.items():
        rows = await arc.relay.list(table, fields=list(fields.keys()))
        for row in rows:
            _collect(row, fields, referenced)

    candidates = await arc.relay.list(
        "filerfile", filters={"status": {"in": ["clean", "pending", "skipped"]}}, fields=["id", "file_id"]
    )
    for row in candidates:
        if row["file_id"] not in referenced:
            await arc.relay.save("filerfile", {"id": row["id"], "status": "deleted", "deleted_at": utcnow()})
