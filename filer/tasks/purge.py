"""Purges `status = "deleted"` filerfile rows once `deleted_at` is older
than the configured grace window (`filer_purge_after_days`, default 30 —
docs §7). This is the ONLY place a filerfile row is ever actually
DELETEd — every other transition is a plain `status` update via
arc.relay.save(), deliberately bypassing arc.relay.delete()'s own
soft-delete/`_trash` path (see FilerFile.json's own field-notes in the
proposal doc for why: one deletion story, not two overlapping ones).

Runs after reconcile.py (3am) so anything reconcile just marked
`deleted` this run still gets its full 30-day window, not purged early
by a scheduling coincidence.
"""

from __future__ import annotations

from datetime import timedelta

import arc

from filer import utcnow


@arc.relay.task(queue="default", cron="0 4 * * *")
async def purge_deleted_files() -> None:
    from filer.providers import PROVIDERS

    cutoff = utcnow() - timedelta(days=arc.filer.purge_after_days())
    # Deliberately unbounded — every eligible row must actually be purged,
    # not just the first DEFAULT_LIST_LIMIT of them each run.
    rows = await arc.relay.list(
        "filerfile", filters={"status": "deleted", "deleted_at": {"lte": cutoff}}, limit=None
    )
    for row in rows:
        await PROVIDERS[row["storage"]].delete(row["storage_key"])
        await arc.relay.sql('DELETE FROM "filerfile" WHERE id = $1', row["id"])
