"""Upkeep for uploads: the three things a crash, a full disk or a stopped scanner can leave behind.

* `sweep_upload_spool` (hourly): a worker that died mid-upload leaves its spool file. Files in the receiving
  folder that nothing has written to for `filer_spool_max_age_hours` are removed. A running upload keeps its
  file fresh, so a live one is never touched.
* `reap_stale_uploads` (every 15 minutes): an upload records its row as `uploading` BEFORE it stores any
  byte (so a crash cannot leave an object nobody knows about). A row still `uploading` after
  `filer_upload_stale_minutes` was abandoned by a crash: its object (if any) and the row are removed.
* `rescan_pending_files` (every 5 minutes): a file is `pending` until the scanner has given a verdict. If the
  scan job never ran or could not reach ClamAV, the file would wait for ever; this offers every file that has
  waited a few minutes to the scan again (oldest first, a bounded batch per run). While ClamAV is down it
  does nothing but say so once per run.
"""

from __future__ import annotations

import asyncio
import logging

import arc
from filer import SCAN_RETRY_AFTER_MINUTES, _clamd_ping, _scan, uploads

_logger = logging.getLogger("arc.filer")
#: Rows handled per run: each run is bounded, the next run takes up where this one stopped.
_BATCH = 200


@arc.relay.task(queue="default", cron="17 * * * *")
async def sweep_upload_spool() -> None:
    directory = (
        uploads.spool_dir()
    )  # settings: read here on the event loop, not in the thread below
    max_age_hours = max(
        1,
        int(
            arc.settings.get(uploads.SPOOL_MAX_AGE_HOURS_KEY) or uploads.DEFAULT_SPOOL_MAX_AGE_HOURS
        ),
    )
    await asyncio.to_thread(uploads.sweep_spool, directory, max_age_seconds=max_age_hours * 3600)


@arc.relay.task(queue="default", cron="*/15 * * * *")
async def reap_stale_uploads() -> None:
    from filer.providers import PROVIDERS

    cutoff = arc.tz.ago(minutes=arc.filer.upload_stale_minutes())
    rows = await arc.relay.sql(
        'SELECT id, storage, storage_key FROM "filerfile" WHERE status = $1 AND updated_at < $2 '
        "ORDER BY updated_at LIMIT $3",
        "uploading",
        cutoff,
        _BATCH,
    )
    for row in rows:
        try:
            await PROVIDERS[row["storage"]].delete(row["storage_key"])
        except Exception:  # noqa: BLE001 - leave the row for the next run rather than lose track of the object
            _logger.warning(
                "could not remove the object of abandoned upload %s",
                row["storage_key"],
                exc_info=True,
            )
            continue
        await arc.relay.sql(
            'DELETE FROM "filerfile" WHERE id = $1 AND status = $2', row["id"], "uploading"
        )
        _logger.warning("removed the abandoned upload %s", row["storage_key"])


@arc.relay.task(queue="default", cron="*/5 * * * *")
async def rescan_pending_files() -> None:
    filer = arc.filer
    if filer.scan_enabled(private=True) or filer.scan_enabled(private=False):
        socket_path = filer.clamav_socket()
        try:
            alive = await asyncio.wait_for(_clamd_ping(socket_path), timeout=5.0)
        except Exception:  # noqa: BLE001 - any failure to ask means the scanner is not available
            alive = False
        if not alive:
            _logger.warning(
                "ClamAV is not reachable at %s: files stay pending until it is back", socket_path
            )
            return
    cutoff = arc.tz.ago(minutes=SCAN_RETRY_AFTER_MINUTES)
    rows = await arc.relay.sql(
        'SELECT id FROM "filerfile" WHERE status = $1 AND updated_at < $2 ORDER BY updated_at LIMIT $3',
        "pending",
        cutoff,
        _BATCH,
    )
    for row in rows:
        arc.relay.enqueue(_scan, str(row["id"]))
    if rows:
        _logger.info("offered %d pending file(s) to the scanner again", len(rows))
