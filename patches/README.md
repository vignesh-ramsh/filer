# patches/

Add or modify fields YOU own on a table ANOTHER installed plugin owns. Same JSON shape as `schemas/`, minus `system`/`audit`/`child`. Never create a table here — that's `schemas/`'s job.

**Never patch a table your own plugin owns.** Its fields and indexes belong in its schema file (`schemas/<Table>.json`); `arc pgdb plan`/`migrate` refuse a patch on your own table, and say which schema to move it into (keep the field ids, so nothing changes in the database).

A patch can't target a `"system": true` table (skipped with a warning at plan/migrate time — docs/arc.MD §3.9).

Example — `Employee.json` (adding a field to a table some other installed plugin owns):

```json
{
  "fields": [
    {"id": "AB01", "name": "emergency_contact", "type": "STRING", "length": 100}
  ]
}
```
