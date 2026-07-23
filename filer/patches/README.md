# patches/

Add or modify fields YOU own on a table — your own, or another installed plugin's. Same JSON shape as `schemas/`, minus `system`/`audit`/`child`. Never create a table here — that's `schemas/`'s job.

A patch can't target a `"system": true` table (skipped with a warning at plan/migrate time — docs/arc.MD §3.9).

Example — `Employee.json` (adding a field to a table some other installed plugin owns):

```json
{
  "fields": [
    {"id": "AB01", "name": "emergency_contact", "type": "STRING", "length": 100}
  ]
}
```
