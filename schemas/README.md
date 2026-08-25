# schemas/

One JSON file per table this plugin OWNS (creates). Loaded via `pgdb.register_model(...)` in `__init__.py`. The filename (minus `.json`) becomes the table's file **stem** — the only valid value for a REFERENCE/TABLE field's `target` elsewhere, never the physical, slugified table name (docs/arc.MD §3.9).

Every normal table must declare at least one business `"unique": true` field of its own (not just the auto-injected `id`).

Example — `Department.json`:

```json
{
  "system": false,
  "audit": false,
  "child": false,
  "fields": [
    {"id": "AA01", "name": "code", "type": "STRING", "unique": true, "required": true, "length": 8},
    {"id": "AA02", "name": "dept_name", "type": "STRING", "required": true, "length": 100}
  ],
  "index": [{"key": "idx_dept_name", "fields": ["dept_name"]}]
}
```

After adding or changing a schema file:
1. `arc pgdb plan` — preview the diff, never touches the DB.
2. `arc pgdb migrate` — apply it (run this yourself).
