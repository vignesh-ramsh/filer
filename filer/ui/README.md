# ui/

Most plugins don't need their own UI — this is a placeholder, not a requirement. If you want to serve one (following admin's own `/admin-desk` pattern, docs/arc.MD §3.14/§6):

1. `npm create vite@latest . -- --template react-ts` in this directory.
2. Build it, then in `__init__.py`'s `register()`, uncomment the `mount_spa` block and point it at your own build's `dist/`.
3. Pick a route prefix that isn't your plugin's own name if you don't want the two coupled — e.g. `"filer_desk"` (already the default in the commented-out sample above).

See `plugins/admin/admin/ui/` for a complete, working reference.
