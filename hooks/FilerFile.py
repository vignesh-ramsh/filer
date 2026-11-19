"""hooks/FilerFile.py - the `filer_allow_public_uploads` switch, for the rows themselves.

`arc.filer.upload*()` already refuses a public upload while the setting is off (filer/__init__.py, `_store`). This
closes the other way a file becomes public: writing the row directly - the admin Data Browser, `arc.relay.save` from
another plugin's code - with `private` set to false. A row that is ALREADY public is not touched by this (its other
fields, such as the scan verdict, still update), and one switched back to private is always fine.
"""

import arc


@arc.relay.validate
async def refuse_a_public_file_while_public_uploads_are_off(ctx):
    if ctx.payload.get("private") is not False:
        return  # this write does not make the file public (or does not mention visibility at all)
    if ctx.old is not None and ctx.old.get("private") is False:
        return  # already public: nothing new is exposed
    arc.filer.require_visibility_allowed(private=False)
