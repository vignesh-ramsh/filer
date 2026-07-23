"""filer.tokens — the private-file URL signature scheme.

Deliberately nginx's own `secure_link_md5` algorithm
(`md5(expires . uri . secret)`, base64url, no padding) rather than a
bespoke HMAC-SHA256 — so there is exactly ONE algorithm to implement, and
dev (bare gateway, no nginx — filer.api.filer_api.serve_file calls verify()
directly) and production (nginx's own secure_link module, configured
separately) are byte-for-byte compatible, not just conceptually similar.
See docs/filer-attachment-storage-proposal.md §8/§9 for the full reasoning
and the matching nginx `location` block.

MD5 here is not a general-purpose cryptographic signature — it's nginx's
own narrow, well-understood mechanism (a non-forgeable-in-practice
integrity/expiry marker validated against a server-held secret, not a
collision-attack-relevant use), reused deliberately for exact dev/prod
parity rather than inventing a second "more modern" scheme that would
only ever run in the no-nginx dev path.

The token proves "this link is valid and unexpired," nothing about who
is holding it — no user identity is embedded or checked here at all; see
filer/__init__.py's own module docstring for where authorization
actually happens (a business endpoint's role gate, before a URL is ever
handed out).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import time


def sign(uri: str, expires: int, secret: str) -> str:
    digest = hashlib.md5(f"{expires}{uri} {secret}".encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify(uri: str, expires: int, sig: str, secret: str) -> bool:
    if expires < int(time.time()):
        return False
    return hmac.compare_digest(sign(uri, expires, secret), sig)
