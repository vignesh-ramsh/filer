"""filer.tokens — the private-file URL signature scheme.

Two schemes, selected by the `filer_url_signing_scheme` setting
(filer/__init__.py's own FilerProvider.url_signing_scheme):

  * "md5" (the default) — nginx's own `secure_link_md5` algorithm
    (`md5(expires . uri . secret)`, base64url, no padding), so there is
    exactly ONE algorithm to implement, and dev (bare gateway, no nginx
    — filer.api.filer_api.serve_file calls verify() directly) and
    production (nginx's own secure_link module, configured separately —
    see docs/reviewes/filer-attachment-storage-proposal.md §9's own
    nginx `location` block) validate byte-for-byte identical tokens.
    KEPT as the default deliberately, not merely for legacy reasons: an
    operator following that doc's own "recommended for real traffic"
    topology has nginx validate every private-file request itself,
    WITHOUT ever reaching this Python process — nginx's `secure_link`
    module can only ever speak MD5 (there is no nginx directive for an
    HMAC-SHA256 signature short of a custom Lua/OpenResty module), so
    changing the DEFAULT out from under that deployment would silently
    turn every private file 403 the moment this code shipped.

  * "hmac-sha256" — a real HMAC, for a deployment that does NOT rely on
    nginx's own secure_link module to independently validate these
    tokens (gateway validates every request itself either way, or a
    different front door entirely). Genuinely stronger construction
    (a proper keyed MAC, not a general-purpose hash reused as one) —
    opt into it with `filer_url_signing_scheme = hmac-sha256` if nginx
    parity doesn't matter for your deployment. Breaks the nginx
    `location` block above outright if it's still configured to use
    `secure_link_md5` — the whole point of keeping "md5" the default is
    that switching schemes is something an operator opts into
    deliberately, not something that can happen underneath them.

MD5 here, either way, is not being asked to be a general-purpose
cryptographic signature on its own merits — in "md5" mode it's nginx's
own narrow, well-understood mechanism (a non-forgeable-in-practice
integrity/expiry marker validated against a server-held secret, not a
collision-attack-relevant use); "hmac-sha256" mode doesn't touch MD5 at
all.

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

#: The two schemes sign()/verify() understand — filer/__init__.py's
#: url_signing_scheme() validates a configured value against this set
#: (declare()'s own `type=` only covers int/float/bool/str, no enum
#: support, so the check lives at the point of use instead).
SCHEMES = frozenset({"md5", "hmac-sha256"})
DEFAULT_SCHEME = "md5"


def _digest(uri: str, expires: int, secret: str, scheme: str) -> bytes:
    if scheme == "hmac-sha256":
        return hmac.new(secret.encode(), f"{expires}{uri}".encode(), hashlib.sha256).digest()
    # "md5" — nginx secure_link_md5's own exact literal-string format
    # (a space before the secret, no delimiter between expires and uri)
    # must be reproduced precisely; see this module's own docstring for
    # why that's load-bearing, not incidental.
    return hashlib.md5(f"{expires}{uri} {secret}".encode()).digest()


def sign(uri: str, expires: int, secret: str, *, scheme: str = DEFAULT_SCHEME) -> str:
    digest = _digest(uri, expires, secret, scheme)
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify(uri: str, expires: int, sig: str, secret: str, *, scheme: str = DEFAULT_SCHEME) -> bool:
    if expires < int(time.time()):
        return False
    return hmac.compare_digest(sign(uri, expires, secret, scheme=scheme), sig)
