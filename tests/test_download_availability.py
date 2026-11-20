"""Exercise the real serve handler, S3 reader and gateway without a live DB/S3.

Only metadata and the S3 client's transport are replaced. In particular, the
HTTP assertions catch sending 200 before the lazy S3 reader raises.
"""

import asyncio
import importlib.util
import io
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, ReadTimeoutError

import arc
from filer import tokens
from filer.providers import PROVIDERS, S3Provider, S3Settings
from gateway import GatewayProvider
from gateway.request import HTTPError, StreamResponse, send_stream


@pytest.fixture
def serving(monkeypatch, tmp_path):
    row = {
        "file_id": "pub_test", "status": "clean", "private": False,
        "storage": "s3", "storage_key": "public/test.png",
        "content_type": "image/png", "original_filename": "test.png", "size_bytes": 6,
    }
    settings = SimpleNamespace(get=lambda *args, **kwargs: None)

    async def get(*args):
        return row

    def throw(message, *, status=400, code=None, **kwargs):
        raise HTTPError(status, {"error": message, "code": code})

    relay = SimpleNamespace(
        get=get, all_columns=lambda _: [], throw=throw,
        whitelist=lambda **kwargs: lambda func: func,
    )
    monkeypatch.setattr(arc, "settings", settings)
    monkeypatch.setattr(arc, "relay", relay, raising=False)
    monkeypatch.setattr(arc, "filer", SimpleNamespace(
        _signing_secret=lambda: "test-signing-secret", url_signing_scheme=lambda: "hmac-sha256",
    ), raising=False)
    path = Path(__file__).parents[1] / "api" / "filer_api.py"
    spec = importlib.util.spec_from_file_location("_filer_availability_api", path)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)

    body = io.BytesIO(b"abcdef")
    client = SimpleNamespace(get_object=Mock(return_value={"Body": body}))
    provider = S3Provider()
    monkeypatch.setattr(provider, "_s3_settings", lambda: S3Settings(redirect_over_mb=0))
    monkeypatch.setattr(provider, "_bucket", lambda: "test-bucket")
    monkeypatch.setattr(provider, "_client", lambda *args: client)
    monkeypatch.setitem(PROVIDERS, "s3", provider)

    kernel = SimpleNamespace(settings=settings, has=lambda _: False, project_root=tmp_path)
    app = GatewayProvider(kernel, rate_limit_enabled=False, access_log="off")

    async def handler(request):
        return await api.serve_file(row["file_id"], **{
            key: values[-1] for key, values in request.query_params.items()
        })

    app.add_route("GET", "/files/test", handler)
    return SimpleNamespace(api=api, app=app, row=row, client=client, body=body, provider=provider)


async def request(serving, **kwargs):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=serving.app), base_url="http://test"
    ) as client:
        return await client.get("/files/test", **kwargs)


@pytest.mark.parametrize("error", [
    EndpointConnectionError(endpoint_url="http://private-storage:19000"),
    ReadTimeoutError(endpoint_url="http://private-storage:19000"),
    ClientError({"Error": {"Code": "SlowDown"}, "ResponseMetadata": {"HTTPStatusCode": 503}}, "GetObject"),
    ConnectionResetError("connection reset"),
])
async def test_storage_failure_is_http_503_not_a_successful_image(serving, error):
    serving.client.get_object.side_effect = error
    response = await request(serving)
    assert response.status_code == 503
    assert response.json() == {
        "error": "file storage temporarily unavailable", "code": "storage_unavailable",
    }
    assert response.headers["retry-after"] == "30"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("application/json")
    assert "private-storage" not in response.text


async def test_first_body_read_failure_is_503_and_closes_s3_body(serving):
    class BrokenBody(io.BytesIO):
        def read(self, size=-1):
            raise ReadTimeoutError(endpoint_url="http://private-storage:19000")

    body = BrokenBody(b"x")
    serving.client.get_object.return_value = {"Body": body}
    assert (await request(serving)).status_code == 503
    assert body.closed


async def test_missing_object_is_404(serving):
    serving.client.get_object.side_effect = ClientError(
        {"Error": {"Code": "NoSuchKey"}, "ResponseMetadata": {"HTTPStatusCode": 404}}, "GetObject"
    )
    assert (await request(serving)).status_code == 404


@pytest.mark.parametrize("content", [b"", b"abc", b"a" * (600 * 1024)])
async def test_healthy_files_stream_intact_and_close(serving, content):
    body = io.BytesIO(content)
    serving.client.get_object.return_value = {"Body": body}
    response = await request(serving)
    assert response.status_code == 200
    assert response.content == content
    assert response.headers["content-type"] == "image/png"
    assert response.headers["content-disposition"] == "inline"
    assert body.closed


async def test_recovery_succeeds_with_the_same_private_link(serving):
    serving.row["private"] = True
    exp = int(time.time()) + 300
    params = {"exp": exp, "sig": tokens.sign(
        "/files/pub_test", exp, "test-signing-secret", scheme="hmac-sha256"
    )}
    serving.client.get_object.side_effect = EndpointConnectionError(endpoint_url="http://storage")
    assert (await request(serving, params=params)).status_code == 503
    serving.client.get_object.side_effect = None
    response = await request(serving, params=params)
    assert response.status_code == 200 and response.content == b"abcdef"


@pytest.mark.parametrize("private,status,expected", [(True, "clean", 403), (False, "pending", 404)])
async def test_access_and_scan_checks_run_before_storage(serving, private, status, expected):
    serving.row.update(private=private, status=status)
    assert (await request(serving)).status_code == expected
    serving.client.get_object.assert_not_called()


@pytest.mark.parametrize("fail_on", ["http.response.start", "http.response.body"])
@pytest.mark.parametrize("error_type", [ConnectionResetError, asyncio.CancelledError])
async def test_disconnect_closes_prefetched_body(serving, fail_on, error_type):
    response = await serving.api.serve_file("pub_test")

    async def send(message):
        if message["type"] == fail_on:
            raise error_type()

    with pytest.raises(error_type):
        await send_stream(send, response)
    assert serving.body.closed


async def test_only_one_chunk_is_prefetched(serving):
    body = io.BytesIO(b"x" * (1024 * 1024))
    serving.client.get_object.return_value = {"Body": body}
    response = await serving.api.serve_file("pub_test")
    assert body.tell() == 256 * 1024
    await response.source.aclose()
    assert body.closed


async def test_redirect_behavior_stays_unchanged(serving, monkeypatch):
    serving.row["content_type"] = "application/zip"

    async def redirect(*args, **kwargs):
        return "https://files.example.com/signed"

    monkeypatch.setattr(serving.provider, "redirect_url", redirect)
    response = await request(serving)
    assert response.status_code == 302
    assert response.headers["location"] == "https://files.example.com/signed"
    serving.client.get_object.assert_not_called()


async def test_gateway_still_sends_ndjson_and_closes_its_source():
    messages = []
    closed = []

    async def source():
        try:
            yield {"value": 1}
            yield {"value": 2}
        finally:
            closed.append(True)

    async def send(message):
        messages.append(message)

    await send_stream(send, StreamResponse(source=source()))
    assert messages[0]["status"] == 200
    assert b"".join(message.get("body", b"") for message in messages) == b'{"value":1}\n{"value":2}\n'
    assert messages[-1]["more_body"] is False
    assert closed == [True]
