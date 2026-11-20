# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from plane_mcp_bridge.server import Settings, Verifier, make_server, _url


@pytest.fixture
def config():
    return Settings("https://id.example/", "https://mcp.example/mcp", "https://id.example/keys",
                    "user-1", "chatgpt", "workspace", "http://127.0.0.1:8000", "secret-pat")


@pytest.fixture
def signer():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(config, signer, **overrides):
    claims = {"iss": config.issuer, "aud": config.resource, "sub": config.subject,
              "exp": int(time.time()) + 300, "iat": int(time.time()), "client_id": "chatgpt", "scope": "plane:read plane:write"}
    claims.update(overrides)
    return jwt.encode(claims, signer, algorithm="RS256")


@pytest.mark.anyio
async def test_verifier_rejects_wrong_claims(config, signer, monkeypatch):
    verifier = Verifier(config)
    monkeypatch.setattr(verifier.keys, "get_signing_key_from_jwt", lambda _: SimpleNamespace(key=signer.public_key()))
    assert await verifier.verify_token(token(config, signer))
    for claims in ({"aud": "https://other/mcp"},
                   {"aud": [config.resource, "https://other/mcp"]}, {"iss": "https://other/"}, {"sub": "other"},
                   {"exp": int(time.time()) - 1}, {"nbf": int(time.time()) + 100},
                   {"scope": "plane:write"}, {"client_id": ""}, {"client_id": "other"},
                   {"azp": "other"}, {"client_id": "other", "azp": "chatgpt"}):
        assert await verifier.verify_token(token(config, signer, **claims)) is None
    assert await verifier.verify_token(token(config, signer, aud=[config.resource]))
    assert await verifier.verify_token(token(config, signer, azp="chatgpt"))
    claims = {"iss": config.issuer, "aud": config.resource, "sub": config.subject,
              "exp": int(time.time()) + 300, "iat": int(time.time()), "azp": "chatgpt", "scope": "plane:read"}
    assert await verifier.verify_token(jwt.encode(claims, signer, algorithm="RS256"))
    claims.pop("azp")
    assert await verifier.verify_token(jwt.encode(claims, signer, algorithm="RS256")) is None
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(token(config, other)) is None


def test_url_restrictions():
    assert _url("http://127.0.0.1:8000", local_http=True)
    for value in ("http://evil.example", "https://user:pass@example.com", "https://example.com?x=1", "http://169.254.169.254"):
        with pytest.raises(ValueError):
            _url(value, local_http=True)


def test_http_discovery_and_unauthorized(config):
    with TestClient(make_server(config).streamable_http_app(), base_url="http://localhost:8001") as client:
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                        headers={"Accept": "application/json, text/event-stream"})
        assert r.status_code == 401
        assert "resource_metadata=" in r.headers["www-authenticate"]
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["resource"] == config.resource
        assert metadata.json()["authorization_servers"] == [config.issuer]
        assert set(metadata.json()["scopes_supported"]) == {"plane:read", "plane:write"}


def test_authenticated_calls_scope_binding_and_fixed_upstream(config, signer, monkeypatch):
    import httpx
    import plane_mcp_bridge.server as bridge

    calls = []
    def upstream(request):
        calls.append(request)
        return httpx.Response(200, json={"name": "untrusted record"})

    original_client = httpx.AsyncClient
    monkeypatch.setattr(bridge.httpx, "AsyncClient", lambda **kw: original_client(transport=httpx.MockTransport(upstream), **kw))
    server = make_server(config)
    monkeypatch.setattr(server._token_verifier.keys, "get_signing_key_from_jwt", lambda _: SimpleNamespace(key=signer.public_key()))
    headers = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + token(config, signer, scope="plane:read")}
    def rpc(client, name, arguments):
        return client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1,
            "method": "tools/call", "params": {"name": name, "arguments": arguments}})
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8001") as client:
        headers["Authorization"] = "Bearer " + token(config, signer, aud="https://wrong.example/mcp")
        assert rpc(client, "plane_list_projects", {}).status_code == 401
        headers["Authorization"] = "Bearer " + token(config, signer, aud=[config.resource, "https://other.example/mcp"])
        assert rpc(client, "plane_list_projects", {}).status_code == 401
        headers["Authorization"] = "Bearer " + token(config, signer, client_id="other")
        assert rpc(client, "plane_list_projects", {}).status_code == 401
        headers["Authorization"] = "Bearer " + token(config, signer, azp="other")
        assert rpc(client, "plane_list_projects", {}).status_code == 401
        headers["Authorization"] = "Bearer " + token(config, signer, scope="plane:read")
        headers["X-Agent-Name"] = "forged"
        result = rpc(client, "plane_list_projects", {})
        assert result.status_code == 200
        assert result.json()["result"]["isError"] is False
        assert calls[0].url.host == "127.0.0.1"
        assert calls[0].headers["x-api-key"] == "secret-pat"
        assert "x-agent-name" not in calls[0].headers
        result = rpc(client, "plane_create_project", {"name": "Example", "identifier": "EX"})
        assert result.json()["result"]["isError"] is True
        assert len(calls) == 1
        assert "insufficient_scope" in result.json()["result"]["_meta"]["mcp/www_authenticate"][0]
        result = rpc(client, "plane_list_projects", {"url": "http://169.254.169.254"})
        assert result.json()["result"]["isError"] is True
        assert len(calls) == 1
        headers["Authorization"] = "Bearer " + token(config, signer)
        monkeypatch.setenv("PLANE_SOURCE_COMMIT", "a" * 40)
        resource = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2,
            "method": "resources/read", "params": {"uri": "plane://source-code"}})
        assert resource.status_code == 200
        assert resource.json()["result"]["contents"][0]["text"] == "Source code: https://github.com/Lparksi/plane/tree/" + "a" * 40
        monkeypatch.setenv("PLANE_SOURCE_COMMIT", "a" * 40 + "/../../evil")
        resource = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 3,
            "method": "resources/read", "params": {"uri": "plane://source-code"}})
        assert "unavailable" in resource.json()["result"]["contents"][0]["text"]
        result = rpc(client, "plane_create_project", {"name": "Example", "identifier": "EX"})
        assert result.json()["result"]["isError"] is False
        assert calls[-1].method == "POST"
