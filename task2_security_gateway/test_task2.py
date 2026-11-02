"""Comprehensive test suite for Task 2: MCP Security Gateway Proxy."""
import os
import pytest
from httpx import ASGITransport, AsyncClient

from task2_security_gateway.gateway import create_gateway_app, create_token, get_jwt_secret
from task2_security_gateway.mock_mcp_backend import app as backend_app, call_history

TEST_JWT_SECRET = "test-security-gateway-secret-key-32chars!"
TEST_PRESHARED_TOKENS = {
    "token-admin-secret-xyz": {"sub": "alice_admin", "role": "admin"},
    "token-viewer-secret-abc": {"sub": "bob_viewer", "role": "viewer"},
}

os.environ["JWT_SECRET"] = TEST_JWT_SECRET


@pytest.fixture(autouse=True)
def clear_backend_call_history():
    call_history.clear()


@pytest.fixture
def test_setup():
    # Setup test gateway connected to in-memory downstream backend with explicit test credentials
    backend_transport = ASGITransport(app=backend_app)

    async def mock_forward_to_downstream(payload, url, client):
        async with AsyncClient(transport=backend_transport, base_url="http://mock-downstream") as backend_client:
            resp = await backend_client.post("/mcp", json=payload)
            from fastapi import Response
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")

    gateway_app = create_gateway_app(
        downstream_url="http://mock-downstream/mcp",
        jwt_secret=TEST_JWT_SECRET,
        preshared_tokens=TEST_PRESHARED_TOKENS,
    )
    # Patch forward function for direct in-memory fast testing
    from task2_security_gateway import gateway
    original_forward = gateway.forward_to_downstream
    gateway.forward_to_downstream = mock_forward_to_downstream

    gateway_transport = ASGITransport(app=gateway_app)
    yield gateway_transport
    gateway.forward_to_downstream = original_forward


@pytest.mark.asyncio
async def test_auth_missing_or_invalid_bearer_token(test_setup):
    """Verify rejection when Authorization header is absent or invalid."""
    transport = test_setup
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Missing auth header
        res1 = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert res1.status_code == 401
        data1 = res1.json()
        assert data1["error"]["code"] == -32000

        # Invalid token
        res2 = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"Authorization": "Bearer invalid_garbage_token"},
        )
        assert res2.status_code == 401
        assert res2.json()["error"]["code"] == -32000


@pytest.mark.asyncio
async def test_tools_list_transparent_forwarding_for_viewer(test_setup):
    """Verify tools/list is forwarded transparently for a viewer token."""
    transport = test_setup
    viewer_jwt = create_token(role="viewer")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 10, "method": "tools/list"},
            headers={"Authorization": f"Bearer {viewer_jwt}"},
        )
        assert res.status_code == 200
        body = res.json()
        assert "result" in body
        tool_names = [t["name"] for t in body["result"]["tools"]]
        assert "get_system_status" in tool_names
        assert "admin_reset_key" in tool_names
        # Ensure downstream was actually called
        assert len(call_history) == 1
        assert call_history[0]["method"] == "tools/list"


@pytest.mark.asyncio
async def test_tools_call_non_admin_allowed_for_viewer(test_setup):
    """Verify viewer can execute standard non-admin tools."""
    transport = test_setup
    viewer_jwt = create_token(role="viewer")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "read_public_docs", "arguments": {"doc_id": "doc-01"}},
            },
            headers={"Authorization": f"Bearer {viewer_jwt}"},
        )
        assert res.status_code == 200
        body = res.json()
        assert "result" in body
        assert len(call_history) == 1
        assert call_history[0]["params"]["name"] == "read_public_docs"


@pytest.mark.asyncio
async def test_tools_call_admin_blocked_for_viewer_without_reaching_downstream(test_setup):
    """Verify viewer is denied execution of admin_* tools with code -32001 and downstream is NEVER called."""
    transport = test_setup
    viewer_jwt = create_token(role="viewer")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "admin_reset_key", "arguments": {"key_id": "master-key"}},
            },
            headers={"Authorization": f"Bearer {viewer_jwt}"},
        )
        assert res.status_code == 200
        body = res.json()
        assert "error" in body
        assert body["error"]["code"] == -32001
        assert "Unauthorized Tool Call" in body["error"]["message"]
        assert body["id"] == 99

        # CRITICAL: Verify downstream backend received 0 requests!
        assert len(call_history) == 0, "Downstream server was called when it should have been intercepted!"


@pytest.mark.asyncio
async def test_tools_call_admin_allowed_for_admin_role(test_setup):
    """Verify admin role can execute admin_* tools and request reaches downstream."""
    transport = test_setup
    admin_jwt = create_token(role="admin")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 100,
                "method": "tools/call",
                "params": {"name": "admin_purge_cache", "arguments": {"region": "us-east-1"}},
            },
            headers={"Authorization": f"Bearer {admin_jwt}"},
        )
        assert res.status_code == 200
        body = res.json()
        assert "result" in body
        assert "Downstream executed admin_purge_cache" in body["result"]["content"][0]["text"]

        # Downstream received the authorized admin request
        assert len(call_history) == 1
        assert call_history[0]["params"]["name"] == "admin_purge_cache"


@pytest.mark.asyncio
async def test_preshared_token_support(test_setup):
    """Verify pre-shared static tokens correctly resolve roles and enforce permissions."""
    transport = test_setup

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Preshared viewer token attempting admin call -> blocked
        res_viewer = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 201,
                "method": "tools/call",
                "params": {"name": "admin_reset_key", "arguments": {}},
            },
            headers={"Authorization": "Bearer token-viewer-secret-abc"},
        )
        assert res_viewer.json()["error"]["code"] == -32001
        assert len(call_history) == 0

        # 2. Preshared admin token attempting admin call -> allowed
        res_admin = await client.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 202,
                "method": "tools/call",
                "params": {"name": "admin_reset_key", "arguments": {}},
            },
            headers={"Authorization": "Bearer token-admin-secret-xyz"},
        )
        assert "result" in res_admin.json()
        assert len(call_history) == 1


@pytest.mark.asyncio
async def test_downstream_connection_failure_sanitization():
    """Verify that downstream network failures return sanitized HTTP 502 without leaking internal socket/IP info."""
    # Point gateway to a non-existent port to simulate downstream outage
    broken_gateway = create_gateway_app(downstream_url="http://127.0.0.1:59999/mcp")
    transport = ASGITransport(app=broken_gateway)
    admin_token = create_token(role="admin")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 505, "method": "tools/list"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert res.status_code == 502
        body = res.json()
        assert body["error"]["code"] == -32002
        assert "temporarily unavailable" in body["error"]["message"]
        # Ensure internal port or socket trace is NOT leaked in message
        assert "59999" not in body["error"]["message"]
        assert "ConnectionRefused" not in body["error"]["message"]


@pytest.mark.asyncio
async def test_tools_call_malformed_params_returns_code_32602(test_setup):
    """Verify that non-object params or non-string tool names return standard JSON-RPC -32602 error."""
    transport = test_setup
    admin_token = create_token(role="admin")
    headers = {"Authorization": f"Bearer {admin_token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Case 1: params is integer instead of dict
        res1 = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 101, "method": "tools/call", "params": 123},
            headers=headers,
        )
        assert res1.status_code == 400
        assert res1.json()["error"]["code"] == -32602
        assert "must be a JSON object" in res1.json()["error"]["message"]

        # Case 2: params['name'] is integer instead of string
        res2 = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 102, "method": "tools/call", "params": {"name": 123}},
            headers=headers,
        )
        assert res2.status_code == 400
        assert res2.json()["error"]["code"] == -32602
        assert "must be a non-empty string" in res2.json()["error"]["message"]

        # Case 3: params['name'] is empty string
        res3 = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 103, "method": "tools/call", "params": {"name": ""}},
            headers=headers,
        )
        assert res3.status_code == 400
        assert res3.json()["error"]["code"] == -32602


@pytest.mark.asyncio
async def test_custom_jwt_secret_dependency_injection():
    """Verify gateway accepts injected custom JWT secret and rejects tokens signed with different secret."""
    custom_secret = "custom-production-signing-key-456!"
    app = create_gateway_app(jwt_secret=custom_secret, preshared_tokens={})
    transport = ASGITransport(app=app)

    valid_token = create_token(role="admin", secret=custom_secret)
    invalid_token = create_token(role="admin", secret="wrong-secret-key-999-padding-32chars!")

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Invalid secret signature fails authentication
        res1 = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {invalid_token}"},
        )
        assert res1.status_code == 401
        assert res1.json()["error"]["code"] == -32000

        # Pre-shared test credential disabled
        res2 = await client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            headers={"Authorization": "Bearer token-admin-secret-xyz"},
        )
        assert res2.status_code == 401
        assert res2.json()["error"]["code"] == -32000


@pytest.mark.asyncio
async def test_jsonrpc_array_or_primitive_payload_rejected(test_setup):
    """Verify non-object JSON payloads (lists, primitives) return JSON-RPC -32600."""
    transport = test_setup
    token = create_token(role="viewer")
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Payload is a list
        res = await client.post("/mcp", json=[{"jsonrpc": "2.0"}], headers=headers)
        assert res.status_code == 400
        assert res.json()["error"]["code"] == -32600


def test_missing_jwt_secret_raises_configuration_error():
    """Verify that attempting to retrieve secret without JWT_SECRET raises ValueError."""
    old_secret = os.environ.pop("JWT_SECRET", None)
    try:
        with pytest.raises(ValueError, match="JWT_SECRET environment variable is not configured"):
            get_jwt_secret()
    finally:
        if old_secret:
            os.environ["JWT_SECRET"] = old_secret
