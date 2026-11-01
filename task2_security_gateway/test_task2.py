"""Comprehensive test suite for Task 2: MCP Security Gateway Proxy."""
import pytest
from httpx import ASGITransport, AsyncClient

from task2_security_gateway.gateway import create_gateway_app, create_token
from task2_security_gateway.mock_mcp_backend import app as backend_app, call_history


@pytest.fixture(autouse=True)
def clear_backend_call_history():
    call_history.clear()


@pytest.fixture
def test_setup():
    # Setup test gateway connected to in-memory downstream backend
    backend_transport = ASGITransport(app=backend_app)

    async def mock_forward_to_downstream(payload, url, client):
        async with AsyncClient(transport=backend_transport, base_url="http://mock-downstream") as backend_client:
            resp = await backend_client.post("/mcp", json=payload)
            from fastapi import Response
            return Response(content=resp.content, status_code=resp.status_code, media_type="application/json")

    gateway_app = create_gateway_app(downstream_url="http://mock-downstream/mcp")
    # Patch forward function for direct in-memory fast testing
    from task2_security_gateway import gateway
    gateway.forward_to_downstream = mock_forward_to_downstream

    gateway_transport = ASGITransport(app=gateway_app)
    return gateway_transport


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
