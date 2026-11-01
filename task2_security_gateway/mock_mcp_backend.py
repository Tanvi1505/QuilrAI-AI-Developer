"""Task 2: Downstream Mock MCP Server exposing standard and admin-scoped tools."""
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="MockDownstreamMCPServer")

# Call log to verify whether downstream was reached or intercepted
call_history = []

AVAILABLE_TOOLS = [
    {
        "name": "get_system_status",
        "description": "Public health status of systems",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "read_public_docs",
        "description": "Read developer documentation",
        "inputSchema": {"type": "object", "properties": {"doc_id": {"type": "string"}}},
    },
    {
        "name": "admin_reset_key",
        "description": "Privileged operation to reset encryption key",
        "inputSchema": {"type": "object", "properties": {"key_id": {"type": "string"}}},
    },
    {
        "name": "admin_purge_cache",
        "description": "Privileged operation to flush global cluster cache",
        "inputSchema": {"type": "object", "properties": {"region": {"type": "string"}}},
    },
]


@app.post("/mcp")
async def handle_mcp_request(request: Request):
    payload: Dict[str, Any] = await request.json()
    call_history.append(payload)

    method = payload.get("method")
    req_id = payload.get("id")

    if method == "tools/list":
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": AVAILABLE_TOOLS},
            }
        )

    if method == "tools/call":
        params = payload.get("params", {})
        tool_name = params.get("name")
        args = params.get("arguments", {})

        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Downstream executed {tool_name} with {args}",
                        }
                    ],
                    "isError": False,
                },
            }
        )

    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"},
        },
        status_code=400,
    )
