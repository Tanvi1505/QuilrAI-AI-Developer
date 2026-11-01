# ADR-002: MCP Security Gateway Proxy (Tool Filtering & Role-Based Access Control)

## Status
**Accepted & Implemented**

## Context & Problem Statement
Autonomous AI agents interacting with enterprise systems operate by discovering available capabilities (`tools/list`) and dispatching function calls (`tools/call`). When an agent is exposed to user prompts or external documents, it is vulnerable to **Indirect Prompt Injection** and **Tool Hijacking**, where an attacker manipulates the agent into invoking privileged functions (e.g. `admin_reset_key`, `admin_purge_cache`).

In a zero-trust enterprise deployment (aligned with **Quilr's Guardian Agent** architecture), an MCP server must never be directly exposed to untrusted agent callers. Instead, an intermediate **Security Gateway Proxy** must enforce perimeter authentication and fine-grained, method-level authorization.

## Core Requirements & Policy Rules
1. **Perimeter Authentication**: Extract and validate `Authorization: Bearer <token>` HTTP headers, resolving caller identity and role (`admin` vs `viewer`). Support signed JWTs (HS256) and secure pre-shared tokens.
2. **Transparent Tool Discovery (`tools/list`)**: When an agent requests available tools, forward the request transparently to downstream servers to allow capability exploration without friction.
3. **Privileged Tool Call Interception (`tools/call`)**:
   - Inspect `params.name`. If the tool name begins with `admin_`, verify that the caller's verified role is `admin`.
   - **Zero-Downstream-Leak Guarantee**: If the caller lacks `admin` privileges (e.g. `viewer`), the gateway must **intercept the request immediately** and return standard JSON-RPC error `-32001: Unauthorized Tool Call` directly, **without allowing the request to touch the downstream backend**.
4. **Transport & Protocol Fidelity**: Preserve JSON-RPC 2.0 wire format fidelity (`id`, `jsonrpc: "2.0"`), handling single requests and error sanitization.

## Architecture & Implementation

### 1. Reverse Proxy Middleware & Route Handling
The gateway is implemented using an asynchronous ASGI reverse proxy built with **FastAPI** and **HTTPX**.
- Uses an asynchronous connection pool with keep-alive for minimal proxy overhead.
- Clean application lifespan management for non-blocking graceful shutdown.

### 2. Authorization Engine (`tools/call` Interceptor)
```python
if method == "tools/call":
    tool_name = payload.get("params", {}).get("name", "")
    if tool_name.startswith("admin_") and user_role != "admin":
        emit_security_audit_event("SECURITY_INTERCEPT_TOOL_CALL", {
            "tool": tool_name,
            "role": user_role,
            "decision": "BLOCKED"
        })
        return JSONResponse(
            content=make_jsonrpc_error(
                req_id=req_id,
                code=-32001,
                message=f"Unauthorized Tool Call: Tool '{tool_name}' requires 'admin' role, current role is '{user_role}'"
            )
        )
```

### 3. Verification & Zero-Downstream Audit
Tested via `test_task2.py`:
- Spawns in-memory downstream mock server with a verified invocation log (`call_history`).
- Proves that when a `viewer` calls `admin_reset_key`, the gateway returns HTTP 200 with JSON-RPC error code `-32001`, and `len(call_history) == 0`.
- Proves that when an `admin` calls `admin_reset_key`, the request is forwarded and executed downstream (`len(call_history) == 1`).
