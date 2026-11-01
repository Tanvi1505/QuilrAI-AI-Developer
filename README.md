# Quilr AI - Field Developer Technical Assessment

**Candidate:** Tanvica Samudrala  
**Target Role:** AI Field Developer 
**Company:** Quilr AI  

## [Task 1: Custom MCP Server with Strict Validation & Transport Handling](./task1_mcp_server)

* **Code:** [`task1_mcp_server/server.py`](./task1_mcp_server/server.py)
* **Schemas:** [`task1_mcp_server/schemas.py`](./task1_mcp_server/schemas.py)
* **Tests:** [`task1_mcp_server/test_task1.py`](./task1_mcp_server/test_task1.py)

### What it does
Implements a runnable MCP server using the official Python SDK (`mcp.server.mcpserver.MCPServer`) over the `stdio` transport, exposing two tools:
1. `get_customer_record`: Look up customer records by `customer_id` (format: `CUST-XXXXX`).
2. `trigger_refund`: Process refunds with positive `amount`, valid `customer_id`, and a `reason` (minimum 10 characters).

### Why I built it this way
* **Strict STDIO Isolation:** In MCP over stdio, `stdout` is the raw communication wire for JSON-RPC messages. If any library or stray code runs a `print()`, it corrupts the JSON stream and crashes the client parser. I routed all server logs, diagnostics, and audit events strictly to `sys.stderr`, leaving `stdout` 100% clean for JSON-RPC frames.
* **Error Mapping (`-32602`):** I wanted a clear distinction between protocol validation errors and business logic:
  * Malformed formats (e.g. `INVALID`, negative amounts, short reasons) fail Pydantic validation and are mapped directly to standard JSON-RPC `-32602 (INVALID_PARAMS)` error codes.
  * Valid inputs for customers not in the database return an application response (`status: NOT_FOUND`) so the agent can understand what happened instead of blowing up the connection.
* **Idempotency & Guardrails:** Added an optional `idempotency_key` on refunds so repeated tool calls from an agent retrying don't accidentally double-charge customers.

---

## [Task 2: MCP Security Gateway Proxy (Tool Filtering & Auth)](./task2_security_gateway)

* **Gateway Code:** [`task2_security_gateway/gateway.py`](./task2_security_gateway/gateway.py)
* **Mock MCP Backend:** [`task2_security_gateway/mock_mcp_backend.py`](./task2_security_gateway/mock_mcp_backend.py)
* **Tests:** [`task2_security_gateway/test_task2.py`](./task2_security_gateway/test_task2.py)

### What it does
A lightweight reverse proxy sitting between an AI client and a downstream MCP server that inspects incoming requests and enforces role-based tool execution:
1. Reads `Authorization: Bearer <token>` and extracts user role (`admin` or `viewer`).
2. If `tools/list`: Forwards transparently downstream so agents can discover capabilities.
3. If `tools/call`: Checks `params.name`. If the tool starts with `admin_` (e.g. `admin_reset_key`), only users with the `admin` role are permitted.
4. If unauthorized: Intercepts and immediately returns JSON-RPC error `-32001: Unauthorized Tool Call` **without calling the downstream server**.

### Why I built it this way
* **Zero Downstream Traffic on Intercept:** If a viewer calls an admin tool, the downstream server should never even see the packet. The proxy catches it at the boundary, logs an intercept event to stderr, and responds directly. In `test_task2.py`, I verify that downstream request count remains exactly 0 on rejected calls.
* **Token Flexibility:** Built support for both standard HS256 JWT tokens and pre-shared service keys so it works seamlessly in local dev and production pipelines.
* **Proper JSON-RPC Wire Errors:** Returns a clean JSON-RPC error body with matching `id` so calling agent frameworks parse it naturally without breaking their execution loop.

---

## [Task 3: LLM Gateway Streaming Guardrail (PII Redaction)](./task3_streaming_guardrail)

* **Redactor Logic:** [`task3_streaming_guardrail/guardrail.py`](./task3_streaming_guardrail/guardrail.py)
* **Streaming Proxy:** [`task3_streaming_guardrail/proxy_server.py`](./task3_streaming_guardrail/proxy_server.py)
* **Tests:** [`task3_streaming_guardrail/test_task3.py`](./task3_streaming_guardrail/test_task3.py)

### What it does
An LLM Gateway endpoint that streams Server-Sent Events (SSE) back to the client while intercepting and redacting sensitive data (Emails, SSNs, Credit Cards) to `[REDACTED]` in real time.

### Why I built it this way
* **The Boundary Token Problem:** Tokenizers don't emit words cleanly. An email like `alice@company.com` might arrive split across chunks as `["Contact ali", "ce@company.com"]`. If you just regex each chunk as it arrives, `Contact ali` slips through unredacted. If you wait until the stream finishes to check everything, you destroy Time To First Token (TTFT).
* **Sliding Lookahead Window ($W = 64$ chars):** I implemented a bounded lookahead buffer:
  * As chunks arrive, they append to a small internal buffer and regex redaction runs.
  * Any text before the last 64 characters is guaranteed safe from upcoming splits and is yielded to the client immediately.
  * When the stream finishes (`data: [DONE]`), whatever remains in the buffer is flushed.
* **Memory & Performance:** Buffer memory never exceeds $W + \text{chunk\_size}$ (less than 150 bytes), meaning memory usage is constant $O(1)$ regardless of whether the output is 100 tokens or 100,000 tokens.

---

## [Task 4: Rate-Limiting & Model Fallback Router for LLM Gateways](./task4_resilient_router)

* **SQLite Rate Limiter:** [`task4_resilient_router/storage.py`](./task4_resilient_router/storage.py)
* **Resilient Router:** [`task4_resilient_router/router.py`](./task4_resilient_router/router.py)
* **Gateway Endpoint:** [`task4_resilient_router/proxy_server.py`](./task4_resilient_router/proxy_server.py)
* **Tests:** [`task4_resilient_router/test_task4.py`](./task4_resilient_router/test_task4.py)

### What it does
A completion router that protects upstream LLMs and keeps the service available:
1. Enforces a token-aware sliding window rate limiter (50,000 tokens/minute per tenant) stored in an on-disk SQLite database.
2. If the primary provider returns a 429 Too Many Requests or takes longer than 3000ms, it automatically fails over to a secondary backup provider.
3. If both providers fail, it returns a sanitized gateway error payload without exposing raw stack traces or internal host details.

### Why I built it this way
* **On-Disk SQLite with WAL Mode:** Used `aiosqlite` with `PRAGMA journal_mode=WAL;`. WAL mode allows concurrent reads without blocking on writes, which is essential for a gateway handling multiple parallel requests.
* **Atomic Eviction & Race Prevention:** A naive read-then-write check causes race conditions when multiple requests hit at the same time. The check, 60s cleanup, and insert are handled atomically under an async lock, and dynamic `Retry-After` seconds are calculated based on the oldest event in the active window.
* **Clean Fallback & Sanitization:** The router sets an explicit 3.0s timeout on primary requests. On timeout, 429, or 5xx, it cleanly catches the issue and dispatches to backup. If everything fails, it returns an HTTP 502 with code `GATEWAY_UPSTREAM_UNAVAILABLE` and an assigned request ID, keeping internal IPs and tracebacks strictly hidden.
