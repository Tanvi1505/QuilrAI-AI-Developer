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
* **Idempotency, Atomic Concurrency & Crash Recovery:** Added durable idempotency on refunds backed by an on-disk SQLite ledger (`WAL` mode). To prevent race conditions from simultaneous requests sharing an idempotency key, the ledger uses `BEGIN IMMEDIATE` atomic reservation (`IN_PROGRESS` vs `SETTLED`). Exactly one concurrent request executes while others receive in-progress notices or settled replays without duplicate charges. If a worker process is interrupted or crashes mid-flight, a 60-second reservation TTL automatically reclaims stale locks so retries are never permanently blocked.

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
* **Delimiter-Aware Lookahead Buffering & Spaced Patterns:**
  * Spaced PII handling: SSNs and credit card numbers contain valid internal spaces or hyphens (e.g. `123 45 6789`, `4111 2222 3333 4444`). These are evaluated across the active buffer rather than being split by whitespace, and held by a minimum 32-character lookahead window so incomplete spaced patterns are never prematurely emitted.
  * Delimiter-aware email emission: trailing active tokens without whitespace/punctuation are held in the buffer until a delimiter confirms the token is closed, completely preventing emails or subdomains from being partially matched or sliced.
  * Supported formats: expanded regex handles standard RFC 5321 emails (up to 254 chars), US SSNs, and multiple payment card PAN formats (Visa 13/16, MasterCard, Amex 15-digit / 4-6-5, Diners Club 14-digit / 4-6-4, Discover).
  * Lossless flush: when the stream terminates (or if upstream SSE drops without `[DONE]`), the `finally` block redacts and flushes any remaining buffer text so no tokens are lost.
* **Oversized Token Defense & Bounded Memory:** To maintain $O(1)$ memory and protect against delimiter-free streams (e.g. continuous base64 payloads), unbroken tokens exceeding `max_unbroken_token_len` (512 chars) are replaced with `[REDACTED]` rather than emitted as raw slices, guaranteeing zero sensitive text leakage.

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
* **Strict Tenant Authentication & Quota Reservation:**
  * Tenant identity is resolved strictly from verified `Bearer` credentials against a registered credentials store (with dependency injection for test environments), returning 401 for unauthorized calls with no wildcard bypasses.
  * Quota protection: validates that `requested_tokens` and `max_tokens` are strictly positive integers (rejecting negative numbers, booleans, and floats with 400 Bad Request).
  * Output reservation: server-side quota reservations enforce prompt tokens plus permitted maximum output (`estimated_prompt_tokens + max_tokens`), preventing clients from bypassing rate limits by supplying tiny token estimates.
* **On-Disk SQLite with Cross-Process Concurrency:**
  * Uses SQLite `PRAGMA journal_mode=WAL;` and `BEGIN IMMEDIATE` transaction write locks so separate worker processes/containers coordinate safely without races.
  * The check, 60s cleanup, and allocation run atomically, returning dynamic `Retry-After` seconds based on the oldest record in the window.
* **Strict Total Deadline & Sanitized Errors:**
  * Wraps primary provider execution in `asyncio.wait_for` to guarantee a strict 3000ms absolute deadline across all network phases.
  * If both providers fail, returns an HTTP 502 with `GATEWAY_UPSTREAM_UNAVAILABLE` and a correlation request ID, strictly stripping internal stack traces, IP addresses, and socket details.
