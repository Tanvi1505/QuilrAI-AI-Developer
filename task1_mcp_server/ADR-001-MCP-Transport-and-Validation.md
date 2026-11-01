# ADR-001: Model Context Protocol (MCP) STDIO Transport Isolation & Strict Schema Validation

## Status
**Accepted & Implemented**

## Context & Problem Statement
As an **AI Field Developer / Solutions Engineer** deploying agentic integrations into enterprise environments (e.g. Fortune 500 financial or healthcare platforms), MCP servers interface between autonomous LLM agents (clients) and privileged downstream enterprise APIs (CRM, ERP, payment ledgers).

In production zero-trust agent deployments, two critical failure modes occur:
1. **STDIO Transport Corruption**: MCP clients (such as Claude Desktop, agent runtimes, or gateway proxies) expect strict, newline-delimited JSON-RPC 2.0 frames on `stdout`. If a third-party library, debug snippet, or runtime warning writes unformatted text to `stdout`, the client's parser fails catastrophically, severing the agent's connection.
2. **Lax Input Validation & Tool Hijacking**: If an agent hallucinates invalid identifiers, negative refund amounts, or tampered payloads, lax validation can execute financial fraud or trigger downstream 500 exceptions. The MCP protocol specifies that input validation rejections must follow standard JSON-RPC error codes (specifically `-32602: Invalid params`).

## Decision Drivers & Alignment with Quilr AI
- **Quilr Mission Alignment**: Quilr secures the agentic enterprise through runtime guardrails and least-privilege tool execution. This MCP server acts as the first line of defense at the tool interface.
- **Strict Protocol Compliance**: Differentiating between **JSON-RPC Protocol Errors** (`-32602`) and **Domain Application Results** (`status: NOT_FOUND`).
- **Defensive Engineering**: Bounded financial thresholds ($25,000 maximum single automated refund), regex input sanitization, and transaction idempotency defense against agent retry loops.

## Architecture & Implementation Decisions

### 1. Zero-Trust STDIO Isolation
- **Transport Routing**: `sys.stdout` is strictly reserved for the official MCP SDK JSON-RPC wire serializer.
- **Diagnostic Logging**: Configured the Python standard logging framework with `stream=sys.stderr`.
- **Security Audit Stream**: Implemented `emit_security_audit_event()` which outputs structured JSON logs to `sys.stderr` with event type, actor ID, timestamp, and target resource. In production, enterprise log forwarders (FluentBit, Datadog, Splunk) harvest `stderr` directly without interfering with the IPC transport.

### 2. Validation Taxonomy: Protocol Error vs Application Feedback
A common pitfall in MCP implementations is confusing protocol rejections with business logic:
- **Protocol Rejection (`-32602 INVALID_PARAMS`)**: Triggered when the payload fails syntactic or schema contract rules (e.g., `customer_id` does not match `^CUST-[A-Za-z0-9]{5}$`, `amount <= 0`, `reason < 10 chars`). The server catches Pydantic's `ValidationError` inside `StrictValidationMCPServer.call_tool` and raises `MCPError(code=INVALID_PARAMS)`.
- **Domain Result (`status: NOT_FOUND` or `status: FAILED`)**: If `customer_id` has a valid format (e.g. `CUST-99999`) but does not exist in the database, this is an application query result, **not a protocol error**. The server returns a structured JSON result indicating `NOT_FOUND` so the LLM agent can explain the situation to the end user without crashing the RPC session.

### 3. Agentic Idempotency & Financial Thresholds
- Autonomous agents can hallucinate or retry tool calls upon network timeouts. For financial mutations like `trigger_refund`, we support an optional `idempotency_key`.
- Repeated requests with the same key replay the previous settled transaction (`IDEMPOTENT_REPLAY`) rather than issuing duplicate payouts.
- Capped single agent-initiated refunds at $25,000, enforcing a circuit-breaker guardrail.

## Verification & Test Strategy
Tested via a live subprocess test harness ([`test_task1.py`](./test_task1.py)) which:
1. Spawns `python -m task1_mcp_server.server` with pipes connected to `stdin`, `stdout`, and `stderr`.
2. Inspects every line emitted on `stdout` with `json.loads` to prove zero non-JSON pollution occurs under all edge cases.
3. Validates both successful flows and malformed payloads (boundary values, negative amounts, regex violations).
