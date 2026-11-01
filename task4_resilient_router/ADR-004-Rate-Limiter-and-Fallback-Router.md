# ADR-004: Rate-Limiting & Resilient Model Fallback Router for LLM Gateways

## Status
**Accepted & Implemented**

## Context & Problem Statement
Enterprise LLM Gateways (such as **Quilr's LLM Posture & Routing Manager**) must protect backend model providers from traffic surges and budget overruns while ensuring 99.99% availability for critical business applications.

Two essential engineering challenges exist:
1. **Token-Aware Rate Limiting with High Concurrency**:
   Simple request-count rate limiters fail in LLM environments because token consumption varies wildly (a request may use 20 tokens or 4,000 tokens). A token-aware sliding window rate limiter (e.g. 50,000 tokens/min per tenant) is required. Under parallel concurrent requests, naive read-then-write checks cause race conditions where tenants exceed their quota.
2. **Provider Failover & Error Sanitization**:
   Third-party model providers suffer from intermittent HTTP 429 (Too Many Requests) throttling or hung connections (tail latency > 3000ms). The gateway must automatically fail over to a secondary backup model provider within 3000ms, and under dual-failure scenarios, it must sanitize errors to prevent leaking raw upstream stack traces or internal network infrastructure.
3. **Database Constraint**:
   Must use **on-disk SQLite** for local persistence and zero external infrastructure dependencies.

## Architecture & Implementation Decisions

### 1. On-Disk SQLite Storage (`SQLiteTokenRateLimiter`)
- **Database Engine**: Local on-disk SQLite (`gateway_rate_limit.db`) accessed via asynchronous `aiosqlite`.
- **WAL Journaling**: Configured `PRAGMA journal_mode=WAL;` and `PRAGMA synchronous=NORMAL;` for high-throughput concurrent reads and writes without table locking bottlenecks.
- **Table Schema & Indexing**:
  ```sql
  CREATE TABLE IF NOT EXISTS token_usage_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      tenant_id TEXT NOT NULL,
      tokens INTEGER NOT NULL,
      timestamp REAL NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_tenant_timestamp ON token_usage_events(tenant_id, timestamp);
  ```
- **State Eviction & Atomic Quota Allocation**:
  In a single atomic transaction under an async mutex lock:
  1. Purges historical events older than `now - 60.0s`.
  2. Computes current window token sum: `SELECT COALESCE(SUM(tokens), 0), MIN(timestamp) ... WHERE tenant_id = ? AND timestamp >= ?`.
  3. If `current_tokens + requested_tokens > 50,000`, calculates dynamic `Retry-After` seconds and returns HTTP 429 without allocating.
  4. If quota is available, inserts the transaction event atomically.

### 2. Resilient Model Router (`ResilientModelRouter`)
- **Primary Provider Execution**:
  - Sets an explicit HTTP client timeout of 3.0 seconds (3000ms).
  - Handles HTTP 429 (Too Many Requests) or HTTP 5xx responses from Primary.
  - Catches `httpx.TimeoutException` or socket drops.
- **Graceful Failover Mechanics**:
  - Upon any Primary failure, immediately dispatches the completion payload to the Secondary Backup Provider.
  - Adds routing metadata: `_gateway_metadata: { routed_provider: "secondary_backup", failover_reason: "..." }`.
- **Zero-Leak Error Sanitization**:
  If both Primary and Secondary providers fail, the router returns a standardized gateway envelope:
  ```json
  {
    "error": {
      "code": "GATEWAY_UPSTREAM_UNAVAILABLE",
      "message": "The AI service is temporarily unavailable. Primary and secondary providers failed to fulfill request.",
      "status": 502,
      "request_id": "req-..."
    }
  }
  ```
  No internal stack traces, tracebacks, database file paths, or upstream IP addresses are leaked.

## Verification & Concurrency Stress Testing
Tested in `test_task4.py`:
- 20 parallel concurrent requests attempting 60,000 tokens against a 50,000 token limit: exactly 16 requests are approved (48,000 tokens) and 4 rejected, proving zero race condition over-allocations.
- Tenant isolation: Tenant A reaching quota does not impact Tenant B.
- Time-based eviction: Simulates 61s offset to prove token capacity reclamation.
- Primary 429 failover to Backup.
- Primary 3000ms timeout race condition failover to Backup.
- Sanitized dual-failure payload verification (asserting `"Traceback"` and internal IPs are absent).
