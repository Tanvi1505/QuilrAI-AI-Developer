# ADR-003: LLM Gateway Streaming Guardrail (Delimiter-Aware Lookahead & Stateful Oversized-Token Redaction)

## Status
**Accepted & Implemented**

## Context & Problem Statement
In enterprise conversational AI and agent gateways (such as **Quilr's Next-Gen Streaming DLP**), Large Language Models stream responses token-by-token using Server-Sent Events (SSE). Sensitive enterprise information—including Emails, Social Security Numbers (SSNs), and Credit Card Numbers—must be redacted to `[REDACTED]` before leaving the enterprise boundary.

### The Engineering Challenge: The Boundary Token Dilemma
A naive stream proxy that executes regular expressions independently on each chunk fails because LLM tokenizers fracture words and entities across chunk boundaries:
- **Chunk 1**: `"Contact alice."`
- **Chunk 2**: `"smith@enterprise."`
- **Chunk 3**: `"com for billing."`

Neither Chunk 1 nor Chunk 2 contains a complete email. If evaluated independently per chunk, the sensitive data leaks into the client response.

Conversely, accumulating the entire stream into memory until completion violates latency SLAs, degrades **Time To First Token (TTFT)**, and requires unbounded $O(N)$ memory.

Furthermore, a fixed-window lookahead (e.g., blindly emitting `buffer[:-64]`) introduces severe edge cases:
1. An email or domain longer than 64 characters would be partially sliced and emitted before being fully recognized.
2. Spaced entities (such as spaced SSNs `123 45 6789` or spaced credit cards `4111 2222 3333 4444`) can be split across whitespace delimiters.
3. An adversarial stream containing thousands of characters without whitespace (e.g., base64 payloads) could cause unbounded memory growth unless capped.

## Architectural Decision: Delimiter-Aware Buffer with Stateful Oversized-Token Discard
We designed and implemented `StreamingPIIRedactor` with a hybrid delimiter-aware lookahead architecture:

### 1. Unified Buffer Evaluation for Spaced & Delimited PII
- As stream deltas arrive, they are appended to the internal buffer: `buffer += chunk`.
- Digit-based PII patterns (SSNs and Credit Cards) supporting internal hyphens and spaces are evaluated across the full active buffer.
- A lookahead tail ($\ge 32$ characters) is retained to ensure multi-token spaced entities are never partially emitted across chunk boundaries.

### 2. Delimiter-Aware Email Redaction & Safe Emission Boundary
- Emails are redacted strictly on **closed tokens** preceding the active trailing word (identified by the last whitespace delimiter `last_space = max(rfind(' '), rfind('\n'), rfind('\t'))`).
- Text is emitted cleanly up to the last word delimiter prior to the safe cutoff (`min(len(buffer) - lookahead_window, last_space + 1)`). This guarantees active trailing words are never prematurely sliced or emitted before being closed.

### 3. Stateful Oversized-Token Protection ($M = 512$ chars)
- To maintain strictly bounded $O(1)$ memory and prevent denial-of-service vulnerabilities from delimiter-free streams:
  - If the active trailing token reaches `max_unbroken_token_len` (default 512 characters), the token is replaced with `[REDACTED]`.
  - The redactor enters a stateful `discarding_oversized_token = True` mode.
  - All subsequent continuation chunks belonging to the same uninterrupted token are swallowed until the next delimiter arrives.
  - This prevents continuation fragments of an oversized token from being emitted or leaking sensitive suffixes.

### 4. Stream Lifecycle, Termination, and Interruption Handling
- **Normal Completion:** When upstream emits `data: [DONE]`, the lookahead buffer is flushed through the redactor and `[DONE]` is forwarded.
- **Mid-Stream Disconnect:** If the upstream connection drops prematurely (e.g., `RemoteProtocolError`, socket reset), the proxy catches the transport error, logs a sanitized warning, flushes the remaining buffered tokens safely through `redactor.flush()` so partial context is not lost or leaked raw, and terminates without `[DONE]`.
- **Client Cancellation:** Downstream client cancellations (`asyncio.CancelledError`) cleanly exit the async generator and release upstream client resources without illegal yields.

### 5. Log Sanitization & Information Disclosure Prevention
- When upstream returns HTTP 4xx/5xx errors, the proxy logs only the HTTP status code and endpoint metadata. Raw upstream response bodies are excluded from server logs to prevent accidental exposure of confidential prompts, echoed PII, or internal stack traces.

## Mathematical & Operational Boundaries
- **Bounded Memory Guarantee ($O(1)$)**:
  $$\text{Memory} \le \text{lookahead\_window} + \text{max\_unbroken\_token\_len} + \text{max\_chunk\_size} \approx 64 + 512 + 64 = 640 \text{ bytes}$$
- **Time To First Token (TTFT)**:
  Emits closed tokens progressively as soon as safe delimiter boundaries are established, preserving responsive TTFT.
- **Supported Formats**:
  - RFC 5321 emails (up to 254 chars)
  - US SSNs (9–11 chars, formatted with hyphens or spaces)
  - Major credit card formats (Visa 13/16, MasterCard 16, Amex 15/spaced 4-6-5, Diners Club 14/spaced 4-6-4, Discover 16, generic 15–16 continuous digits)

## Verification Strategy
Verified in `task3_streaming_guardrail/test_task3.py`:
- Cross-chunk splits across 2, 3, and single-character adversarial chunks.
- Emails split across chunk boundaries, including 80+ character enterprise emails.
- Spaced SSNs and credit cards split across whitespace chunk boundaries.
- 2,000-character unbroken tokens arriving across 50 small chunks with sensitive suffixes (`sensitive_leak@corp.internal.com`), verifying stateful discarding.
- Mid-stream network drops safely flushing lookahead buffers without crash.
- Upstream error sanitization verifying internal hostnames and diagnostics do not leak to clients.
- Memory boundedness across 1,000 consecutive chunks.
