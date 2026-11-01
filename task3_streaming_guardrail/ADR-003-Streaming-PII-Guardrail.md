# ADR-003: LLM Gateway Streaming Guardrail (Real-Time Bounded Lookahead PII Redaction)

## Status
**Accepted & Implemented**

## Context & Problem Statement
In enterprise conversational AI and agent gateways (such as **Quilr's Next-Gen Streaming DLP**), Large Language Models stream responses token-by-token using Server-Sent Events (SSE). Sensitive enterprise information—including Emails, Social Security Numbers (SSNs), and Credit Card Numbers—must be redacted to `[REDACTED]` before leaving the enterprise boundary.

### The Engineering Challenge: The Boundary Token Dilemma
A naive stream proxy that executes regular expressions on each individual chunk fails catastrophically because LLM tokenizers fracture words and entities across chunk boundaries:
- **Chunk 1**: `"Contact alice."`
- **Chunk 2**: `"smith@enterprise."`
- **Chunk 3**: `"com for billing."`

Neither Chunk 1 nor Chunk 2 contains a complete email. If evaluated independently per chunk, the sensitive data leaks completely into the client's browser or agent memory.

Conversely, accumulating the entire stream into memory until completion violates latency SLAs, destroys **Time To First Token (TTFT)**, and requires unbounded $O(N)$ memory.

## Architectural Decision: Bounded Sliding Window Lookahead Buffer
We designed and implemented a **Streaming Lookahead Buffer** (`StreamingPIIRedactor`):
1. **Bounded Lookahead Window ($W = 64$ chars)**:
   The longest atomic sensitive pattern in our target ontology (Email, SSN, Credit Card) is well under 64 characters.
2. **Buffer Ingestion & Partial Emission**:
   - As each chunk arrives: `buffer += chunk`.
   - Complete pattern matches within `buffer` are immediately redacted to `[REDACTED]`.
   - If `len(buffer) > W`, the prefix `buffer[:-W]` is guaranteed to be free of cross-boundary splits and is **immediately yielded to the client**.
   - `buffer` retains only the trailing $W$ characters.
3. **Stream Termination (EOF Flush)**:
   - When upstream emits `data: [DONE]`, the redactor performs a final pattern scan over the remaining buffer and flushes it before sending `[DONE]`.

## Mathematical & Performance Guarantees
- **Strictly Bounded Memory ($O(1)$)**:
  $$\text{Memory} \le W + \text{max\_chunk\_size} \approx 64 + 32 = 96 \text{ bytes}$$
  Memory consumption remains constant whether the LLM generates 10 tokens or 100,000 tokens.
- **Minimal TTFT Overhead**:
  Tokens are delayed only until the initial $W$ characters (~15 tokens) are received. Subsequent tokens flow concurrently with negligible microsecond regex evaluation overhead.
- **Zero Boundary Leaks**:
  Any pattern of length $\le W$ split across 2, 3, or more arbitrary token cuts is fully reconstructed and redacted.

## Target Ontology & Regex Compilations
1. **Email Addresses**: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`
2. **US Social Security Numbers (SSN)**: `\b\d{3}[-\s]\d{2}[-\s]\d{4}\b`
3. **Credit Cards (Visa, MasterCard, Amex)**: `\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b`

## Verification Strategy
Verified in `test_task3.py`:
- 2-chunk and 3-chunk boundary splits for Emails, SSNs, and Credit Cards.
- 1,000-chunk streaming test proving maximum observed buffer never exceeds $W + 25$ bytes.
- Live SSE HTTP proxy test measuring TTFT and verifying `[REDACTED]` presence in the assembled stream.
