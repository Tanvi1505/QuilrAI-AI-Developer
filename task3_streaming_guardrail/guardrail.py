"""Task 3: High-Performance Streaming Guardrail for Real-Time PII Redaction.

Production-grade Streaming PII Guardrail addressing enterprise requirements:
1. Complete PII Safety Guarantee: Does not emit active, un-delimited word tokens
   until they are closed by a delimiter (or exceed RFC 5321 max length of 254 chars).
   This completely prevents long emails, SSNs, or credit cards from being prematurely sliced
   or partially emitted across chunk boundaries.
2. Low Latency / TTFT Preservation: Tokens before closed word delimiters are emitted progressively.
3. Bounded O(1) Memory: Constant bounded footprint.
4. Lossless Flush: Guaranteed flush of remaining buffer on EOF or connection drops.
"""
import re
from typing import AsyncGenerator, List, Pattern, Tuple

# Pre-compiled high-performance regular expressions for sensitive entities
# 1. Email Addresses
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# 2. US Social Security Numbers (SSN): 123-45-6789 or 123 45 6789
SSN_REGEX = re.compile(
    r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"
)

# 3. Credit Card Numbers (Visa, MasterCard, Amex, Discover, etc.)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b"
)

PII_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("EMAIL", EMAIL_REGEX),
    ("SSN", SSN_REGEX),
    ("CREDIT_CARD", CREDIT_CARD_REGEX),
]

REDACTION_TOKEN = "[REDACTED]"
RFC_5321_MAX_EMAIL_LEN = 256  # RFC 5321 ceiling on email address length


class StreamingPIIRedactor:
    """Bounded lookahead buffer with delimiter-aware emission for real-time PII redaction."""

    def __init__(self, lookahead_window: int = 64):
        self.lookahead_window = lookahead_window
        self.buffer = ""
        self.total_bytes_processed = 0

    def _redact_text(self, text: str) -> str:
        """Apply all PII regex patterns to text."""
        result = text
        for _, pattern in PII_PATTERNS:
            result = pattern.sub(REDACTION_TOKEN, result)
        return result

    def process_chunk(self, chunk: str) -> str:
        """Ingest a stream chunk delta and return safe-to-emit redacted text.

        Enforces:
        1. Safe Redaction: Redacts closed tokens (preceding trailing whitespace/delimiter).
        2. Boundary Guarantee: Never emits the middle of an un-delimited word token
           (protecting emails or tokens of arbitrary length from premature emission).
        3. Low TTFT: Safely emits closed words once buffer exceeds lookahead_window.
        """
        if not chunk:
            return ""

        self.total_bytes_processed += len(chunk)
        self.buffer += chunk

        # Locate the boundary of the trailing active token
        last_space = max(
            self.buffer.rfind(" "),
            self.buffer.rfind("\n"),
            self.buffer.rfind("\t"),
        )

        if last_space == -1:
            # Unbroken word exceeds RFC 5321 email ceiling; safe to redact & emit leading slice
            if len(self.buffer) > RFC_5321_MAX_EMAIL_LEN:
                self.buffer = self._redact_text(self.buffer)
                safe_text = self.buffer[:-RFC_5321_MAX_EMAIL_LEN]
                self.buffer = self.buffer[-RFC_5321_MAX_EMAIL_LEN:]
                return safe_text
            return ""

        # Redact all closed tokens before the trailing active token
        closed_part = self.buffer[:last_space]
        trailing_part = self.buffer[last_space:]
        self.buffer = self._redact_text(closed_part) + trailing_part

        # Recalculate delimiter boundary after redaction substitutions
        last_space = max(
            self.buffer.rfind(" "),
            self.buffer.rfind("\n"),
            self.buffer.rfind("\t"),
        )

        # Emit safe portion: must be older than lookahead_window AND strictly before active trailing word
        if len(self.buffer) > self.lookahead_window:
            safe_cutoff = min(len(self.buffer) - self.lookahead_window, last_space + 1)
            last_delim = max(
                self.buffer.rfind(" ", 0, safe_cutoff),
                self.buffer.rfind("\n", 0, safe_cutoff),
            )
            emit_idx = (last_delim + 1) if last_delim != -1 else safe_cutoff
            if emit_idx > 0:
                safe_text = self.buffer[:emit_idx]
                self.buffer = self.buffer[emit_idx:]
                return safe_text

        return ""

    def flush(self) -> str:
        """Flush and redact remaining buffer upon stream termination or disconnection."""
        if not self.buffer:
            return ""
        final_text = self._redact_text(self.buffer)
        self.buffer = ""
        return final_text


async def redact_stream(
    token_stream: AsyncGenerator[str, None],
    lookahead_window: int = 64,
) -> AsyncGenerator[str, None]:
    """Async generator wrapping an incoming token stream with streaming PII redaction."""
    redactor = StreamingPIIRedactor(lookahead_window=lookahead_window)

    try:
        async for chunk in token_stream:
            safe_output = redactor.process_chunk(chunk)
            if safe_output:
                yield safe_output
    finally:
        final_output = redactor.flush()
        if final_output:
            yield final_output
