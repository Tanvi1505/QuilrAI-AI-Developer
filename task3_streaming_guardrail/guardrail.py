"""Task 3: High-Performance Streaming Guardrail for Real-Time PII Redaction."""
import re
from typing import AsyncGenerator, Iterator, List, Pattern, Tuple

# Pre-compiled high-performance regular expressions for sensitive entities
# 1. Email Addresses
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# 2. US Social Security Numbers (SSN): 123-45-6789 or 123 45 6789
SSN_REGEX = re.compile(
    r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"
)

# 3. Credit Card Numbers (Visa, MasterCard, Amex, Discover, etc. 13-16 digits with optional spaces/dashes)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b"
)

PII_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("EMAIL", EMAIL_REGEX),
    ("SSN", SSN_REGEX),
    ("CREDIT_CARD", CREDIT_CARD_REGEX),
]

REDACTION_TOKEN = "[REDACTED]"


class StreamingPIIRedactor:
    """Bounded-memory sliding window buffer for real-time PII redaction over token streams.

    Guarantees:
    1. Bounded memory: Buffer never exceeds (lookahead_window + chunk_size) -> O(1) memory.
    2. Boundary safety: PII split across chunk boundaries is caught by the lookahead window.
    3. Low latency / minimal TTFT impact: Tokens beyond the lookahead window are yielded immediately.
    """

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

        Returns:
            The safe slice of text that can be immediately forwarded to the client.
        """
        if not chunk:
            return ""

        self.total_bytes_processed += len(chunk)
        self.buffer += chunk

        # Redact any completed patterns in the current buffer
        self.buffer = self._redact_text(self.buffer)

        # If buffer exceeds the lookahead window, safely emit the leading portion
        if len(self.buffer) > self.lookahead_window:
            safe_length = len(self.buffer) - self.lookahead_window
            safe_text = self.buffer[:safe_length]
            self.buffer = self.buffer[safe_length:]
            return safe_text

        return ""

    def flush(self) -> str:
        """Flush remaining buffer upon stream termination."""
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

    async for chunk in token_stream:
        safe_output = redactor.process_chunk(chunk)
        if safe_output:
            yield safe_output

    final_output = redactor.flush()
    if final_output:
        yield final_output
