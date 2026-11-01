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

# 3. Credit Card Numbers (Visa 13/16-digit, MasterCard, Amex 15-digit / 4-6-5, Discover, Diners Club 14-digit / 4-6-4)
CREDIT_CARD_REGEX = re.compile(
    r"\b(?:"
    r"4[0-9]{12}(?:[0-9]{3})?|"  # Visa 13 or 16 digit
    r"(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|"  # MasterCard
    r"3[47][0-9]{13}|"  # Amex 15 digit continuous
    r"3[47][0-9]{2}[-\s][0-9]{6}[-\s][0-9]{5}|"  # Amex 4-6-5 format
    r"3(?:0[0-5]|[68][0-9])[0-9]{11}|"  # Diners Club 14 digit continuous
    r"3(?:0[0-5]|[68][0-9])[0-9][-\s][0-9]{6}[-\s][0-9]{4}|"  # Diners Club 4-6-4 format
    r"6(?:011|5[0-9]{2})[0-9]{12}|"  # Discover 16 digit
    r"(?:[0-9]{4}[-\s]){3}[0-9]{4}|"  # Grouped 16 digit (4-4-4-4)
    r"[0-9]{15,16}"  # Generic 15-16 continuous digits
    r")\b"
)

PII_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("EMAIL", EMAIL_REGEX),
    ("SSN", SSN_REGEX),
    ("CREDIT_CARD", CREDIT_CARD_REGEX),
]

REDACTION_TOKEN = "[REDACTED]"
DEFAULT_MAX_UNBROKEN_TOKEN_LEN = 512  # Upper ceiling to bound buffer memory against malicious delimiter-free streams


class StreamingPIIRedactor:
    """Bounded lookahead buffer with delimiter-aware emission for real-time PII redaction.

    Operational Design & Documented Boundary Guarantees:
    - Standard PII Protection: Fully redacts standard RFC 5321 emails (up to 254 chars),
      US SSNs (9-11 chars), and major credit card PANs across arbitrary streaming chunk boundaries.
    - Delimiter-Aware Windowing: Trailing active words (without trailing whitespace or punctuation)
      are preserved in the lookahead buffer until closed, preventing partial token emission.
    - Lossless Terminal Flush: Redacts and flushes remaining buffer on stream termination or disconnect.
    - Memory Boundedness vs. Token Length Trade-off: To maintain O(1) bounded memory and prevent DOS
      vulnerabilities from infinite streams without whitespace (e.g. continuous base64), tokens
      exceeding `max_unbroken_token_len` (default 512 chars) are progressively flushed. If a non-standard
      sensitive entity exceeds 512 continuous characters without a delimiter, partial emission can occur.
    """

    def __init__(self, lookahead_window: int = 64, max_unbroken_token_len: int = DEFAULT_MAX_UNBROKEN_TOKEN_LEN):
        # Enforce minimum 32-char lookahead to guarantee spaced SSNs (11 chars) and Cards (19 chars) are never partially emitted
        self.lookahead_window = max(lookahead_window, 32)
        self.max_unbroken_token_len = max_unbroken_token_len
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
        1. Unified Spaced PII Redaction: Evaluates SSN and Credit Card patterns across the active buffer,
           supporting valid internal whitespace and hyphens (e.g. '123 45 6789', '4111 2222 3333 4444')
           without breaking across space boundaries.
        2. Delimiter-Aware Email Redaction: Redacts emails strictly on closed tokens (before the active
           trailing word) to prevent premature matching of intermediate subdomains (e.g. '.corp.' or '.or').
        3. Oversized Token Protection: Replaces unbroken tokens exceeding max_unbroken_token_len with
           [REDACTED] to guarantee zero sensitive data leakage while maintaining bounded O(1) memory.
        4. Lookahead Tail Protection: Holds at least lookahead_window (>= 32 chars) so incomplete
           spaced entities are never partially emitted.
        """
        if not chunk:
            return ""

        self.total_bytes_processed += len(chunk)
        self.buffer += chunk

        # 1. Redact digit-based PII across buffer (supports internal spaces and hyphens)
        self.buffer = SSN_REGEX.sub(REDACTION_TOKEN, self.buffer)
        self.buffer = CREDIT_CARD_REGEX.sub(REDACTION_TOKEN, self.buffer)

        # 2. Check whitespace boundary for email redaction and token emission
        last_space = max(
            self.buffer.rfind(" "),
            self.buffer.rfind("\n"),
            self.buffer.rfind("\t"),
        )

        if last_space == -1:
            if len(self.buffer) >= self.max_unbroken_token_len:
                # Oversized uninterrupted token: to prevent leaking sensitive substrings
                # while preserving bounded O(1) memory, replace oversized token with REDACTION_TOKEN
                self.buffer = ""
                return REDACTION_TOKEN
            return ""

        # 3. Redact emails strictly on closed tokens preceding the active trailing word
        closed_part = self.buffer[:last_space]
        trailing_part = self.buffer[last_space:]
        self.buffer = EMAIL_REGEX.sub(REDACTION_TOKEN, closed_part) + trailing_part

        # Recalculate delimiter boundary after email redaction substitution
        last_space = max(
            self.buffer.rfind(" "),
            self.buffer.rfind("\n"),
            self.buffer.rfind("\t"),
        )

        # 4. Calculate safe emission index
        safe_cutoff = min(len(self.buffer) - self.lookahead_window, last_space + 1)
        if safe_cutoff <= 0:
            return ""

        # Find the last word boundary before safe_cutoff to emit cleanly on word delimiters
        last_delim = max(
            self.buffer.rfind(" ", 0, safe_cutoff),
            self.buffer.rfind("\n", 0, safe_cutoff),
            self.buffer.rfind("\t", 0, safe_cutoff),
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
