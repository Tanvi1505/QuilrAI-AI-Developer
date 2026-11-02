"""Comprehensive test suite for Task 3: Streaming Guardrail (PII Redaction)."""
import json
import time
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from task3_streaming_guardrail.guardrail import StreamingPIIRedactor
from task3_streaming_guardrail.mock_llm_provider import app as mock_provider_app, DEFAULT_CHUNKS
from task3_streaming_guardrail.proxy_server import create_proxy_app


# ----------------------------------------------------------------------
# 1. Unit Tests for StreamingPIIRedactor & Buffer State Management
# ----------------------------------------------------------------------

def test_single_chunk_pii_redaction():
    """Verify standard single-chunk redaction of email, SSN, and credit card."""
    redactor = StreamingPIIRedactor(lookahead_window=30)
    output = redactor.process_chunk("Reach out to security@company.com or call support.")
    output += redactor.flush()
    assert "security@company.com" not in output
    assert "[REDACTED]" in output


def test_cross_chunk_boundary_email_redaction():
    """Verify that an email split across 3 chunks is caught and redacted."""
    redactor = StreamingPIIRedactor(lookahead_window=40)
    chunks = [
        "Please send the report to john.",
        "doe.developer@",
        "domain-example.org right away.",
    ]
    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert "john.doe.developer@domain-example.org" not in full_result
    assert "Please send the report to [REDACTED] right away." == full_result


def test_cross_chunk_boundary_ssn_redaction():
    """Verify that an SSN split across 3 separate chunk deltas is redacted."""
    redactor = StreamingPIIRedactor(lookahead_window=20)
    chunks = ["Customer SSN is ", "987-", "65-", "4321 for verification."]
    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert "987-65-4321" not in full_result
    assert "Customer SSN is [REDACTED] for verification." == full_result


def test_cross_chunk_boundary_credit_card_redaction():
    """Verify that a credit card number split across chunks is redacted."""
    redactor = StreamingPIIRedactor(lookahead_window=30)
    chunks = ["Payment processed on card: 4111-2222", "-3333-4444 successfully."]
    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert "4111-2222-3333-4444" not in full_result
    assert "Payment processed on card: [REDACTED] successfully." == full_result


def test_cross_chunk_boundary_very_long_email_redaction():
    """Verify that an email longer than 80 chars split across chunks is completely redacted."""
    redactor = StreamingPIIRedactor(lookahead_window=256)
    long_email = "very.long.enterprise.compliance.officer.name@security-governance.corp.subdomain.internal-systems.com"
    chunks = [
        "Please forward the audit dossier to ",
        "very.long.enterprise.",
        "compliance.officer.name@",
        "security-governance.corp.",
        "subdomain.internal-systems.com",
        " for review.",
    ]
    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert long_email not in full_result
    assert "Please forward the audit dossier to [REDACTED] for review." == full_result


def test_lossless_flush_when_upstream_drops_without_done():
    """Verify that any trailing buffer is flushed and not lost if upstream connection drops without [DONE]."""
    redactor = StreamingPIIRedactor(lookahead_window=256)
    # Stream text that is shorter than lookahead_window (held in buffer)
    redactor.process_chunk("Final concluding message from model")
    # Simulate abrupt connection termination
    flushed = redactor.flush()
    assert flushed == "Final concluding message from model"
    assert len(redactor.buffer) == 0


def test_memory_efficiency_bounded_buffer():
    """Verify that processing 10,000 tokens maintains an O(1) bounded buffer size."""
    lookahead = 50
    redactor = StreamingPIIRedactor(lookahead_window=lookahead)
    max_observed_buffer = 0

    # Stream 1,000 chunks of non-sensitive text
    for i in range(1000):
        chunk = f" token_{i} "
        redactor.process_chunk(chunk)
        if len(redactor.buffer) > max_observed_buffer:
            max_observed_buffer = len(redactor.buffer)

    # Buffer must never exceed lookahead + maximum chunk size (approx 50 + 15 = 65)
    assert max_observed_buffer <= lookahead + 25, f"Buffer unbounded: {max_observed_buffer}"
    redactor.flush()
    assert len(redactor.buffer) == 0


def test_clean_text_preservation():
    """Verify that harmless non-sensitive text is passed through without corruption."""
    redactor = StreamingPIIRedactor(lookahead_window=30)
    sample = "The quick brown fox jumps over the lazy dog. Version 2.4.0 deployed at 14:00 UTC."
    output = redactor.process_chunk(sample) + redactor.flush()
    assert output == sample


# ----------------------------------------------------------------------
# 2. End-to-End Integration Tests for Proxy Streaming Endpoint
# ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_streaming_proxy_end_to_end_pii_redaction_and_ttft():
    """Verify end-to-end SSE proxying intercepts and redacts stream in real time."""
    # Connect proxy to mock upstream provider
    provider_transport = ASGITransport(app=mock_provider_app)

    # Mock client requesting through proxy
    proxy_app = create_proxy_app(upstream_url="http://mock-upstream/v1/chat/completions")

    # Override proxy client to route directly to ASGI transport
    from unittest.mock import patch
    original_client = httpx.AsyncClient

    def get_test_client(*args, **kwargs):
        return original_client(transport=provider_transport, *args, **kwargs)

    with patch("task3_streaming_guardrail.proxy_server.httpx.AsyncClient", side_effect=get_test_client):
        proxy_transport = ASGITransport(app=proxy_app)
        async with AsyncClient(transport=proxy_transport, base_url="http://test-gw") as client:
            t_start = time.time()
            ttft = None
            received_tokens = []

            async with client.stream(
                "POST",
                "/v1/chat/completions",
                json={"prompt": "Review customer notes", "stream": True, "delay_ms": 5.0},
            ) as response:
                assert response.status_code == 200
                assert "text/event-stream" in response.headers["content-type"]

                async for line in response.aiter_lines():
                    line = line.strip()
                    if not line:
                        continue
                    if line == "data: [DONE]":
                        break
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        token = data["choices"][0]["delta"]["content"]
                        if token:
                            if ttft is None:
                                ttft = time.time() - t_start
                            received_tokens.append(token)

            full_reconstructed = "".join(received_tokens)

            # Assert PII was completely redacted
            assert "support-agent.42@subdomain.corp-internal.com" not in full_reconstructed
            assert "123-45-6789" not in full_reconstructed
            assert "4111-2222-3333-4444" not in full_reconstructed
            assert "[REDACTED]" in full_reconstructed

            # Assert responsive TTFT (first token emitted well before full completion)
            assert ttft is not None
            assert len(received_tokens) > 1, "Expected multiple streamed chunks, not a single monolithic buffer"


# ----------------------------------------------------------------------
# 3. Adversarial Edge Case & Boundary Tests
# ----------------------------------------------------------------------

def test_adversarial_single_character_chunk_stream():
    """Adversarially feeds input one character at a time to test boundary resilience."""
    redactor = StreamingPIIRedactor(lookahead_window=20)
    input_text = "Call alice at alice.smith@security.org or card 4111-2222-3333-4444 or 123-45-6789 today."

    emitted = []
    for ch in input_text:
        out = redactor.process_chunk(ch)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    result = "".join(emitted)
    assert "alice.smith@security.org" not in result
    assert "4111-2222-3333-4444" not in result
    assert "123-45-6789" not in result
    assert "Call alice at [REDACTED] or card [REDACTED] or [REDACTED] today." == result


def test_adversarial_diverse_credit_card_representations():
    """Verify redaction across diverse credit card formats (Amex 4-6-5, Diners 4-6-4, continuous 15/16)."""
    cards = [
        ("Amex formatted", "Charge on 3782-822463-98710 card.", "Charge on [REDACTED] card."),
        ("Amex spaced", "Charge on 3782 822463 98710 card.", "Charge on [REDACTED] card."),
        ("Diners Club", "Charge on 3852-000000-0000 card.", "Charge on [REDACTED] card."),
        ("MasterCard 16", "Charge on 5500222233334444 card.", "Charge on [REDACTED] card."),
    ]
    for desc, raw, expected in cards:
        r = StreamingPIIRedactor(lookahead_window=20)
        res = r.process_chunk(raw) + r.flush()
        assert res == expected, f"Failed for {desc}: got {res}"


def test_adversarial_unusually_long_unbroken_token_replaced():
    """Verify that an uninterrupted token exceeding max length is replaced with [REDACTED] to prevent leaks."""
    redactor = StreamingPIIRedactor(lookahead_window=32, max_unbroken_token_len=100)
    oversized_token = "A" * 150

    emitted = []
    for i in range(0, len(oversized_token), 25):
        out = redactor.process_chunk(oversized_token[i:i + 25])
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    result = "".join(emitted)
    assert "[REDACTED]" in result
    assert "A" * 100 not in result
    assert len(redactor.buffer) == 0


def test_adversarial_oversized_unbroken_token_following_ordinary_text():
    """Verify that an oversized token following whitespace does not bypass the bounded-memory limit."""
    redactor = StreamingPIIRedactor(lookahead_window=32, max_unbroken_token_len=100)
    # Stream ordinary text followed by a 300-char uninterrupted token
    out1 = redactor.process_chunk("System diagnostics log: " + "X" * 300)
    # Buffer must not hold 300 raw chars; it must cap and replace the trailing token
    assert len(redactor.buffer) < 100
    out2 = redactor.flush()
    full = out1 + out2
    assert "System diagnostics log: [REDACTED]" in full
    assert "X" * 100 not in full


def test_cross_chunk_boundary_spaced_ssn_redaction():
    """Verify SSNs split across whitespace chunk boundaries are completely redacted."""
    redactor = StreamingPIIRedactor(lookahead_window=32)
    chunks = ["Customer SSN is 123 ", "45 ", "6789 for account verification."]
    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert "123 45 6789" not in full_result
    assert "123" not in full_result
    assert "Customer SSN is [REDACTED] for account verification." == full_result


def test_cross_chunk_boundary_spaced_credit_card_redaction():
    """Verify credit card numbers split across whitespace chunk boundaries are completely redacted."""
    redactor = StreamingPIIRedactor(lookahead_window=32)
    chunks = ["Payment processed on card 4111 ", "2222 ", "3333 ", "4444 successfully."]
    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert "4111 2222 3333 4444" not in full_result
    assert "4111" not in full_result
    assert "Payment processed on card [REDACTED] successfully." == full_result


def test_adversarial_multichunk_oversized_token_with_sensitive_suffix():
    """Verify that a 2,000-char unbroken token arriving across 50 small chunks with a sensitive suffix is statefully discarded."""
    redactor = StreamingPIIRedactor(lookahead_window=32, max_unbroken_token_len=100)
    raw_token = ("A" * 1960) + "sensitive_leak@corp.internal.com"
    full_stream_text = "Log start: " + raw_token + " and subsequent safe text."

    # Slice stream into 50 chunks of ~40 characters each
    chunk_size = 40
    chunks = [full_stream_text[i:i + chunk_size] for i in range(0, len(full_stream_text), chunk_size)]
    assert len(chunks) >= 50

    emitted = []
    for c in chunks:
        out = redactor.process_chunk(c)
        if out:
            emitted.append(out)
    emitted.append(redactor.flush())

    full_result = "".join(emitted)
    assert "sensitive_leak@corp.internal.com" not in full_result
    assert "A" * 100 not in full_result
    assert "[REDACTED]" in full_result
    assert "and subsequent safe text." in full_result
    assert redactor.discarding_oversized_token is False


@pytest.mark.asyncio
async def test_streaming_proxy_upstream_unavailable_returns_502():
    """Verify proxy returns structured 502 with clean JSON when upstream is unreachable."""
    proxy_app = create_proxy_app(upstream_url="http://127.0.0.1:59999/v1/chat/completions")
    proxy_transport = ASGITransport(app=proxy_app)
    async with AsyncClient(transport=proxy_transport, base_url="http://test-gw") as client:
        resp = await client.post("/v1/chat/completions", json={"prompt": "ping"})
        assert resp.status_code == 502
        data = resp.json()
        assert data["error"]["code"] == "UPSTREAM_UNAVAILABLE"


@pytest.mark.asyncio
async def test_streaming_proxy_malformed_json_returns_400():
    """Verify proxy returns structured 400 when request body is not valid JSON."""
    proxy_app = create_proxy_app()
    proxy_transport = ASGITransport(app=proxy_app)
    async with AsyncClient(transport=proxy_transport, base_url="http://test-gw") as client:
        resp = await client.post(
            "/v1/chat/completions",
            content=b"invalid-json-data",
            headers={"content-type": "application/json"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert data["error"]["code"] == "INVALID_JSON"

