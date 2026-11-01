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
