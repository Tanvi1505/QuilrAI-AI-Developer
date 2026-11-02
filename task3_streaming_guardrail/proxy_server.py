"""Task 3: LLM Gateway Proxy Endpoint with Real-Time Streaming PII Redaction Guardrail."""
import asyncio
import json
import logging
import sys
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
import httpx

from task3_streaming_guardrail.guardrail import StreamingPIIRedactor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [llm_gateway_proxy] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("llm_gateway_proxy")


def create_proxy_app(upstream_url: str = "http://127.0.0.1:8002/v1/chat/completions") -> FastAPI:
    app = FastAPI(title="LLMGatewayStreamingGuardrail")

    async def stream_guardrailed_response(
        upstream_response: httpx.Response,
        lookahead_window: int = 64,
    ) -> AsyncGenerator[str, None]:
        """Stream guardrailed chunks to client while redacting PII in real time.

        Guarantees lossless buffer flush even if upstream terminates without [DONE].
        """
        redactor = StreamingPIIRedactor(lookahead_window=lookahead_window)
        chunk_index = 0

        try:
            async for line in upstream_response.aiter_lines():
                line_str = line.strip()
                if not line_str:
                    continue

                if line_str == "data: [DONE]":
                    break

                if line_str.startswith("data: "):
                    raw_json = line_str[6:]
                    try:
                        payload = json.loads(raw_json)
                    except json.JSONDecodeError:
                        continue

                    delta_content = ""
                    choices = payload.get("choices", [])
                    if choices and "delta" in choices[0]:
                        delta_content = choices[0]["delta"].get("content", "")

                    if delta_content:
                        safe_text = redactor.process_chunk(delta_content)
                        if safe_text:
                            chunk_index += 1
                            out_chunk = {
                                "id": f"gw-chunk-{chunk_index}",
                                "object": "chat.completion.chunk",
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {"content": safe_text},
                                        "finish_reason": None,
                                    }
                                ],
                            }
                            yield f"data: {json.dumps(out_chunk)}\n\n"
        except asyncio.CancelledError:
            # Client disconnected / stream cancelled; cleanly propagate without yielding
            raise
        except Exception as exc:
            # Upstream connection failed or dropped mid-stream; log diagnostics to server logs
            logger.error("Upstream connection dropped during streaming: %s", exc)
            return

        # Lossless drain on normal stream completion / EOF: Guarantee remaining buffer is flushed and redacted
        final_tail = redactor.flush()
        if final_tail:
            chunk_index += 1
            flush_chunk = {
                "id": f"gw-chunk-{chunk_index}",
                "object": "chat.completion.chunk",
                "choices": [
                    {"index": 0, "delta": {"content": final_tail}, "finish_reason": None}
                ],
            }
            yield f"data: {json.dumps(flush_chunk)}\n\n"

        yield "data: [DONE]\n\n"

    @app.post("/v1/chat/completions")
    async def chat_completions_proxy(request: Request):
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                status_code=400,
                content={"error": {"code": "INVALID_JSON", "message": "Malformed JSON body"}},
            )

        client = httpx.AsyncClient(timeout=30.0)

        # Connect to upstream model provider with explicit lifecycle and failure handling
        try:
            req = client.build_request("POST", upstream_url, json=body)
            resp = await client.send(req, stream=True)
            if resp.status_code >= 400:
                await resp.aread()
                status_code = resp.status_code
                error_body = resp.text
                await resp.aclose()
                await client.aclose()
                # Log detailed upstream diagnostics strictly to server logs
                logger.error("Upstream model provider error (%d): %s", status_code, error_body)
                # Return generic client-facing message to prevent information disclosure
                return JSONResponse(
                    status_code=status_code,
                    content={
                        "error": {
                            "code": "UPSTREAM_ERROR",
                            "message": "Upstream model provider returned an error",
                        }
                    },
                )
        except Exception:
            await client.aclose()
            return JSONResponse(
                status_code=502,
                content={
                    "error": {
                        "code": "UPSTREAM_UNAVAILABLE",
                        "message": "Failed to connect to upstream LLM service",
                    }
                },
            )

        async def response_wrapper():
            try:
                async for chunk in stream_guardrailed_response(resp):
                    yield chunk
            finally:
                await resp.aclose()
                await client.aclose()

        return StreamingResponse(
            response_wrapper(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app


app = create_proxy_app()
