"""Task 3: LLM Gateway Proxy Endpoint with Real-Time Streaming PII Redaction Guardrail."""
import json
import logging
import sys
from typing import AsyncGenerator
from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
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
        """Stream guardrailed chunks to client while redacting PII in real time."""
        redactor = StreamingPIIRedactor(lookahead_window=lookahead_window)
        chunk_index = 0

        async for line in upstream_response.aiter_lines():
            line_str = line.strip()
            if not line_str:
                continue

            if line_str == "data: [DONE]":
                # Stream finished upstream; flush remaining buffer
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

    @app.post("/v1/chat/completions")
    async def chat_completions_proxy(request: Request):
        body = await request.json()
        client = httpx.AsyncClient(timeout=30.0)

        # Send request to upstream model provider
        req = client.build_request("POST", upstream_url, json=body)
        resp = await client.send(req, stream=True)

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
