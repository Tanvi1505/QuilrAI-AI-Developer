"""Task 3: Mock Upstream LLM Provider streaming SSE chunks with realistic token splits."""
import asyncio
import json
from typing import AsyncGenerator, List, Optional
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI(title="MockLLMProvider")


class CompletionRequest(BaseModel):
    prompt: Optional[str] = "Hello world"
    stream: bool = True
    chunks: Optional[List[str]] = None
    delay_ms: float = 10.0


# Default test sequence designed to split PII across multiple chunk boundaries
DEFAULT_CHUNKS = [
    "Welcome to customer support. ",
    "The primary contact is ",
    "supp",
    "ort-agent.42@",
    "subdomain.corp-internal.com",
    ". Also, verify SSN: ",
    "123-",
    "45-",
    "6789 before proceeding. ",
    "Card on file is 4111-22",
    "22-3333-",
    "4444. Have a ",
    "great day!",
]


async def generate_sse_chunks(
    chunks: List[str], delay_ms: float
) -> AsyncGenerator[str, None]:
    for i, token in enumerate(chunks):
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)

        chunk_payload = {
            "id": f"chatcmpl-mock-{i}",
            "object": "chat.completion.chunk",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": token},
                    "finish_reason": None,
                }
            ],
        }
        yield f"data: {json.dumps(chunk_payload)}\n\n"

    # Terminal stream frame
    yield "data: [DONE]\n\n"


@app.post("/v1/chat/completions")
async def chat_completions(req: CompletionRequest):
    chunks = req.chunks if req.chunks is not None else DEFAULT_CHUNKS
    return StreamingResponse(
        generate_sse_chunks(chunks, req.delay_ms),
        media_type="text/event-stream",
    )
