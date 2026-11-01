"""Task 4: Mock Upstream Model Providers (Primary with error/delay triggers, Secondary fallback)."""
import asyncio
from typing import Optional
from fastapi import FastAPI, Response
from pydantic import BaseModel

primary_app = FastAPI(title="PrimaryModelProvider")
backup_app = FastAPI(title="BackupModelProvider")


class ProviderState:
    """Configurable test state for Primary Model Provider."""
    simulate_429: bool = False
    simulate_timeout_delay_ms: float = 0.0
    simulate_500: bool = False
    call_count: int = 0


state = ProviderState()


class CompletionRequest(BaseModel):
    model: str = "primary-llm"
    prompt: str
    max_tokens: int = 256


@primary_app.post("/v1/completions")
async def primary_completions(req: CompletionRequest):
    state.call_count += 1

    if state.simulate_timeout_delay_ms > 0:
        await asyncio.sleep(state.simulate_timeout_delay_ms / 1000.0)

    if state.simulate_429:
        return Response(
            content='{"error": "Upstream rate limit reached (429)"}',
            status_code=429,
            media_type="application/json",
        )

    if state.simulate_500:
        return Response(
            content='{"error": "Internal upstream hardware exception"}',
            status_code=500,
            media_type="application/json",
        )

    return {
        "id": "cmpl-primary-001",
        "provider": "primary-model-provider",
        "model": req.model,
        "choices": [{"text": f"Primary completed: {req.prompt}", "finish_reason": "stop"}],
        "usage": {"total_tokens": req.max_tokens},
    }


@backup_app.post("/v1/completions")
async def backup_completions(req: CompletionRequest):
    return {
        "id": "cmpl-backup-002",
        "provider": "secondary-backup-provider",
        "model": "backup-llm",
        "choices": [{"text": f"Backup completed: {req.prompt}", "finish_reason": "stop"}],
        "usage": {"total_tokens": req.max_tokens},
    }
