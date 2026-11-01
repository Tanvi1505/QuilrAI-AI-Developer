"""Task 4: Complete LLM Gateway Server integrating Rate Limiter & Fallback Router."""
import uuid
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Header, Request, status
from fastapi.responses import JSONResponse
import httpx

from task4_resilient_router.router import ResilientModelRouter
from task4_resilient_router.storage import SQLiteTokenRateLimiter, DEFAULT_DB_PATH


def create_gateway_app(
    db_path: str = DEFAULT_DB_PATH,
    max_tokens_per_minute: int = 50_000,
    primary_url: str = "http://127.0.0.1:8003/v1/completions",
    secondary_url: str = "http://127.0.0.1:8004/v1/completions",
    http_client: Optional[httpx.AsyncClient] = None,
) -> FastAPI:
    rate_limiter = SQLiteTokenRateLimiter(
        db_path=db_path,
        max_tokens_per_minute=max_tokens_per_minute,
        window_seconds=60.0,
    )
    shared_client = http_client or httpx.AsyncClient()
    router = ResilientModelRouter(
        primary_url=primary_url,
        secondary_url=secondary_url,
        primary_timeout=3.0,
        http_client=shared_client,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await rate_limiter.init_db()
        yield
        if not http_client:
            await shared_client.aclose()

    app = FastAPI(title="LLMResilientGateway", lifespan=lifespan)
    app.state.rate_limiter = rate_limiter
    app.state.router = router

    @app.post("/v1/completions")
    async def completions_endpoint(
        request: Request,
        authorization: Optional[str] = Header(None),
        x_tenant_id: Optional[str] = Header(None),
    ):
        req_id = f"req-{uuid.uuid4().hex[:12]}"

        # 1. Tenant Authentication & Identification
        tenant_id = x_tenant_id
        if not tenant_id and authorization and authorization.startswith("Bearer "):
            tenant_id = authorization.split("Bearer ", 1)[1].strip()

        if not tenant_id:
            tenant_id = "default-tenant"

        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "code": "INVALID_JSON_PAYLOAD",
                        "message": "Malformed JSON body in request",
                        "status": 400,
                        "request_id": req_id,
                    }
                },
            )

        # 2. Token Estimation (prompt length heuristic: 1 token ~ 4 chars + requested max_tokens)
        prompt_text = payload.get("prompt", "")
        max_tokens = payload.get("max_tokens", 256)
        estimated_prompt_tokens = max(1, len(prompt_text) // 4)
        total_requested_tokens = payload.get("requested_tokens", estimated_prompt_tokens + max_tokens)

        # 3. Sliding Window Rate Limiter Check (backed by SQLite)
        allowed, current_used, retry_after = await rate_limiter.check_and_record_tokens(
            tenant_id=tenant_id,
            requested_tokens=total_requested_tokens,
        )

        if not allowed:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(int(retry_after))},
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"Token rate limit exceeded. Tenant used {current_used} tokens; limit is {rate_limiter.max_tokens_per_minute} tokens/min.",
                        "status": 429,
                        "retry_after_seconds": retry_after,
                        "request_id": req_id,
                    }
                },
            )

        # 4. Resilient Routing with 429 & 3000ms Timeout Fallback
        status_code, response_data = await router.route_completion(
            payload=payload,
            request_id=req_id,
        )

        return JSONResponse(status_code=status_code, content=response_data)

    return app


app = create_gateway_app()
