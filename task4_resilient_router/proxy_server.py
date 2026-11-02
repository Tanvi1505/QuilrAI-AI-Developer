"""Task 4: Complete LLM Gateway Server integrating Rate Limiter & Fallback Router."""
import uuid
from contextlib import asynccontextmanager
from typing import Dict, Optional
from fastapi import FastAPI, Header, Request, status
from fastapi.responses import JSONResponse
import httpx

from task4_resilient_router.router import ResilientModelRouter
from task4_resilient_router.storage import SQLiteTokenRateLimiter, DEFAULT_DB_PATH


# Registered mock enterprise tenant credentials for secure authentication
TENANT_CREDENTIALS_REGISTRY = {
    "live_key_tenant_alpha_921": "tenant_1",
    "live_key_tenant_beta_441": "tenant_2",
    "live_key_tenant_race_883": "tenant_race",
}


def authenticate_tenant(
    authorization: Optional[str],
    credentials_registry: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Authenticate incoming caller credentials and securely resolve tenant identity.

    Strictly matches tokens against the verified credentials registry.
    Rejects unauthenticated callers to prevent tenant spoofing or quota exhaustion attacks.
    """
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split("Bearer ", 1)[1].strip()
    if not token:
        return None
    registry = credentials_registry if credentials_registry is not None else TENANT_CREDENTIALS_REGISTRY
    return registry.get(token)


def create_gateway_app(
    db_path: str = DEFAULT_DB_PATH,
    max_tokens_per_minute: int = 50_000,
    primary_url: str = "http://127.0.0.1:8003/v1/completions",
    secondary_url: str = "http://127.0.0.1:8004/v1/completions",
    http_client: Optional[httpx.AsyncClient] = None,
    tenant_credentials: Optional[Dict[str, str]] = None,
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
    ):
        req_id = f"req-{uuid.uuid4().hex[:12]}"

        # 1. Tenant Authentication & Identification (reject unauthenticated access)
        tenant_id = authenticate_tenant(authorization, credentials_registry=tenant_credentials)
        if not tenant_id:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "error": {
                        "code": "UNAUTHORIZED_TENANT",
                        "message": "Missing or invalid tenant credentials in Authorization header",
                        "status": 401,
                        "request_id": req_id,
                    }
                },
            )

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

        # 2. Complete Request Shape Validation (reject JSON arrays, null, non-objects)
        if not isinstance(payload, dict):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "code": "INVALID_REQUEST_SHAPE",
                        "message": "Request body must be a JSON object",
                        "status": 400,
                        "request_id": req_id,
                    }
                },
            )

        if "prompt" not in payload:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "code": "MISSING_REQUIRED_FIELD",
                        "message": "Missing required field: 'prompt'",
                        "status": 400,
                        "request_id": req_id,
                    }
                },
            )

        prompt_text = payload["prompt"]
        if not isinstance(prompt_text, str) or not prompt_text.strip():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "code": "INVALID_PROMPT",
                        "message": "'prompt' must be a non-empty string",
                        "status": 400,
                        "request_id": req_id,
                    }
                },
            )

        # 3. Server-Side Token Estimation & Quota Reservation
        max_tokens = payload.get("max_tokens", 256)
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "error": {
                        "code": "INVALID_MAX_TOKENS",
                        "message": "max_tokens must be a positive integer",
                        "status": 400,
                        "request_id": req_id,
                    }
                },
            )

        estimated_prompt_tokens = max(1, len(prompt_text) // 4)
        # Quota reservation MUST account for estimated prompt input AND permitted maximum output
        min_reservation_tokens = estimated_prompt_tokens + max_tokens

        if "requested_tokens" in payload:
            req_tok = payload["requested_tokens"]
            # Strict type and positivity validation (rejects negative numbers, booleans, floats)
            if not isinstance(req_tok, int) or isinstance(req_tok, bool) or req_tok <= 0:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": {
                            "code": "INVALID_REQUESTED_TOKENS",
                            "message": "requested_tokens must be a strictly positive integer",
                            "status": 400,
                            "request_id": req_id,
                        }
                    },
                )
            # Guard against quota bypass: clamp reservation to account for permitted maximum output
            total_requested_tokens = max(req_tok, min_reservation_tokens)
        else:
            total_requested_tokens = min_reservation_tokens

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
