"""Task 4: Resilient Model Fallback Router with 3000ms Timeout & 429 Failover."""
import asyncio
import logging
import sys
import uuid
from typing import Any, Dict, Optional, Tuple
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [model_router] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("model_router")

PRIMARY_TIMEOUT_SECONDS = 3.0  # 3000ms requirement


class ResilientModelRouter:
    """Manages model completion routing with timeout race handling and automatic failover."""

    def __init__(
        self,
        primary_url: str = "http://127.0.0.1:8003/v1/completions",
        secondary_url: str = "http://127.0.0.1:8004/v1/completions",
        primary_timeout: float = PRIMARY_TIMEOUT_SECONDS,
        secondary_timeout: float = 5.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        self.primary_url = primary_url
        self.secondary_url = secondary_url
        self.primary_timeout = primary_timeout
        self.secondary_timeout = secondary_timeout
        self.http_client = http_client or httpx.AsyncClient()

    async def route_completion(
        self,
        payload: Dict[str, Any],
        request_id: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        """Routes completion to Primary. On 429 or timeout (>3000ms), fails over to Secondary."""
        req_id = request_id or f"req-{uuid.uuid4().hex[:12]}"

        # Validate request payload shape
        if not isinstance(payload, dict):
            return 400, {
                "error": {
                    "code": "INVALID_REQUEST_SHAPE",
                    "message": "Request payload must be a JSON object",
                    "request_id": req_id,
                }
            }
        if "prompt" not in payload:
            return 400, {
                "error": {
                    "code": "MISSING_REQUIRED_FIELD",
                    "message": "Missing required field: 'prompt'",
                    "request_id": req_id,
                }
            }
        prompt_text = payload.get("prompt")
        if not isinstance(prompt_text, str) or not prompt_text.strip():
            return 400, {
                "error": {
                    "code": "INVALID_PROMPT",
                    "message": "'prompt' must be a non-empty string",
                    "request_id": req_id,
                }
            }

        should_failover = False
        failover_reason = ""

        # --- Attempt Primary Model Provider with Strict Wall-Clock Deadline ---
        try:
            logger.info("[%s] Routing to primary provider: %s", req_id, self.primary_url)
            # Enforce strict wall-clock deadline across all network phases (DNS, connect, TLS, transfer)
            primary_coro = self.http_client.post(
                self.primary_url,
                json=payload,
                timeout=httpx.Timeout(self.primary_timeout, connect=1.0),
            )
            resp = await asyncio.wait_for(primary_coro, timeout=self.primary_timeout)

            # Check for 429 status requirement
            if resp.status_code == 429:
                should_failover = True
                failover_reason = "Primary provider returned 429 (Too Many Requests)"
                logger.warning("[%s] %s", req_id, failover_reason)
            elif resp.status_code >= 500:
                should_failover = True
                failover_reason = f"Primary provider failed with status {resp.status_code}"
                logger.warning("[%s] %s", req_id, failover_reason)
            else:
                return resp.status_code, resp.json()

        except (httpx.TimeoutException, asyncio.TimeoutError):
            should_failover = True
            failover_reason = f"Primary provider timed out after {int(self.primary_timeout * 1000)}ms"
            logger.warning("[%s] TIMEOUT: %s", req_id, failover_reason)

        except Exception as exc:
            should_failover = True
            failover_reason = f"Primary provider error: {type(exc).__name__}"
            logger.warning("[%s] ERROR: %s", req_id, failover_reason)

        # --- Automatic Failover to Secondary Backup Model Provider ---
        if should_failover:
            logger.info(
                "[%s] INITIATING FAILOVER to secondary backup provider: %s (Reason: %s)",
                req_id,
                self.secondary_url,
                failover_reason,
            )
            try:
                resp = await self.http_client.post(
                    self.secondary_url,
                    json=payload,
                    timeout=self.secondary_timeout,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    # Annotate routing metadata
                    data["_gateway_metadata"] = {
                        "routed_provider": "secondary_backup",
                        "failover_reason": failover_reason,
                    }
                    return 200, data

                logger.error(
                    "[%s] Secondary provider failed with status %d",
                    req_id,
                    resp.status_code,
                )

            except Exception as backup_exc:
                logger.error(
                    "[%s] Secondary provider failed with exception: %s",
                    req_id,
                    backup_exc,
                )

        # --- Standardized Error Payload (Zero Leaked Internal Stack Traces) ---
        sanitized_error = {
            "error": {
                "code": "GATEWAY_UPSTREAM_UNAVAILABLE",
                "message": "The AI service is temporarily unavailable. Primary and secondary providers failed to fulfill request.",
                "status": 502,
                "request_id": req_id,
            }
        }
        return 502, sanitized_error
