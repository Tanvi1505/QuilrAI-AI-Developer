"""Task 2: MCP Security Gateway Proxy with Bearer Auth & Tool-Level RBAC Filtering."""
import logging
import sys
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional
import jwt
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
import httpx

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [mcp_gateway] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("mcp_gateway")

JWT_SECRET = "security-gateway-secret-key-32chars!"
JWT_ALGORITHM = "HS256"

# Known token lookup for fast testing and pre-shared token authentication
PRESHARED_TOKENS = {
    "token-admin-secret-xyz": {"sub": "alice_admin", "role": "admin"},
    "token-viewer-secret-abc": {"sub": "bob_viewer", "role": "viewer"},
}


def create_token(role: str, user_id: str = "user-123") -> str:
    """Utility to generate a signed JWT with role claim."""
    return jwt.encode(
        {"sub": user_id, "role": role},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def extract_role_from_token(token: str) -> Optional[str]:
    """Extract user role from Bearer token supporting both signed JWT and pre-shared tokens."""
    # 1. Check pre-shared tokens
    if token in PRESHARED_TOKENS:
        return PRESHARED_TOKENS[token]["role"]

    # 2. Decode JWT
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return decoded.get("role")
    except jwt.PyJWTError as e:
        logger.warning("Token decoding failed: %s", e)
        return None


def make_jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> Dict[str, Any]:
    """Format standard JSON-RPC 2.0 error object."""
    error_obj: Dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error_obj["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": error_obj,
    }


def create_gateway_app(downstream_url: str = "http://127.0.0.1:8001/mcp") -> FastAPI:
    """Factory creating the MCP Security Gateway FastAPI application."""
    http_client = httpx.AsyncClient(timeout=10.0)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        await http_client.aclose()

    app = FastAPI(title="MCPSecurityGateway", lifespan=lifespan)

    @app.post("/mcp")
    async def mcp_proxy(
        request: Request,
        authorization: Optional[str] = Header(None),
    ):
        # 1. Bearer Token Authentication
        if not authorization or not authorization.startswith("Bearer "):
            logger.warning("Request rejected: Missing or malformed Authorization header")
            return JSONResponse(
                status_code=401,
                content=make_jsonrpc_error(
                    None,
                    -32000,
                    "Unauthorized: Missing or malformed Bearer token",
                ),
            )

        token = authorization.split("Bearer ", 1)[1].strip()
        user_role = extract_role_from_token(token)

        if not user_role:
            logger.warning("Request rejected: Invalid or expired token")
            return JSONResponse(
                status_code=401,
                content=make_jsonrpc_error(
                    None,
                    -32000,
                    "Unauthorized: Invalid token or unrecognized credentials",
                ),
            )

        # 2. Parse JSON-RPC wire format payload
        try:
            payload: Dict[str, Any] = await request.json()
        except Exception as e:
            logger.warning("Invalid JSON payload received: %s", e)
            return JSONResponse(
                status_code=400,
                content=make_jsonrpc_error(None, -32700, "Parse error: Invalid JSON received"),
            )

        method = payload.get("method")
        req_id = payload.get("id")

        if payload.get("jsonrpc") != "2.0" or not method:
            return JSONResponse(
                status_code=400,
                content=make_jsonrpc_error(req_id, -32600, "Invalid Request: Not a valid JSON-RPC 2.0 payload"),
            )

        logger.info("Processing JSON-RPC method '%s' for role '%s'", method, user_role)

        # 3. RBAC Policy Inspection
        # Case A: tools/list -> Forward transparently to downstream server
        if method == "tools/list":
            logger.info("Forwarding 'tools/list' transparently to downstream: %s", downstream_url)
            return await forward_to_downstream(payload, downstream_url, http_client)

        # Case B: tools/call -> Inspect tool name for 'admin_' prefix
        if method == "tools/call":
            params = payload.get("params", {})
            tool_name = params.get("name", "")

            if tool_name.startswith("admin_"):
                if user_role != "admin":
                    logger.warning(
                        "SECURITY INTERCEPT: Denied '%s' tool call by user role '%s'",
                        tool_name,
                        user_role,
                    )
                    # Requirement: intercept and return JSON-RPC Error (-32001: Unauthorized Tool Call)
                    # directly WITHOUT calling downstream server.
                    return JSONResponse(
                        content=make_jsonrpc_error(
                            req_id=req_id,
                            code=-32001,
                            message=f"Unauthorized Tool Call: Tool '{tool_name}' requires 'admin' role, current role is '{user_role}'",
                        )
                    )

            # Authorized or non-admin tool: forward to downstream
            return await forward_to_downstream(payload, downstream_url, http_client)

        # All other methods forward transparently
        return await forward_to_downstream(payload, downstream_url, http_client)

    return app


async def forward_to_downstream(
    payload: Dict[str, Any],
    downstream_url: str,
    client: httpx.AsyncClient,
) -> JSONResponse:
    """Forward transparent JSON-RPC request to downstream MCP server and relay the response."""
    try:
        resp = await client.post(downstream_url, json=payload)
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type="application/json",
        )
    except httpx.RequestError as exc:
        # Log internal network diagnostics exclusively to stderr for operators
        logger.error("Downstream MCP server unreachable at %s: %s", downstream_url, exc)
        req_id = payload.get("id")
        # Sanitize error envelope: zero internal socket / IP topology leakage to callers
        return JSONResponse(
            status_code=502,
            content=make_jsonrpc_error(
                req_id,
                -32002,
                "Gateway error: Downstream MCP service is temporarily unavailable",
            ),
        )


app = create_gateway_app()
