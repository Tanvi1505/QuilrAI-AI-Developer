"""Production Model Context Protocol (MCP) Server with Strict Validation & STDIO Isolation.

Built for enterprise deployments at Quilr AI:
- Connects via official MCP SDK stdio transport.
- Enforces strict Pydantic schema validation, mapping bad inputs to JSON-RPC -32602 (INVALID_PARAMS).
- Guarantees STDIO isolation: stderr handles all audit logs, telemetry, and diagnostics.
- Includes automated agent guardrails: idempotency tracking, transaction limits, and audit logs.
"""
import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, Optional

from pydantic import Field, ValidationError

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS

from task1_mcp_server.schemas import CustomerLookupPayload, RefundExecutionPayload

# -----------------------------------------------------------------------------
# Zero-Trust STDIO Isolation Configuration
# -----------------------------------------------------------------------------
# In the Model Context Protocol stdio transport:
# - stdout: Strictly reserved for JSON-RPC 2.0 messages (newline-delimited).
# - stderr: Dedicated to server lifecycle logs, audit trails, and debug telemetry.
# Accidental prints or unhandled tracebacks to stdout corrupt the client's JSON parser.
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [quilr-mcp] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("quilr-mcp-server")


def emit_security_audit_event(event_type: str, details: Dict[str, Any]):
    """Emit structured JSON security audit record strictly to stderr for SIEM/governance ingestion."""
    audit_record = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "customer-support-mcp-server",
        "actor": "agentic-workflow",
        "payload": details,
    }
    sys.stderr.write(f"[SECURITY_AUDIT] {json.dumps(audit_record)}\n")
    sys.stderr.flush()


# -----------------------------------------------------------------------------
# Enterprise Mock Data Store & Persistent Idempotency Ledger
# -----------------------------------------------------------------------------
import os
import sqlite3

ENTERPRISE_CUSTOMERS: Dict[str, Dict[str, Any]] = {
    "CUST-10001": {
        "customer_id": "CUST-10001",
        "name": "Sarah Chen",
        "email": "schen@acme-cloud.io",
        "tier": "enterprise",
        "current_balance": 4850.00,
        "status": "ACTIVE",
        "account_manager": "Vidit Arora",
    },
    "CUST-20002": {
        "customer_id": "CUST-20002",
        "name": "Marcus Vance",
        "email": "m.vance@fintech-partners.com",
        "tier": "growth",
        "current_balance": 920.50,
        "status": "ACTIVE",
        "account_manager": "Field Support",
    },
    "CUST-ABCDE": {
        "customer_id": "CUST-ABCDE",
        "name": "Elena Rostova",
        "email": "elena@quantum-ai.org",
        "tier": "enterprise_plus",
        "current_balance": 12500.00,
        "status": "ACTIVE",
        "account_manager": "Dedicated TAM",
    },
}

IDEMPOTENCY_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "mcp_idempotency.db"
)


def _init_idempotency_store(db_path: str = IDEMPOTENCY_DB_PATH):
    """Ensure persistent on-disk idempotency table exists with WAL journaling."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS refund_idempotency (
                idempotency_key TEXT PRIMARY KEY,
                transaction_payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()


def get_idempotent_transaction(
    key: str, db_path: str = IDEMPOTENCY_DB_PATH
) -> Optional[Dict[str, Any]]:
    """Retrieve settled transaction record across process restarts."""
    _init_idempotency_store(db_path)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT transaction_payload FROM refund_idempotency WHERE idempotency_key = ?;",
            (key,),
        )
        row = cur.fetchone()
        if row:
            return json.loads(row[0])
    return None


def save_idempotent_transaction(
    key: str, record: Dict[str, Any], db_path: str = IDEMPOTENCY_DB_PATH
):
    """Persist transaction record to disk for durability across deployments."""
    _init_idempotency_store(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO refund_idempotency
            (idempotency_key, transaction_payload, created_at)
            VALUES (?, ?, ?);
            """,
            (key, json.dumps(record), record.get("timestamp", datetime.now(timezone.utc).isoformat())),
        )
        conn.commit()


# -----------------------------------------------------------------------------
# Custom MCP Server Subclass with JSON-RPC Protocol Error Mapping
# -----------------------------------------------------------------------------
class StrictValidationMCPServer(MCPServer):
    """MCP Server that maps Pydantic schema validation failures directly to standard

    JSON-RPC error code -32602 (INVALID_PARAMS).
    """

    async def call_tool(self, name: str, arguments: dict, context: Any = None):
        try:
            return await super().call_tool(name, arguments, context)
        except ToolError as exc:
            # Check if this tool execution failed due to Pydantic parameter validation
            if isinstance(exc.__cause__, ValidationError):
                validation_errors = exc.__cause__.errors()
                error_summaries = []
                for error in validation_errors:
                    field_path = " -> ".join(str(loc) for loc in error["loc"])
                    error_summaries.append(f"{field_path}: {error['msg']}")

                formatted_message = (
                    f"Invalid parameters for tool '{name}': "
                    + "; ".join(error_summaries)
                )

                emit_security_audit_event(
                    "TOOL_VALIDATION_FAILURE",
                    {"tool": name, "arguments": arguments, "error": formatted_message},
                )

                logger.warning(
                    "Schema rejection on tool '%s' with code %d: %s",
                    name,
                    INVALID_PARAMS,
                    formatted_message,
                )

                # Raise MCPError with official JSON-RPC -32602 code
                raise MCPError(
                    code=INVALID_PARAMS,
                    message=formatted_message,
                ) from exc

            # Re-raise unexpected internal tool errors
            raise


# Initialize the MCP Server instance
server = StrictValidationMCPServer(
    "quilr-customer-operations-server",
    version="1.0.0",
    instructions="MCP Server providing secure, validated access to customer records and financial refund workflows.",
)


# -----------------------------------------------------------------------------
# Tool 1: get_customer_record
# -----------------------------------------------------------------------------
@server.tool(
    name="get_customer_record",
    description="Retrieve verified enterprise customer profile and billing balance by customer_id (must match CUST-XXXXX).",
)
async def get_customer_record(
    customer_id: Annotated[
        str,
        Field(
            pattern=r"^CUST-[A-Za-z0-9]{5}$",
            description="Unique 10-character customer identifier formatted strictly as CUST-XXXXX.",
            examples=["CUST-10001", "CUST-ABCDE"],
        ),
    ]
) -> Dict[str, Any]:
    """Retrieve customer profile with strict schema validation and SIEM audit logging."""
    # Execute full Pydantic contract validation
    contract = CustomerLookupPayload(customer_id=customer_id)
    canonical_id = contract.customer_id

    emit_security_audit_event(
        "CUSTOMER_LOOKUP_REQUEST",
        {"customer_id": canonical_id},
    )

    record = ENTERPRISE_CUSTOMERS.get(canonical_id)
    if not record:
        logger.info("Customer lookup 404: %s not found in data store", canonical_id)
        return {
            "status": "NOT_FOUND",
            "customer_id": canonical_id,
            "message": f"Customer record '{canonical_id}' does not exist in enterprise data store.",
        }

    return {
        "status": "SUCCESS",
        "customer_id": canonical_id,
        "data": record,
    }


# -----------------------------------------------------------------------------
# Tool 2: trigger_refund
# -----------------------------------------------------------------------------
@server.tool(
    name="trigger_refund",
    description="Process an authorized financial refund. Requires valid customer_id, positive amount, and detailed reason (min 10 chars).",
)
async def trigger_refund(
    customer_id: Annotated[
        str,
        Field(
            pattern=r"^CUST-[A-Za-z0-9]{5}$",
            description="Target customer identifier formatted as CUST-XXXXX.",
            examples=["CUST-10001"],
        ),
    ],
    amount: Annotated[
        float,
        Field(
            gt=0.0,
            description="Refund amount in USD (must be strictly positive float).",
            examples=[49.99, 250.0],
        ),
    ],
    reason: Annotated[
        str,
        Field(
            min_length=10,
            description="Comprehensive business justification for refund (minimum 10 characters required for compliance audit).",
            examples=["Double billed on monthly invoice INV-90412"],
        ),
    ],
    idempotency_key: Annotated[
        Optional[str],
        Field(
            default=None,
            description="Optional unique key to ensure idempotency across agent retries.",
        ),
    ] = None,
) -> Dict[str, Any]:
    """Execute refund with financial guardrails, idempotency, and audit logging."""
    # Enforce Pydantic validation
    command = RefundExecutionPayload(
        customer_id=customer_id,
        amount=amount,
        reason=reason,
        idempotency_key=idempotency_key,
    )

    # 1. Durable Idempotency Check (Persistent across process restarts)
    if command.idempotency_key:
        prior_transaction = get_idempotent_transaction(command.idempotency_key)
        if prior_transaction:
            logger.info(
                "Idempotency hit for key '%s'. Returning existing transaction %s",
                command.idempotency_key,
                prior_transaction["refund_id"],
            )
            return {
                "status": "IDEMPOTENT_REPLAY",
                "message": "Transaction previously completed. Replaying confirmed transaction.",
                "data": prior_transaction,
            }

    # 2. Customer Existence Check
    canonical_id = command.customer_id
    customer = ENTERPRISE_CUSTOMERS.get(canonical_id)
    if not customer:
        return {
            "status": "FAILED",
            "error_code": "CUSTOMER_NOT_FOUND",
            "message": f"Cannot issue refund: Customer '{canonical_id}' does not exist.",
        }

    # 3. Financial Transaction Processing
    refund_id = f"REF-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    transaction_record = {
        "status": "PROCESSED",
        "refund_id": refund_id,
        "customer_id": canonical_id,
        "amount": round(command.amount, 2),
        "reason": command.reason,
        "timestamp": timestamp,
        "settled_currency": "USD",
        "account_manager": customer["account_manager"],
    }

    # Save to durable on-disk idempotency ledger
    if command.idempotency_key:
        save_idempotent_transaction(command.idempotency_key, transaction_record)

    # 4. Security Audit Log
    emit_security_audit_event(
        "REFUND_EXECUTED",
        {
            "refund_id": refund_id,
            "customer_id": canonical_id,
            "amount": command.amount,
            "reason": command.reason,
        },
    )

    logger.info(
        "Refund %s executed: $%.2f credited to %s",
        refund_id,
        command.amount,
        canonical_id,
    )

    return transaction_record


# -----------------------------------------------------------------------------
# Main STDIO Transport Entrypoint
# -----------------------------------------------------------------------------
def run_stdio_server():
    """Main execution entrypoint using official MCP STDIO transport."""
    logger.info("Initializing Quilr MCP Server over STDIO transport...")
    logger.info("Listening for JSON-RPC frames on stdin; transmitting via stdout.")
    logger.info("System logs and security audit stream directed to stderr.")

    try:
        asyncio.run(server.run_stdio_async())
    except (KeyboardInterrupt, SystemExit):
        logger.info("MCP Server shutdown cleanly.")
    except Exception as exc:
        logger.critical("Fatal MCP Server crash: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    run_stdio_server()
