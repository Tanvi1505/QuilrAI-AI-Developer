"""Enterprise Data Contracts and Validation Schemas for Customer & Refund Operations.

Designed for Model Context Protocol (MCP) tool bindings with strict JSON-RPC schema generation.
Aligned with Quilr's zero-trust agentic security model:
- Explicit regex bounds prevent prompt injection / payload tampering in identifiers.
- Numeric constraints prevent negative or zero-value financial anomalies.
- Minimum length checks ensure substantive human/agent audit trails.
"""
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict, field_validator


class CustomerLookupPayload(BaseModel):
    """Schema contract for querying customer records."""
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    customer_id: str = Field(
        ...,
        pattern=r"^CUST-[A-Za-z0-9]{5}$",
        description="Enterprise customer identifier formatted strictly as CUST-XXXXX (5 alphanumeric characters).",
        examples=["CUST-10001", "CUST-AB12C"],
    )

    @field_validator("customer_id")
    @classmethod
    def validate_identifier_hygiene(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not cleaned.startswith("CUST-"):
            raise ValueError("Customer ID must start with prefix 'CUST-'")
        return cleaned


class RefundExecutionPayload(BaseModel):
    """Schema contract for initiating financial refunds via agent tool calls."""
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    customer_id: str = Field(
        ...,
        pattern=r"^CUST-[A-Za-z0-9]{5}$",
        description="Customer identifier formatted as CUST-XXXXX.",
        examples=["CUST-10001"],
    )
    amount: float = Field(
        ...,
        gt=0.0,
        le=25_000.0,  # Field engineering guardrail: Cap single automated agent refund at $25k to prevent runaway transactions
        description="Refund amount in USD (must be strictly positive, capped at $25,000 for automated agent execution).",
        examples=[49.99, 150.0],
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Detailed justification for the refund (minimum 10 characters for audit compliance).",
        examples=["Customer duplicate charge on invoice INV-88219"],
    )
    idempotency_key: Optional[str] = Field(
        default=None,
        description="Optional client-provided idempotency key to prevent duplicate refunds from agent retries.",
    )

    @field_validator("customer_id")
    @classmethod
    def standardize_customer_id(cls, value: str) -> str:
        return value.strip().upper()

    @field_validator("reason")
    @classmethod
    def validate_reason_substance(cls, value: str) -> str:
        trimmed = value.strip()
        if len(trimmed) < 10:
            raise ValueError("Refund reason must contain at least 10 non-whitespace characters for compliance audit.")
        return trimmed
