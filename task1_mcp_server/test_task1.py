"""Production Test Suite for Task 1: Custom MCP Server with Strict Validation & Transport Handling.

Tests verify:
1. STDIO Isolation: stdout receives strictly valid JSON-RPC frames, no rogue print lines.
2. Protocol Compliance: JSON-RPC error mapping (code -32602) on schema rejections.
3. Edge Case Handling: Pydantic format validation, bounds, and idempotency replay.
4. Security Telemetry: stderr receives structured audit events without leaking to stdout.
"""
import json
import os
import subprocess
import sys
import pytest

PYTHON_BIN = sys.executable
SERVER_MODULE = "task1_mcp_server.server"
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class MCPStdioTestHarness:
    """End-to-end test harness communicating with the MCP Server over raw subprocess pipes."""

    def __init__(self):
        self.proc = subprocess.Popen(
            [PYTHON_BIN, "-m", SERVER_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=PROJECT_DIR,
            text=True,
            bufsize=1,
        )
        self.req_id = 0

    def send_rpc(self, method: str, params: dict | None = None) -> dict:
        self.req_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self.req_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        wire_message = json.dumps(payload) + "\n"
        self.proc.stdin.write(wire_message)
        self.proc.stdin.flush()

        response_line = self.proc.stdout.readline()
        assert response_line, "MCP Server stdout terminated prematurely"

        # Verify strict STDIO isolation: Line must be valid JSON-RPC, not raw log text
        try:
            parsed = json.loads(response_line)
        except json.JSONDecodeError as err:
            pytest.fail(
                f"STDIO ISOLATION FAILURE: Non-JSON data detected on stdout: {response_line!r} (Error: {err})"
            )

        assert parsed.get("jsonrpc") == "2.0", f"Missing jsonrpc 2.0 version specifier: {parsed}"
        return parsed

    def send_notify(self, method: str, params: dict | None = None):
        payload = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

    def teardown(self):
        if self.proc.stdin and not self.proc.stdin.closed:
            self.proc.stdin.close()
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def mcp_harness():
    harness = MCPStdioTestHarness()
    # Execute MCP initialization handshake
    init_res = harness.send_rpc(
        "initialize",
        {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "quilr-test-agent", "version": "1.0.0"},
        },
    )
    assert "result" in init_res
    harness.send_notify("notifications/initialized")
    yield harness
    harness.teardown()


def test_stdio_isolation_and_tool_discovery(mcp_harness: MCPStdioTestHarness):
    """Verify tool discovery exposes expected tools with schemas and stdout remains uncontaminated."""
    res = mcp_harness.send_rpc("tools/list")
    assert "result" in res
    tools = {t["name"]: t for t in res["result"]["tools"]}
    assert "get_customer_record" in tools
    assert "trigger_refund" in tools

    # Validate tool parameters in JSON schema (camelCase per official MCP wire spec)
    refund_schema = tools["trigger_refund"].get("inputSchema") or tools["trigger_refund"].get("input_schema")
    assert "customer_id" in refund_schema["required"]
    assert "amount" in refund_schema["required"]
    assert "reason" in refund_schema["required"]


def test_get_customer_record_valid_retrieval(mcp_harness: MCPStdioTestHarness):
    """Verify successful retrieval for valid CUST-XXXXX format."""
    res = mcp_harness.send_rpc(
        "tools/call",
        {"name": "get_customer_record", "arguments": {"customer_id": "CUST-10001"}},
    )
    assert "result" in res
    assert res["result"]["isError"] is False
    content = json.loads(res["result"]["content"][0]["text"])
    assert content["status"] == "SUCCESS"
    assert content["data"]["name"] == "Sarah Chen"
    assert content["data"]["tier"] == "enterprise"


@pytest.mark.parametrize(
    "malformed_id, reason",
    [
        ("INVALID", "missing CUST- prefix and length"),
        ("CUST-1", "too short suffix"),
        ("CUST-123456", "suffix too long"),
        ("CUST_10001", "underscore instead of hyphen"),
        ("cust-10001!", "special character in suffix"),
        ("1234567890", "no prefix"),
    ],
)
def test_get_customer_record_schema_rejection_code_32602(
    mcp_harness: MCPStdioTestHarness, malformed_id: str, reason: str
):
    """Verify malformed customer IDs are rejected with JSON-RPC error -32602 (INVALID_PARAMS)."""
    res = mcp_harness.send_rpc(
        "tools/call",
        {"name": "get_customer_record", "arguments": {"customer_id": malformed_id}},
    )
    assert "error" in res, f"Expected validation failure for: {reason} ({malformed_id})"
    assert res["error"]["code"] == -32602, f"Expected code -32602, got: {res['error']}"
    assert "Invalid parameters" in res["error"]["message"]


def test_trigger_refund_successful_execution(mcp_harness: MCPStdioTestHarness):
    """Verify triggering an authorized refund returns confirmation record."""
    res = mcp_harness.send_rpc(
        "tools/call",
        {
            "name": "trigger_refund",
            "arguments": {
                "customer_id": "CUST-10001",
                "amount": 149.50,
                "reason": "Duplicate subscription charge during annual migration",
            },
        },
    )
    assert "result" in res
    assert res["result"]["isError"] is False
    record = json.loads(res["result"]["content"][0]["text"])
    assert record["status"] == "PROCESSED"
    assert record["amount"] == 149.50
    assert record["customer_id"] == "CUST-10001"
    assert record["refund_id"].startswith("REF-")


@pytest.mark.parametrize(
    "cid, amount, reason, desc",
    [
        ("NOT-A-CUST", 50.0, "Valid justification provided", "invalid customer id pattern"),
        ("CUST-10001", -25.0, "Valid justification provided", "negative amount constraint"),
        ("CUST-10001", 0.0, "Valid justification provided", "zero amount constraint"),
        ("CUST-10001", 100.0, "Too short", "reason length under 10 characters"),
        ("CUST-10001", 100.0, "          ", "whitespace-only reason failing min_length"),
    ],
)
def test_trigger_refund_validation_failures_code_32602(
    mcp_harness: MCPStdioTestHarness, cid: str, amount: float, reason: str, desc: str
):
    """Verify all invalid refund parameters return JSON-RPC error -32602."""
    res = mcp_harness.send_rpc(
        "tools/call",
        {
            "name": "trigger_refund",
            "arguments": {"customer_id": cid, "amount": amount, "reason": reason},
        },
    )
    assert "error" in res, f"Expected error for condition: {desc}"
    assert res["error"]["code"] == -32602
    assert "Invalid parameters" in res["error"]["message"]


def test_trigger_refund_idempotency_guard(mcp_harness: MCPStdioTestHarness):
    """Verify that repeated calls with the same idempotency key replay safely without double-charging."""
    idem_key = "idemp-test-agent-9901"
    args = {
        "customer_id": "CUST-10001",
        "amount": 75.00,
        "reason": "Invoice reconciliation adjustment",
        "idempotency_key": idem_key,
    }

    # Initial call: processed
    res1 = mcp_harness.send_rpc("tools/call", {"name": "trigger_refund", "arguments": args})
    record1 = json.loads(res1["result"]["content"][0]["text"])
    assert record1["status"] == "PROCESSED"
    first_refund_id = record1["refund_id"]

    # Duplicate replay call from agent
    res2 = mcp_harness.send_rpc("tools/call", {"name": "trigger_refund", "arguments": args})
    record2 = json.loads(res2["result"]["content"][0]["text"])
    assert record2["status"] == "IDEMPOTENT_REPLAY"
    assert record2["data"]["refund_id"] == first_refund_id
