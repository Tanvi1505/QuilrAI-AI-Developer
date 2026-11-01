#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "🚀 Running AI Field Developer / Solutions Engineer Assessment Suite"
echo "======================================================================"

if [ -d ".venv" ]; then
    PYTHON_EXEC=".venv/bin/python"
    PYTEST_EXEC=".venv/bin/pytest"
else
    PYTHON_EXEC="python3"
    PYTEST_EXEC="pytest"
fi

echo "Using Python: $($PYTHON_EXEC --version)"
echo "Using Pytest: $($PYTEST_EXEC --version)"
echo ""

echo "▶ Task 1: Custom MCP Server (Validation & STDIO Transport)"
$PYTEST_EXEC task1_mcp_server/test_task1.py -v --tb=short

echo ""
echo "▶ Task 2: MCP Security Gateway Proxy (Tool Filtering & Auth)"
$PYTEST_EXEC task2_security_gateway/test_task2.py -v --tb=short

echo ""
echo "▶ Task 3: LLM Gateway Streaming Guardrail (PII Redaction)"
$PYTEST_EXEC task3_streaming_guardrail/test_task3.py -v --tb=short

echo ""
echo "▶ Task 4: Rate-Limiting & Model Fallback Router (SQLite Sliding Window)"
$PYTEST_EXEC task4_resilient_router/test_task4.py -v --tb=short

echo ""
echo "======================================================================"
echo "✅ ALL 4 ASSESSMENT TASKS PASSED WITH FULL SPECIFICATION COMPLIANCE"
echo "======================================================================"
