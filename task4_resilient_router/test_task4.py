"""Comprehensive test suite for Task 4: Rate Limiting & Model Fallback Router."""
import asyncio
import os
import tempfile
import time
import httpx
import pytest
from httpx import ASGITransport, AsyncClient

from task4_resilient_router.mock_providers import primary_app, backup_app, state as provider_state
from task4_resilient_router.proxy_server import create_gateway_app
from task4_resilient_router.router import ResilientModelRouter
from task4_resilient_router.storage import SQLiteTokenRateLimiter


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        os.remove(path)


# ----------------------------------------------------------------------
# 1. Tests for SQLite Token-Aware Sliding Window Rate Limiter
# ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sqlite_token_limiter_basic_and_overflow(temp_db):
    """Verify rate limiter allows tokens under 50,000 and rejects when limit exceeded."""
    limiter = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=50_000, window_seconds=60.0)
    await limiter.init_db()

    # 1. First batch: 30,000 tokens -> allowed
    ok, used, retry = await limiter.check_and_record_tokens("tenant_1", 30_000)
    assert ok is True
    assert used == 30_000
    assert retry == 0.0

    # 2. Second batch: 15,000 tokens -> allowed (total 45,000)
    ok, used, retry = await limiter.check_and_record_tokens("tenant_1", 15_000)
    assert ok is True
    assert used == 45_000

    # 3. Third batch: 10,000 tokens -> exceeds 50,000 (45k + 10k = 55k) -> rejected!
    ok, used, retry = await limiter.check_and_record_tokens("tenant_1", 10_000)
    assert ok is False
    assert used == 45_000
    assert retry > 0.0


@pytest.mark.asyncio
async def test_sqlite_token_limiter_tenant_isolation(temp_db):
    """Verify that quota limits are partitioned per tenant API key."""
    limiter = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=50_000)
    await limiter.init_db()

    # Tenant A consumes maximum capacity
    ok_a, _, _ = await limiter.check_and_record_tokens("tenant_a", 50_000)
    assert ok_a is True

    # Tenant A is now blocked
    blocked_a, _, _ = await limiter.check_and_record_tokens("tenant_a", 100)
    assert blocked_a is False

    # Tenant B has full capacity available
    ok_b, used_b, _ = await limiter.check_and_record_tokens("tenant_b", 40_000)
    assert ok_b is True
    assert used_b == 40_000


@pytest.mark.asyncio
async def test_sliding_window_state_eviction_over_time(temp_db):
    """Verify that records older than 60s are evicted, restoring token capacity."""
    limiter = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=50_000, window_seconds=60.0)
    await limiter.init_db()

    t0 = 1000.0
    # At t0, consume 40,000 tokens
    ok, used, _ = await limiter.check_and_record_tokens("tenant_x", 40_000, now=t0)
    assert ok is True

    # At t0 + 30s, try consuming 20,000 tokens -> rejected (total 60k > 50k)
    ok, _, _ = await limiter.check_and_record_tokens("tenant_x", 20_000, now=t0 + 30.0)
    assert ok is False

    # At t0 + 61s, original 40,000 tokens are outside 60s window and evicted -> allowed!
    ok, used, _ = await limiter.check_and_record_tokens("tenant_x", 20_000, now=t0 + 61.0)
    assert ok is True
    assert used == 20_000


@pytest.mark.asyncio
async def test_concurrent_token_allocation_race_condition(temp_db):
    """Verify atomic SQLite locking prevents race conditions under parallel requests."""
    limiter = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=50_000)
    await limiter.init_db()

    # Launch 20 concurrent requests each attempting to consume 3,000 tokens (total attempted = 60,000)
    async def try_consume():
        allowed, _, _ = await limiter.check_and_record_tokens("tenant_race", 3_000)
        return allowed

    results = await asyncio.gather(*[try_consume() for _ in range(20)])
    allowed_count = sum(1 for r in results if r is True)
    # 50,000 / 3,000 = exactly 16 requests allowed (16 * 3000 = 48,000; 17th would be 51,000)
    assert allowed_count == 16
    assert results.count(False) == 4


@pytest.mark.asyncio
async def test_cross_process_sqlite_locking_simulation(temp_db):
    """Verify that multiple independent rate-limiter instances (simulating separate OS worker processes)

    coordinate atomically via SQLite BEGIN IMMEDIATE database-level file locks.
    """
    # Create 3 distinct limiter instances simulating 3 different server workers
    limiter_proc1 = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=20_000)
    limiter_proc2 = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=20_000)
    limiter_proc3 = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=20_000)
    await limiter_proc1.init_db()

    limiters = [limiter_proc1, limiter_proc2, limiter_proc3]

    # Concurrently fire 10 requests of 3,000 tokens distributed across the 3 independent limiter instances
    async def worker_request(i: int):
        target_limiter = limiters[i % 3]
        allowed, _, _ = await target_limiter.check_and_record_tokens("multi_worker_tenant", 3_000)
        return allowed

    results = await asyncio.gather(*[worker_request(i) for i in range(10)])
    allowed_count = sum(1 for r in results if r is True)
    # Total limit 20,000 / 3,000 = exactly 6 allowed (6 * 3000 = 18,000; 7th = 21,000)
    assert allowed_count == 6
    assert results.count(False) == 4


# ----------------------------------------------------------------------
# 2. Tests for Resilient Model Routing & Fallback Mechanics
# ----------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_mock_provider_state():
    provider_state.simulate_429 = False
    provider_state.simulate_timeout_delay_ms = 0.0
    provider_state.simulate_500 = False
    provider_state.call_count = 0


@pytest.mark.asyncio
async def test_router_normal_primary_success():
    """Verify router successfully calls primary model when healthy."""
    primary_transport = ASGITransport(app=primary_app)
    backup_transport = ASGITransport(app=backup_app)

    async with AsyncClient(transport=primary_transport, base_url="http://primary") as p_client, \
               AsyncClient(transport=backup_transport, base_url="http://backup") as b_client:

        router = ResilientModelRouter(
            primary_url="http://primary/v1/completions",
            secondary_url="http://backup/v1/completions",
            primary_timeout=3.0,
            http_client=p_client,
        )
        status, data = await router.route_completion({"prompt": "Hello primary"})
        assert status == 200
        assert data["provider"] == "primary-model-provider"


@pytest.mark.asyncio
async def test_router_fallback_on_primary_429_too_many_requests():
    """Verify router automatically fails over to backup provider when primary returns 429."""
    provider_state.simulate_429 = True

    primary_transport = ASGITransport(app=primary_app)
    backup_transport = ASGITransport(app=backup_app)

    async def mock_post(url, json, timeout=None):
        if "primary" in str(url):
            async with AsyncClient(transport=primary_transport, base_url="http://primary") as client:
                return await client.post("/v1/completions", json=json)
        else:
            async with AsyncClient(transport=backup_transport, base_url="http://backup") as client:
                return await client.post("/v1/completions", json=json)

    router = ResilientModelRouter(
        primary_url="http://primary/v1/completions",
        secondary_url="http://backup/v1/completions",
        primary_timeout=3.0,
    )
    router.http_client.post = mock_post

    status, data = await router.route_completion({"prompt": "Testing 429 failover"})
    assert status == 200
    assert data["provider"] == "secondary-backup-provider"
    assert data["_gateway_metadata"]["routed_provider"] == "secondary_backup"
    assert "429" in data["_gateway_metadata"]["failover_reason"]


@pytest.mark.asyncio
async def test_router_fallback_on_primary_timeout_after_3000ms():
    """Verify router times out after 3000ms and fails over to secondary backup."""
    # Configure primary timeout of 0.1s in test router to simulate timeout without sleeping full 3s
    router = ResilientModelRouter(
        primary_url="http://primary/v1/completions",
        secondary_url="http://backup/v1/completions",
        primary_timeout=0.1,  # Simulation of 3000ms limit
    )

    async def mock_slow_primary_post(url, json, timeout=None):
        if "primary" in str(url):
            await asyncio.sleep(0.3)  # Exceeds 0.1s timeout
            raise httpx.ReadTimeout("Request timed out")
        else:
            return httpx.Response(
                200,
                json={"provider": "secondary-backup-provider", "choices": [{"text": "Backup answered"}]},
            )

    router.http_client.post = mock_slow_primary_post

    status, data = await router.route_completion({"prompt": "Testing timeout failover"})
    assert status == 200
    assert data["provider"] == "secondary-backup-provider"
    assert "timed out" in data["_gateway_metadata"]["failover_reason"]


@pytest.mark.asyncio
async def test_standardized_sanitized_error_payload_on_dual_failure():
    """Verify that when both providers fail, gateway returns sanitized envelope without leaking stack traces."""
    router = ResilientModelRouter(
        primary_url="http://primary/v1/completions",
        secondary_url="http://backup/v1/completions",
        primary_timeout=0.1,
    )

    async def mock_dual_fail(url, json, timeout=None):
        raise ConnectionRefusedError("Internal socket connection refused to 10.0.12.44:5432")

    router.http_client.post = mock_dual_fail

    status, data = await router.route_completion({"prompt": "Fail both"}, request_id="req-test-sanitize-01")
    assert status == 502
    assert "error" in data
    assert data["error"]["code"] == "GATEWAY_UPSTREAM_UNAVAILABLE"
    assert data["error"]["status"] == 502
    assert data["error"]["request_id"] == "req-test-sanitize-01"

    # CRITICAL: Verify NO internal stack traces or IP addresses leaked
    raw_str = str(data)
    assert "Traceback" not in raw_str
    assert "10.0.12.44" not in raw_str
    assert "socket" not in raw_str


# ----------------------------------------------------------------------
# 3. Security Tests: Rate-Limit Bypass Prevention & Tenant Authentication
# ----------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rate_limiter_rejects_negative_and_malformed_tokens(temp_db):
    """Verify rate limiter throws ValueError on negative, boolean, or malformed token amounts."""
    limiter = SQLiteTokenRateLimiter(db_path=temp_db, max_tokens_per_minute=50_000)
    await limiter.init_db()

    with pytest.raises(ValueError, match="strictly positive integer"):
        await limiter.check_and_record_tokens("tenant_1", -1000)

    with pytest.raises(ValueError, match="strictly positive integer"):
        await limiter.check_and_record_tokens("tenant_1", 0)

    with pytest.raises(ValueError, match="strictly positive integer"):
        await limiter.check_and_record_tokens("tenant_1", True)  # bool is subclass of int

    with pytest.raises(ValueError, match="non-empty string"):
        await limiter.check_and_record_tokens("", 100)


@pytest.mark.asyncio
async def test_proxy_endpoint_rejects_unauthenticated_tenant(temp_db):
    """Verify proxy endpoint requires valid tenant credentials and rejects unauthenticated callers with 401."""
    app = create_gateway_app(db_path=temp_db)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Missing Authorization header
        res1 = await client.post("/v1/completions", json={"prompt": "hello"})
        assert res1.status_code == 401
        data1 = res1.json()
        assert data1["error"]["code"] == "UNAUTHORIZED_TENANT"

        # 2. Invalid Bearer token
        res2 = await client.post(
            "/v1/completions",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer totally_unregistered_invalid_token"},
        )
        assert res2.status_code == 401
        data2 = res2.json()
        assert data2["error"]["code"] == "UNAUTHORIZED_TENANT"

        # 3. Arbitrary prefix token (tenant_xyz or key_abc) without registry registration must be rejected
        res3 = await client.post(
            "/v1/completions",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer tenant_arbitrary_unregistered"},
        )
        assert res3.status_code == 401
        assert res3.json()["error"]["code"] == "UNAUTHORIZED_TENANT"

        res4 = await client.post(
            "/v1/completions",
            json={"prompt": "hello"},
            headers={"Authorization": "Bearer key_unregistered"},
        )
        assert res4.status_code == 401
        assert res4.json()["error"]["code"] == "UNAUTHORIZED_TENANT"


@pytest.mark.asyncio
async def test_proxy_endpoint_dependency_injection_tenant_credentials(temp_db):
    """Verify custom tenant credentials registry can be injected for isolated test environments."""
    custom_registry = {"custom_test_secret_99": "injected_test_tenant"}
    app = create_gateway_app(db_path=temp_db, tenant_credentials=custom_registry)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Injected credential succeeds
        res = await client.post(
            "/v1/completions",
            json={"prompt": "test prompt", "max_tokens": 10},
            headers={"Authorization": "Bearer custom_test_secret_99"},
        )
        assert res.status_code in (200, 502)

        # Standard credential not in custom registry is rejected
        res_other = await client.post(
            "/v1/completions",
            json={"prompt": "test prompt"},
            headers={"Authorization": "Bearer live_key_tenant_alpha_921"},
        )
        assert res_other.status_code == 401


@pytest.mark.asyncio
async def test_proxy_endpoint_rejects_negative_and_boolean_requested_tokens(temp_db):
    """Verify proxy returns 400 Bad Request when caller attempts quota bypass via negative tokens."""
    app = create_gateway_app(db_path=temp_db)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        auth_headers = {"Authorization": "Bearer live_key_tenant_alpha_921"}

        # Attempt quota deduction bypass with negative requested_tokens
        res_neg = await client.post(
            "/v1/completions",
            json={"prompt": "hello", "requested_tokens": -10000},
            headers=auth_headers,
        )
        assert res_neg.status_code == 400
        data_neg = res_neg.json()
        assert data_neg["error"]["code"] == "INVALID_REQUESTED_TOKENS"

        # Attempt quota bypass with boolean requested_tokens
        res_bool = await client.post(
            "/v1/completions",
            json={"prompt": "hello", "requested_tokens": True},
            headers=auth_headers,
        )
        assert res_bool.status_code == 400
        data_bool = res_bool.json()
        assert data_bool["error"]["code"] == "INVALID_REQUESTED_TOKENS"


@pytest.mark.asyncio
async def test_proxy_endpoint_rejects_invalid_max_tokens(temp_db):
    """Verify proxy validates max_tokens parameter to be a positive integer."""
    app = create_gateway_app(db_path=temp_db)
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        auth_headers = {"Authorization": "Bearer live_key_tenant_alpha_921"}

        res = await client.post(
            "/v1/completions",
            json={"prompt": "hello", "max_tokens": -50},
            headers=auth_headers,
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "INVALID_MAX_TOKENS"


@pytest.mark.asyncio
async def test_proxy_endpoint_authenticates_tenant_and_clamps_token_floor(temp_db):
    """Verify valid tenant credential succeeds and requested_tokens accounts for permitted maximum output."""
    app = create_gateway_app(db_path=temp_db)
    transport = ASGITransport(app=app)

    # Mock router response to avoid real external calls
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Prompt length = 400 chars -> estimated prompt tokens = 100
        # max_tokens defaults to 256
        # Expected reservation: prompt (100) + max_tokens (256) = 356
        # Client requests only 2 tokens, attempting to under-report
        res = await client.post(
            "/v1/completions",
            json={"prompt": "x" * 400, "requested_tokens": 2, "max_tokens": 256},
            headers={"Authorization": "Bearer live_key_tenant_alpha_921"},
        )
        # Should succeed (or reach router)
        assert res.status_code in (200, 502)
        # Verify in database that reservation accounted for permitted maximum output
        limiter = SQLiteTokenRateLimiter(db_path=temp_db)
        usage = await limiter.get_current_usage("tenant_1")
        assert usage >= 356, f"Expected usage to account for permitted maximum output (>= 356), got {usage}"


@pytest.mark.asyncio
async def test_proxy_endpoint_rejects_malformed_request_shapes(temp_db):
    """Verify endpoint rejects JSON arrays, null, numeric prompts, and missing prompt fields with HTTP 400."""
    app = create_gateway_app(db_path=temp_db)
    transport = ASGITransport(app=app)
    auth_header = {"Authorization": "Bearer live_key_tenant_alpha_921"}

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Case 1: JSON array payload
        res_arr = await client.post("/v1/completions", json=[{"prompt": "hello"}], headers=auth_header)
        assert res_arr.status_code == 400
        assert res_arr.json()["error"]["code"] == "INVALID_REQUEST_SHAPE"

        # Case 2: JSON null / primitive payload
        res_null = await client.post(
            "/v1/completions",
            content=b"null",
            headers={**auth_header, "content-type": "application/json"},
        )
        assert res_null.status_code == 400
        assert res_null.json()["error"]["code"] == "INVALID_REQUEST_SHAPE"

        # Case 3: Missing 'prompt' field
        res_missing = await client.post(
            "/v1/completions",
            json={"max_tokens": 128},
            headers=auth_header,
        )
        assert res_missing.status_code == 400
        assert res_missing.json()["error"]["code"] == "MISSING_REQUIRED_FIELD"

        # Case 4: Numeric 'prompt'
        res_num = await client.post(
            "/v1/completions",
            json={"prompt": 98765},
            headers=auth_header,
        )
        assert res_num.status_code == 400
        assert res_num.json()["error"]["code"] == "INVALID_PROMPT"

        # Case 5: Whitespace-only 'prompt'
        res_blank = await client.post(
            "/v1/completions",
            json={"prompt": "    \t\n  "},
            headers=auth_header,
        )
        assert res_blank.status_code == 400
        assert res_blank.json()["error"]["code"] == "INVALID_PROMPT"

