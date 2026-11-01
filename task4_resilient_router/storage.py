"""Task 4: On-Disk SQLite Storage for Token-Aware Sliding Window Rate Limiting."""
import asyncio
import math
import os
import time
from typing import Optional, Tuple
import aiosqlite

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "gateway_rate_limit.db"
)


class SQLiteTokenRateLimiter:
    """Token-aware sliding window rate limiter backed by persistent on-disk SQLite."""

    def __init__(
        self,
        db_path: str = DEFAULT_DB_PATH,
        max_tokens_per_minute: int = 50_000,
        window_seconds: float = 60.0,
    ):
        self.db_path = db_path
        self.max_tokens_per_minute = max_tokens_per_minute
        self.window_seconds = window_seconds
        self._lock = asyncio.Lock()
        self._initialized = False

    async def init_db(self):
        """Initialize database schema with WAL mode, busy timeout, and compound index."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
            await db.execute("PRAGMA busy_timeout = 5000;")
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS token_usage_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    tokens INTEGER NOT NULL,
                    timestamp REAL NOT NULL
                );
                """
            )
            await db.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_tenant_timestamp
                ON token_usage_events(tenant_id, timestamp);
                """
            )
            await db.commit()
        self._initialized = True

    async def check_and_record_tokens(
        self,
        tenant_id: str,
        requested_tokens: int,
        now: Optional[float] = None,
    ) -> Tuple[bool, int, float]:
        """Atomically checks and records quota in the sliding window.

        Uses SQLite BEGIN IMMEDIATE database-level write locks to guarantee
        cross-process safety across multiple worker processes / containers.
        Rejects non-positive or malformed token amounts to prevent quota manipulation.
        """
        if not isinstance(requested_tokens, int) or isinstance(requested_tokens, bool) or requested_tokens <= 0:
            raise ValueError(
                f"requested_tokens must be a strictly positive integer, received: {requested_tokens!r}"
            )

        if not tenant_id or not isinstance(tenant_id, str):
            raise ValueError(f"tenant_id must be a non-empty string, received: {tenant_id!r}")

        if now is None:
            now = time.time()

        cutoff_time = now - self.window_seconds

        if not self._initialized:
            await self.init_db()

        # In-process mutex for coroutine coordination + SQLite BEGIN IMMEDIATE for cross-process coordination
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("PRAGMA busy_timeout = 5000;")
                # Acquire database-level transaction lock across all OS processes
                await db.execute("BEGIN IMMEDIATE;")
                try:
                    # 1. State Eviction: Purge records older than sliding window
                    await db.execute(
                        "DELETE FROM token_usage_events WHERE timestamp < ?;",
                        (cutoff_time,),
                    )

                    # 2. Query total tokens consumed by this tenant within sliding window
                    cursor = await db.execute(
                        """
                        SELECT COALESCE(SUM(tokens), 0), MIN(timestamp)
                        FROM token_usage_events
                        WHERE tenant_id = ? AND timestamp >= ?;
                        """,
                        (tenant_id, cutoff_time),
                    )
                    row = await cursor.fetchone()
                    current_used = int(row[0]) if row and row[0] is not None else 0
                    oldest_event_time = float(row[1]) if row and row[1] is not None else now

                    # 3. Check quota capacity
                    if current_used + requested_tokens > self.max_tokens_per_minute:
                        # Calculate seconds until oldest transaction drops out of 60s window
                        retry_after = max(1.0, math.ceil((oldest_event_time + self.window_seconds) - now))
                        await db.commit()
                        return False, current_used, retry_after

                    # 4. Atomic token allocation
                    await db.execute(
                        """
                        INSERT INTO token_usage_events (tenant_id, tokens, timestamp)
                        VALUES (?, ?, ?);
                        """,
                        (tenant_id, requested_tokens, now),
                    )
                    await db.commit()
                    return True, current_used + requested_tokens, 0.0
                except Exception:
                    await db.rollback()
                    raise

    async def get_current_usage(self, tenant_id: str, now: Optional[float] = None) -> int:
        """Query total active token usage recorded for a tenant within the sliding window."""
        if now is None:
            now = time.time()
        cutoff_time = now - self.window_seconds

        if not self._initialized:
            await self.init_db()

        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT COALESCE(SUM(tokens), 0) FROM token_usage_events WHERE tenant_id = ? AND timestamp >= ?;",
                (tenant_id, cutoff_time),
            ) as cursor:
                row = await cursor.fetchone()
                return int(row[0]) if row else 0

    async def clear_all(self):
        """Purge all rate limit records (used in test fixtures)."""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM token_usage_events;")
                await db.commit()
