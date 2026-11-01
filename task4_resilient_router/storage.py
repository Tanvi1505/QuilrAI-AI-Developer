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

    async def init_db(self):
        """Initialize database schema with WAL mode and compound index."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL;")
            await db.execute("PRAGMA synchronous=NORMAL;")
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

    async def check_and_record_tokens(
        self,
        tenant_id: str,
        requested_tokens: int,
        now: Optional[float] = None,
    ) -> Tuple[bool, int, float]:
        """Atomically checks if tenant has sufficient token quota in the sliding window.

        Args:
            tenant_id: Unique identifier for the tenant / API key.
            requested_tokens: Number of tokens to consume for this request.
            now: Optional timestamp override for deterministic testing.

        Returns:
            Tuple of:
                - allowed (bool): True if allowed, False if rate limited
                - current_tokens_used (int): Tokens used in current window
                - retry_after_seconds (float): Seconds until quota becomes available (0 if allowed)
        """
        if now is None:
            now = time.time()

        cutoff_time = now - self.window_seconds

        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
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

    async def clear_all(self):
        """Purge all rate limit records (used in test fixtures)."""
        async with self._lock:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("DELETE FROM token_usage_events;")
                await db.commit()
