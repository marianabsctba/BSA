from __future__ import annotations

import os
import threading

from psycopg_pool import ConnectionPool


_POOLS: dict[str,ConnectionPool] = {}
_LOCK=threading.Lock()


def _positive_int(name: str, default: int) -> int:
    try:
        value=int(os.getenv(name,str(default)))
    except (TypeError,ValueError):
        return default
    return value if value>0 else default


def postgres_pool(dsn: str) -> ConnectionPool:
    """Return one bounded synchronous pool per DSN for this process."""
    with _LOCK:
        existing=_POOLS.get(dsn)
        if existing is not None:
            return existing
        min_size=_positive_int("BSA_POSTGRES_POOL_MIN",1)
        max_size=max(min_size,_positive_int("BSA_POSTGRES_POOL_MAX",8))
        timeout=float(_positive_int("BSA_POSTGRES_POOL_TIMEOUT_SECONDS",10))
        pool=ConnectionPool(
            conninfo=dsn,
            min_size=min_size,
            max_size=max_size,
            timeout=timeout,
            open=True,
            name="bsa-assets",
        )
        _POOLS[dsn]=pool
        return pool


def pooled_connection(dsn: str):
    return postgres_pool(dsn).connection()


def close_postgres_pools() -> None:
    with _LOCK:
        pools=list(_POOLS.values())
        _POOLS.clear()
    for pool in pools:
        pool.close()
