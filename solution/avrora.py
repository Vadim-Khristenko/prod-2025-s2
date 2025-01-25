from os import getenv
from redis.asyncio import Redis, ConnectionPool
from fastapi.exceptions import HTTPException
from fastapi import status
import asyncpg
from typing import Optional
import logging

tbank400 = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail={
        "status": "error",
        "message": "Ошибка в данных запроса."
    }
)

tbank401u = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={
        "status": "error",
        "message": "Пользователь не авторизован."
    }
)

tbank401a = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={
        "status": "error",
        "message": "Неверный email или пароль."
    }
)

tbank409a = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail={
        "status": "error",
        "message": "Такой email уже зарегистрирован."
    }
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

REDIS_CONFIG = {
    "host": getenv("REDIS_HOST", "localhost"),
    "port": int(getenv("REDIS_PORT", "6379")),
    "db": 0,
    "max_connections": 20,
    "decode_responses": True
}

POSTGRES_CONFIG = {
    "host": getenv("POSTGRES_HOST", "172.28.144.1"),
    "port": int(getenv("POSTGRES_PORT", "5500")),
    "user": getenv("POSTGRES_USERNAME", "tbank"),
    "password": getenv("POSTGRES_PASSWORD", "admin-19344-1023982"),
    "database": getenv("POSTGRES_DATABASE", "PROD"),
    "min_size": 10,
    "max_size": 20,
    "command_timeout": 60,
    "statement_cache_size": 1000
}

_redis_pool: Optional[ConnectionPool] = None
_pg_pool: Optional[asyncpg.Pool] = None

def get_redis_pool() -> ConnectionPool:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = ConnectionPool(**REDIS_CONFIG)
    return _redis_pool

async def get_pool() -> asyncpg.Pool:
    global _pg_pool
    if _pg_pool is None:
        _pg_pool = await asyncpg.create_pool(**POSTGRES_CONFIG)
    return _pg_pool

rc = Redis(connection_pool=get_redis_pool())

SERVER_ADDRESS = getenv("SERVER_ADDRESS", "0.0.0.0:8080")
ANTIFRAUD_ADDRESS = getenv("ANTIFRAUD_ADDRESS", "localhost:9090")
SECRET_KEY = getenv("RANDOM_SECRET", "RC_P0132013")