import os
from datetime import datetime, timezone
from contextlib import asynccontextmanager
import logging as l
import uvicorn
from asyncpg import UniqueViolationError
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
import asyncio
import orjson

WORKERS = 3

l.basicConfig(level=l.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
              handlers=[l.StreamHandler(), l.FileHandler('app.log', mode='a')])
log = l.getLogger(__name__)

from avrora import get_pool, SERVER_ADDRESS, rc
from cm_and_cv.auth import ura, cra, AuthService, EntityService
from cm_and_cv.profile import upr
from cm_and_cv.promo import promo_router


async def init_db(conn):
    await conn.execute('''CREATE TABLE IF NOT EXISTS users (
        uuid UUID PRIMARY KEY,name VARCHAR(100) NOT NULL,
        surname VARCHAR(120) NOT NULL,email VARCHAR(120) NOT NULL,
        avatar_url VARCHAR(350),other JSONB NOT NULL,
        password VARCHAR(128) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT users_email_unique UNIQUE (email)) WITH (fillfactor = 90)''')

    await conn.execute('''CREATE TABLE IF NOT EXISTS companies (
        uuid UUID PRIMARY KEY,name VARCHAR(50) NOT NULL,
        email VARCHAR(120) NOT NULL,password VARCHAR(128) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT companies_email_unique UNIQUE (email)) WITH (fillfactor = 90)''')

    indexes = [
        'CREATE INDEX IF NOT EXISTS idx_users_email_hash ON users USING hash (email)',
        'CREATE INDEX IF NOT EXISTS idx_users_uuid_hash ON users USING hash (uuid)',
        'CREATE INDEX IF NOT EXISTS idx_users_auth ON users (email, password) INCLUDE (uuid)',
        'CREATE INDEX IF NOT EXISTS idx_companies_email_hash ON companies USING hash (email)',
        'CREATE INDEX IF NOT EXISTS idx_companies_uuid_hash ON companies USING hash (uuid)',
        'CREATE INDEX IF NOT EXISTS idx_companies_auth ON companies (email, password) INCLUDE (uuid)'
    ]
    for idx in indexes:
        try:
            await conn.execute(idx)
        except UniqueViolationError:
            pass


async def init_db_optimizations(conn):
    optimizations = [
        "ALTER TABLE users SET (autovacuum_vacuum_scale_factor = 0.05)",
        "ALTER TABLE companies SET (autovacuum_vacuum_scale_factor = 0.05)",
        "ALTER TABLE users SET (parallel_workers = 4)",
        "ALTER TABLE companies SET (parallel_workers = 4)"
    ]
    for opt in optimizations:
        try:
            await conn.execute(opt)
        except Exception as e:
            log.warning(f"Optimization failed: {e}")


async def prepare_statements(conn):
    stmts = [
        "SELECT uuid, name, surname, email, avatar_url, other, password FROM users WHERE email = $1",
        "SELECT uuid, email FROM users WHERE email = $1 AND password = $2",
        "SELECT uuid, name, email, password FROM companies WHERE email = $1",
        "SELECT uuid, email FROM companies WHERE email = $1 AND password = $2",
        "SELECT uuid, name, surname, email, avatar_url, other, password FROM users WHERE email = $1",
        "SELECT uuid, name, email, password FROM companies WHERE email = $1",
        "INSERT INTO users (uuid, name, surname, email, avatar_url, other, password) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        "INSERT INTO companies (uuid, name, email, password) VALUES ($1, $2, $3, $4)"
    ]
    for stmt in stmts: await conn.prepare(stmt)


async def warmup_services(pool):
    async with pool.acquire() as conn:
        await conn.fetch("SELECT uuid, email FROM users LIMIT 10")
        await conn.fetch("SELECT uuid, email FROM companies LIMIT 10")

    try:
        await rc.ping()
        config = {'maxmemory-policy': 'allkeys-lru', 'lazyfree-lazy-eviction': 'yes',
                  'lazyfree-lazy-expire': 'yes', 'lazyfree-lazy-server-del': 'yes'}
        pipe = rc.pipeline(transaction=True)
        for k, v in config.items(): pipe.config_set(k, v)
        await pipe.execute()

        test_pwd = "Test123!@#"
        hashed = await AuthService.hash_password(test_pwd)
        await AuthService.verify_password(test_pwd, hashed)
        AuthService.validate_password(test_pwd)
    except Exception as e:
        log.error(f"Warmup failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await get_pool()
    async with app.state.pool.acquire() as conn:
        try:
            await init_db(conn)
            await init_db_optimizations(conn)
            await prepare_statements(conn)
            await warmup_services(app.state.pool)
            log.info("System initialized and warmed up")
        except Exception as e:
            log.error(f"Init error: {str(e)}")
            raise
    yield
    await app.state.pool.close()


app = FastAPI(lifespan=lifespan, default_response_class=JSONResponse,
              docs_url='/api/docs' if os.getenv("BT") else None,
              redoc_url='/api/redoc' if os.getenv("BT") else None)

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"], max_age=3600)

app.include_router(ura)
app.include_router(cra)
app.include_router(upr)
app.include_router(promo_router)


@app.get("/api/ping")
async def send(): return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"status": "error", "message": "Ошибка в данных запроса."})


if __name__ == "__main__":
    host, port = SERVER_ADDRESS.split(":")
    uvicorn.run("main:app", host=host, port=int(port), workers=WORKERS, loop="uvloop",
                http="httptools", limit_concurrency=1000, backlog=4096, timeout_keep_alive=5)