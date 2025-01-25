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

l.basicConfig(
    level=l.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = l.getLogger(__name__)

from avrora import get_pool, SERVER_ADDRESS
from cm_and_cv.auth import ura, cra


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.pool = await get_pool()

    async with app.state.pool.acquire() as conn:
        try:
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    uuid UUID PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    surname VARCHAR(120) NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    avatar_url VARCHAR(350),
                    other JSONB NOT NULL,
                    password VARCHAR(60) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT users_email_unique UNIQUE (email)
                )
            ''')
            for index_query in [
                'CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)',
                'CREATE INDEX IF NOT EXISTS idx_users_uuid ON users(uuid)'
            ]:
                try:
                    await conn.execute(index_query)
                except UniqueViolationError:
                    log.info(f"Index already exists: {index_query}")

            await conn.execute('''
                CREATE TABLE IF NOT EXISTS companies (
                    uuid UUID PRIMARY KEY,
                    name VARCHAR(50) NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    password VARCHAR(60) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                    CONSTRAINT companies_email_unique UNIQUE (email)
                )
            ''')
            for index_query in [
                'CREATE INDEX IF NOT EXISTS idx_companies_email ON companies(email)',
                'CREATE INDEX IF NOT EXISTS idx_companies_uuid ON companies(uuid)'
            ]:
                try:
                    await conn.execute(index_query)
                except UniqueViolationError:
                    log.info(f"Index already exists: {index_query}")

            log.info("Database initialized successfully")
        except Exception as e:
            log.error(f"Error initializing database: {str(e)}")
            raise

    yield

    try:
        await app.state.pool.close()
        log.info("Database connection closed")
    except Exception as e:
        log.error(f"Error closing database connection: {str(e)}")


app = FastAPI(lifespan=lifespan)
app.include_router(ura)
app.include_router(cra)


@app.get("/api/ping")
async def send():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc)}


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    log.warning(f"Validation error: {exc}")
    return JSONResponse(
        status_code=400,
        content={"status": "error", "message": "Ошибка в данных запроса."}
    )


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=SERVER_ADDRESS.split(":")[0],
        port=int(SERVER_ADDRESS.split(":")[1]),
        workers=3,
        loop="uvloop",
        http="httptools",
        limit_concurrency=100,
        backlog=4096,
        timeout_keep_alive=5
    )