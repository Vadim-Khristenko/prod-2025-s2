import datetime as dt
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Tuple, Union
from uuid import UUID
from argon2 import PasswordHasher
import jwt
import orjson
from asyncpg import Pool, Record
from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPBearer
from cachetools import TTLCache
import asyncio
import re

from avrora import rc, SECRET_KEY, get_pool, tbank401a, tbank409a, tbank400
from models import BasicModel, User, Company

TOKEN_CACHE = TTLCache(maxsize=20000, ttl=3600)
USER_CACHE = TTLCache(maxsize=20000, ttl=3600)
COMPANY_CACHE = TTLCache(maxsize=20000, ttl=3600)
VERIFY_CACHE = TTLCache(maxsize=20000, ttl=300)

password_hasher = PasswordHasher(
    time_cost=1,
    memory_cost=32 * 1024,
    parallelism=1
)

ura = APIRouter(prefix="/api/user/auth", tags=["user-auth"])
cra = APIRouter(prefix="/api/business/auth", tags=["company-auth"])
security = HTTPBearer()

PASSWORD_PATTERN = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')


class AuthService:

    @staticmethod
    def validate_password(password: str) -> bool:
        if not (8 <= len(password) <= 60):
            return False
        return bool(PASSWORD_PATTERN.match(password))

    @staticmethod
    async def hash_password(password: str) -> str:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, password_hasher.hash, password)

    @staticmethod
    async def verify_password(plain_password: str, hashed_password: str) -> bool:
        cache_key = f"{plain_password}:{hashed_password}"
        if cache_key in VERIFY_CACHE:
            return VERIFY_CACHE[cache_key]
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, password_hasher.verify, hashed_password, plain_password
            )
            VERIFY_CACHE[cache_key] = result
            return result
        except:
            return False

    @staticmethod
    async def generate_token(uid: UUID, email: str, subject: str) -> str:
        cache_key = f"token:{uid}:{subject}"
        if cache_key in TOKEN_CACHE:
            return TOKEN_CACHE[cache_key]

        now = datetime.now(timezone.utc)
        payload = {
            "uid": str(uid),
            "email": email,
            "type": subject,
            "exp": (now + timedelta(hours=6)).timestamp(),
            "iat": now.timestamp()
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        pipe = rc.pipeline(transaction=True)
        pipe.set(f"auth:token:{uid}", token, ex=21600)
        pipe.set(f"auth:data:{uid}",
                 orjson.dumps({"email": email, "type": subject}),
                 ex=21600)
        await pipe.execute()

        TOKEN_CACHE[cache_key] = token
        return token


class EntityService:

    @staticmethod
    async def check_existence(
            email: str,
            entity_type: str,
            pool: Pool
    ) -> Tuple[Optional[Union[User, Company]], bool]:
        cache = USER_CACHE if entity_type == "user" else COMPANY_CACHE
        if email in cache:
            return cache[email], True

        pipe = rc.pipeline(transaction=True)
        pipe.get(f"{entity_type}:data:{email}")
        pipe.get(f"{entity_type}:existence:{email}")
        cached_data, exists = await pipe.execute()

        if exists == "false":
            return None, False
        if cached_data:
            entity = (User if entity_type == "user" else Company).model_validate_json(cached_data)
            cache[email] = entity
            return entity, True

        table = "users" if entity_type == "user" else "companies"
        fields = ("uuid, name, surname, email, avatar_url, other, password"
                  if entity_type == "user" else "uuid, name, email, password")

        async with pool.acquire() as conn:
            query = f"SELECT {fields} FROM {table} WHERE email = $1"
            record = await conn.fetchrow(query, email)

            if not record:
                await rc.set(f"{entity_type}:existence:{email}", "false", ex=3600)
                return None, False

            entity = await EntityService._create_entity(entity_type, record)
            cache[email] = entity

            pipe = rc.pipeline(transaction=True)
            pipe.set(f"{entity_type}:data:{email}",
                     entity.model_dump_json(), ex=3600)
            pipe.set(f"{entity_type}:existence:{email}", "true", ex=10800)
            await pipe.execute()

            return entity, True

    @staticmethod
    async def _create_entity(entity_type: str, record: Record) -> Union[User, Company]:
        if entity_type == "user":
            return User(
                uuid=record['uuid'],
                name=record['name'],
                surname=record['surname'],
                email=record['email'],
                avatar_url=record['avatar_url'],
                other=orjson.loads(record['other']),
                password=record['password']
            )
        return Company(
            uuid=record['uuid'],
            name=record['name'],
            email=record['email'],
            password=record['password']
        )


async def verify_auth(credentials=Depends(security)) -> Dict:
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

        uid = payload["uid"]
        cache_key = f"token:{uid}"

        if uid in TOKEN_CACHE:
            return TOKEN_CACHE[uid]

        stored_token = await rc.get(f"auth:token:{uid}")
        if not stored_token or stored_token != token:
            raise tbank401a

        result = {
            "uid": uid,
            "email": payload["email"],
            "type": payload["type"]
        }
        TOKEN_CACHE[cache_key] = result
        return result
    except:
        raise tbank401a


@ura.post("/sign-up")
async def user_sign_up(user_data: User):
    if not AuthService.validate_password(user_data.password) or not user_data.avatar_url:
        raise tbank400

    pool = await get_pool()
    check_task = EntityService.check_existence(user_data.email, "user", pool)
    hash_task = AuthService.hash_password(user_data.password)

    (user, exists), hashed_pwd = await asyncio.gather(check_task, hash_task)
    if exists:
        raise tbank409a

    user_data.password = hashed_pwd

    async with pool.acquire() as conn:
        async with conn.transaction():
            insert_task = conn.execute(
                """
                INSERT INTO users (uuid, name, surname, email, 
                                 avatar_url, other, password)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                str(user_data.uuid), user_data.name, user_data.surname,
                user_data.email, user_data.avatar_url,
                user_data.other.model_dump_json(), hashed_pwd
            )
            token_task = AuthService.generate_token(
                user_data.uuid, user_data.email, "user"
            )

            _, token = await asyncio.gather(insert_task, token_task)

            asyncio.create_task(
                rc.pipeline(transaction=True)
                .set(f"user:data:{user_data.email}",
                     user_data.model_dump_json(), ex=3600)
                .set(f"user:existence:{user_data.email}", "true", ex=10800)
                .execute()
            )

            return {"token": token}


@ura.post("/sign-in")
async def user_sign_in(credentials: BasicModel):
    if not credentials.password:
        raise tbank400

    if not AuthService.validate_password(credentials.password):
        raise tbank400

    pool = await get_pool()
    user, exists = await EntityService.check_existence(
        credentials.email, "user", pool
    )

    if not exists:
        raise tbank401a
    verify_task = AuthService.verify_password(credentials.password, user.password)
    token_task = AuthService.generate_token(user.uuid, user.email, "user")

    is_valid, token = await asyncio.gather(verify_task, token_task)
    if not is_valid:
        raise tbank401a

    return {"token": token}


@cra.post("/sign-up")
async def company_sign_up(company_data: Company):
    if not AuthService.validate_password(company_data.password):
        raise tbank400

    pool = await get_pool()
    check_task = EntityService.check_existence(company_data.email, "company", pool)
    hash_task = AuthService.hash_password(company_data.password)

    (company, exists), hashed_pwd = await asyncio.gather(check_task, hash_task)
    if exists:
        raise tbank409a

    company_data.password = hashed_pwd

    async with pool.acquire() as conn:
        async with conn.transaction():
            insert_task = conn.execute(
                """
                INSERT INTO companies (uuid, name, email, password)
                VALUES ($1, $2, $3, $4)
                """,
                str(company_data.uuid), company_data.name,
                company_data.email, hashed_pwd
            )
            token_task = AuthService.generate_token(
                company_data.uuid, company_data.email, "company"
            )

            _, token = await asyncio.gather(insert_task, token_task)

            asyncio.create_task(
                rc.pipeline(transaction=True)
                .set(f"company:data:{company_data.email}",
                     company_data.model_dump_json(), ex=3600)
                .set(f"company:existence:{company_data.email}", "true", ex=10800)
                .execute()
            )

            return {"token": token, "company_id": str(company_data.uuid)}


@cra.post("/sign-in")
async def company_sign_in(credentials: BasicModel):
    if not credentials.password:
        raise tbank400

    if not AuthService.validate_password(credentials.password):
        raise tbank400

    pool = await get_pool()
    company, exists = await EntityService.check_existence(
        credentials.email, "company", pool
    )

    if not exists:
        raise tbank401a

    verify_task = AuthService.verify_password(credentials.password, company.password)
    token_task = AuthService.generate_token(company.uuid, company.email, "company")

    is_valid, token = await asyncio.gather(verify_task, token_task)
    if not is_valid:
        raise tbank401a

    return {"token": token}