import datetime as dt
import re
from datetime import datetime, timezone, timedelta
import logging as l
from hmac import compare_digest
from typing import Optional, Dict
from uuid import UUID
from argon2 import PasswordHasher
import hmac, hashlib, jwt, ujson
from asyncpg import Pool
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from avrora import rc, SECRET_KEY, get_pool, tbank401a, tbank409a, tbank400
from cm_and_cv.auth_models import BasicModel, User, Company
from functools import lru_cache
from cachetools import TTLCache

l.basicConfig(level=l.INFO)
log = l.getLogger(__name__)
security = HTTPBearer()

ura = APIRouter(prefix="/api/user/auth", tags=["user-auth"])
cra = APIRouter(prefix="/api/business/auth", tags=["company-auth"])

password_hasher = PasswordHasher()
token_cache = TTLCache(maxsize=1000, ttl=3600)

async def hash_password(password: str) -> str:
    return password_hasher.hash(password)

async def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return password_hasher.verify(hashed_password, plain_password)
    except Exception:
        return False


async def generate_jwt_token(uid: UUID, subject: str, token_type: Optional[str] = None) -> str:
    now = datetime.now(timezone.utc)
    exp_time = now + timedelta(hours=6)

    payload = {
        "uid": str(uid),
        "type": token_type,
        "exp": exp_time.timestamp(),
        "subject": subject,
        "iat": now.timestamp()
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    async with rc.pipeline(transaction=True) as pipe:
        pipe.set(f"auth:token:{uid}", token, ex=int((exp_time - now).total_seconds()))
        await pipe.execute()

    token_cache[str(uid)] = {
        "ok": True,
        "uid": str(uid),
        "type": token_type,
        "token": token
    }

    return token


async def verify_jwt_token(token: str) -> Dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        uid = payload["uid"]
        if uid in token_cache:
            cached_data = token_cache[uid]
            if compare_digest(cached_data["token"], token):
                return {
                    "ok": True,
                    "uid": uid,
                    "type": cached_data["type"]
                }
        stored_token = await rc.get(f"auth:token:{uid}")

        if not stored_token or compare_digest(stored_token, token) is False:
            raise tbank401a

        token_cache[uid] = {
            "ok": True,
            "uid": uid,
            "type": payload.get("type"),
            "token": token
        }
        return {
            "ok": True,
            "uid": uid,
            "type": payload.get("type")
        }

    except jwt.ExpiredSignatureError:
        raise tbank401a
    except jwt.InvalidTokenError:
        raise tbank401a


async def get_user_by_email(email: str, pool: Pool) -> Optional[User]:
    if await rc.get(f"user:existence:{email}") == "false":
        return None
    cache_key = f"user:data:{email}"
    cached_user = await rc.get(cache_key)

    if cached_user:
        await rc.set(f"user:existence:{email}", "true", ex=dt.timedelta(hours=3))
        return User.model_validate_json(cached_user)

    async with pool.acquire() as conn:
        user_data = await conn.fetchrow(
            """
            SELECT * FROM users 
            WHERE email = $1
            """,
            email
        )
        if user_data:
            await rc.set(f"user:existence:{email}", "true", ex=dt.timedelta(hours=3))
            other_dict = ujson.loads(user_data['other'])

            user_data = {
                "uuid": user_data['uuid'],
                "name": user_data['name'],
                "surname": user_data['surname'],
                "email": user_data['email'],
                "avatar_url": user_data['avatar_url'],
                "other": other_dict,
                "password": user_data['password']
            }
            user = User(**user_data)
            await rc.set(
                cache_key,
                user.model_dump_json(),
                ex=dt.timedelta(hours=1)
            )
            return user
    await rc.set(f"user:existence:{email}", "false", ex=dt.timedelta(hours=3))
    return None


async def get_company_by_email(email: str, pool: Pool) -> Optional[Company]:
    if await rc.get(f"company:existence:{email}") == "false":
        return None

    cache_key = f"company:data:{email}"
    cached_company = await rc.get(cache_key)

    if cached_company:
        await rc.set(f"company:existence:{email}", "true", ex=dt.timedelta(hours=3))
        return Company.model_validate_json(cached_company)

    async with pool.acquire() as conn:
        company_data = await conn.fetchrow(
            """
            SELECT * FROM companies 
            WHERE email = $1
            """,
            email
        )

        if company_data:
            company = Company(**company_data)
            await rc.set(f"company:existence:{email}", "true", ex=dt.timedelta(hours=3))
            await rc.set(
                cache_key,
                company.model_dump_json(),
                ex=dt.timedelta(hours=1)
            )
            return company
    await rc.set(f"company:existence:{email}", "false", ex=dt.timedelta(hours=3))
    return None


async def is_password_can_use(password: str) -> bool:
    if len(password) < 8 or 60 < len(password):
        return False
    if re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", password) is None:
        print(f"{password} is not valid password")
        return False
    return True





@ura.post("/sign-up")
async def user_sign_up(user_data: User):
    pool = await get_pool()
    existing_user = await get_user_by_email(user_data.email, pool)
    if existing_user:
        raise tbank409a
    if not await is_password_can_use(user_data.password):
        raise tbank400

    user_data.password = await hash_password(user_data.password)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO users (uuid, name, surname, email, avatar_url, other, password)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                str(user_data.uuid), user_data.name, user_data.surname,
                user_data.email, user_data.avatar_url, user_data.other.model_dump_json(),
                user_data.password
            )
    await rc.set(f"user:existence:{user_data.email}", "true", ex=dt.timedelta(hours=3))
    token = await generate_jwt_token(user_data.uuid, "user")
    return {"token": token}


@ura.post("/sign-in")
async def user_sign_in(credentials: BasicModel):
    if not credentials.email or not credentials.password:
        raise tbank400

    pool = await get_pool()
    user = await get_user_by_email(credentials.email, pool)

    if not user or not await verify_password(credentials.password, user.password):
        raise tbank401a

    token = await generate_jwt_token(user.uuid, "user")
    return {"token": token}


@cra.post("/sign-up")
async def company_sign_up(company_data: Company):
    pool = await get_pool()

    existing_company = await get_company_by_email(company_data.email, pool)
    if existing_company:
        raise tbank409a
    if not await is_password_can_use(company_data.password):
        raise tbank400

    company_data.password = await hash_password(company_data.password)

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO companies (uuid, name, email, password)
                VALUES ($1, $2, $3, $4)
                """,
                str(company_data.uuid), company_data.name,
                company_data.email, company_data.password
            )
    await rc.set(f"company:existence:{company_data.email}", "true", ex=dt.timedelta(hours=3))
    token = await generate_jwt_token(company_data.uuid, "company")
    return {"token": token, "company_id": str(company_data.uuid)}


@cra.post("/sign-in")
async def company_sign_in(credentials: BasicModel):
    if not credentials.email or not credentials.password:
        raise tbank400

    pool = await get_pool()
    company = await get_company_by_email(credentials.email, pool)

    if not company or not await verify_password(credentials.password, company.password):
        raise tbank401a

    token = await generate_jwt_token(company.uuid, "company")
    return {"token": token}