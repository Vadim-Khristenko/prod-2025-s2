from fastapi import APIRouter, Depends
from cm_and_cv.auth import verify_auth
from avrora import get_pool, rc, tbank400, tbank401u
from models import UserPatch
import orjson
from typing import Dict, Any
import asyncio
from fastapi.responses import ORJSONResponse
from cachetools import TTLCache

upr = APIRouter(
    prefix="/api/user/profile",
    tags=["B2C"],
    default_response_class=ORJSONResponse
)

CACHE_CONFIG = {
    'TTL': 21600,
    'PREFIX': "user:profile:",
    'SIZE': 10000
}

ALLOWED_UPDATE_FIELDS = {'name', 'surname', 'avatar_url', 'other'}
_cache = TTLCache(maxsize=CACHE_CONFIG['SIZE'], ttl=CACHE_CONFIG['TTL'])


class ProfileService:
    @staticmethod
    def serialize_data(data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            'name': data['name'],
            'surname': data['surname'],
            'email': data['email'],
            'avatar_url': data.get('avatar_url'),
            'other': (
                orjson.loads(data['other'])
                if isinstance(data['other'], str)
                else data['other']
            )
        }
        return result

    @staticmethod
    async def get_cached(uid: str) -> Dict[str, Any] | None:
        if data := _cache.get(uid):
            return data

        if redis_data := await rc.get(f"{CACHE_CONFIG['PREFIX']}{uid}"):
            try:
                data = orjson.loads(redis_data)
                _cache[uid] = data
                return data
            except ValueError:
                await rc.delete(f"{CACHE_CONFIG['PREFIX']}{uid}")
        return None

    @staticmethod
    async def set_cached(uid: str, data: Dict[str, Any]) -> None:
        _cache[uid] = data
        await rc.set(
            f"{CACHE_CONFIG['PREFIX']}{uid}",
            orjson.dumps(data),
            ex=CACHE_CONFIG['TTL']
        )

    @staticmethod
    async def get_from_db(pool, uid: str) -> Dict[str, Any]:
        async with pool.acquire() as conn:
            if data := await conn.fetchrow(
                    """
                    SELECT name, surname, email, avatar_url, other 
                    FROM users 
                    WHERE uuid = $1
                    """,
                    uid
            ):
                return ProfileService.serialize_data(dict(data))
        raise tbank401u


@upr.get("")
async def get_profile(auth: dict = Depends(verify_auth)) -> Dict[str, Any]:
    if cached := await ProfileService.get_cached(auth['uid']):
        return cached

    pool = await get_pool()
    response = await ProfileService.get_from_db(pool, auth['uid'])

    asyncio.create_task(ProfileService.set_cached(auth['uid'], response))
    return response


@upr.patch("")
async def update_profile(
        patch: UserPatch,
        auth: dict = Depends(verify_auth)
) -> Dict[str, Any]:
    update_data = patch.model_dump(exclude_unset=True, exclude_none=True)

    if not update_data or not set(update_data).issubset(ALLOWED_UPDATE_FIELDS):
        raise tbank400

    if 'other' in update_data:
        update_data['other'] = orjson.dumps(update_data['other'])

    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            set_clause = ', '.join(f"{k} = ${i + 2}" for i, k in enumerate(update_data))
            query = f"""
                UPDATE users 
                SET {set_clause}
                WHERE uuid = $1
                RETURNING name, surname, email, avatar_url, other
            """

            async with conn.transaction():
                if updated := await conn.fetchrow(query, auth['uid'], *update_data.values()):
                    response = ProfileService.serialize_data(dict(updated))
                    _cache.pop(auth['uid'], None)
                    await rc.delete(f"{CACHE_CONFIG['PREFIX']}{auth['uid']}")
                    asyncio.create_task(ProfileService.set_cached(auth['uid'], response))
                    return response

                raise tbank401u
    except:
        raise tbank400