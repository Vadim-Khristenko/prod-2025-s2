from fastapi import APIRouter, Depends
from cm_and_cv.auth import verify_auth, AuthService, EntityService, VERIFY_CACHE
from avrora import get_pool, rc, tbank400, tbank401u
from models import UserPatch, User
import orjson
from typing import Dict, Any
import asyncio
from fastapi.responses import ORJSONResponse
from cachetools import TTLCache

upr = APIRouter(prefix="/api/user/profile", tags=["user-profile"], default_response_class=ORJSONResponse)

CACHE = {'TTL': 21600, 'PREFIX': "user:profile:", 'SIZE': 10000}
ALLOWED_FIELDS = {'name', 'surname', 'avatar_url', 'other', 'password'}
_cache = TTLCache(maxsize=CACHE['SIZE'], ttl=CACHE['TTL'])


class ProfileService:
    @staticmethod
    def serialize_data(data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'name': data['name'],
            'surname': data['surname'],
            'email': data['email'],
            'avatar_url': data.get('avatar_url'),
            'other': orjson.loads(data['other']) if isinstance(data['other'], str) else data['other']
        }

    @staticmethod
    def clean_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in data.items() if v is not None}

    @staticmethod
    async def get_cached(uid: str) -> Dict[str, Any] | None:
        if data := _cache.get(uid):
            return ProfileService.clean_dict(data)
        if redis_data := await rc.get(f"{CACHE['PREFIX']}{uid}"):
            try:
                data = orjson.loads(redis_data)
                clean_data = ProfileService.clean_dict(data)
                _cache[uid] = clean_data
                return clean_data
            except ValueError:
                await rc.delete(f"{CACHE['PREFIX']}{uid}")
        return None

    @staticmethod
    async def set_cached(uid: str, data: Dict[str, Any]) -> None:
        clean_data = ProfileService.clean_dict(data)
        _cache[uid] = clean_data
        await rc.set(f"{CACHE['PREFIX']}{uid}", orjson.dumps(clean_data), ex=CACHE['TTL'])

    @staticmethod
    async def get_from_db(pool, uid: str) -> Dict[str, Any]:
        async with pool.acquire() as conn:
            if data := await conn.fetchrow(
                    "SELECT name, surname, email, avatar_url, other FROM users WHERE uuid = $1",
                    uid
            ):
                db_data = dict(data)
                return ProfileService.serialize_data(ProfileService.clean_dict(db_data))
        raise tbank401u
    
    @staticmethod
    def clear_password_verify_cache(old_hash: str) -> None:
        keys_to_remove = [
            k for k in VERIFY_CACHE.keys()
            if k.endswith(f":{old_hash}")
        ]
        for k in keys_to_remove:
            VERIFY_CACHE.pop(k, None)


@upr.get("")
async def get_profile(auth: dict = Depends(verify_auth)) -> Dict[str, Any]:
    if cached := await ProfileService.get_cached(auth['uid']): return cached
    pool = await get_pool()
    response = await ProfileService.get_from_db(pool, auth['uid'])
    asyncio.create_task(ProfileService.set_cached(auth['uid'], response))
    return response


@upr.patch("")
async def update_profile(patch: UserPatch, auth: dict = Depends(verify_auth)) -> Dict[str, Any]:
    update_data = patch.model_dump(exclude_unset=True, exclude_none=True)
    if not update_data or not set(update_data).issubset(ALLOWED_FIELDS): raise tbank400

    pool = await get_pool()
    try:
        async with pool.acquire() as conn:
            if password := update_data.pop('password', None):
                old_pwd_hash = await conn.fetchval(
                    "SELECT password FROM users WHERE uuid = $1",
                    auth['uid']
                )
                update_data['password'] = await AuthService.hash_password(password)
                ProfileService.clear_password_verify_cache(old_pwd_hash)
                asyncio.create_task(rc.delete(f"auth:data:{auth['uid']}", f"auth:token:{auth['uid']}"))

            if 'other' in update_data:
                update_data['other'] = orjson.dumps(update_data['other'])

            set_clause = ', '.join(f"{k} = ${i + 2}" for i, k in enumerate(update_data))
            async with conn.transaction():
                if updated := await conn.fetchrow(
                        f"UPDATE users SET {set_clause} WHERE uuid = $1 "
                        "RETURNING uuid, name, surname, email, avatar_url, other, password",
                        auth['uid'], *update_data.values()
                ):
                    user_data = User(
                        uuid=updated['uuid'],
                        name=updated['name'],
                        surname=updated['surname'],
                        email=updated['email'],
                        avatar_url=updated['avatar_url'],
                        other=orjson.loads(updated['other']) if isinstance(updated['other'], str) else updated['other'],
                        password=updated['password']
                    )

                    response = ProfileService.serialize_data(dict(updated))
                    _cache.pop(auth['uid'], None)
                    EntityService.USER_CACHE.pop(updated['email'], None)

                    await rc.set(
                        f"user:data:{updated['email']}",
                        user_data.model_dump_json(),
                        ex=3600
                    )

                    asyncio.create_task(ProfileService.set_cached(auth['uid'], response))
                    return response
                raise tbank401u
    except:
        raise tbank400