from fastapi import APIRouter, Depends
from fastapi.responses import ORJSONResponse
from typing import Dict, Any, Optional
from cachetools import TTLCache
import asyncio
import orjson

from cm_and_cv.auth import verify_auth, AuthService, EntityService, VERIFY_CACHE
from avrora import get_pool, rc, tbank400, tbank401u
from models import UserPatch, User

PROFILE_CACHE_CONFIG = {
    'TTL': 21600,
    'PREFIX': "user:profile:",
    'SIZE': 10000
}

_profile_cache = TTLCache(maxsize=PROFILE_CACHE_CONFIG['SIZE'],
                          ttl=PROFILE_CACHE_CONFIG['TTL'])

ALLOWED_UPDATE_FIELDS = {'name', 'surname', 'avatar_url', 'password', 'other'}


class ProfileService:
    @staticmethod
    def clean_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        return {k: v for k, v in data.items() if v is not None}

    @staticmethod
    def serialize_user_data(data: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'name': data['name'],
            'surname': data['surname'],
            'email': data['email'],
            'avatar_url': data.get('avatar_url'),
            'other': orjson.loads(data['other']) if isinstance(data['other'], str) else data['other']
        }

    @staticmethod
    async def get_cached_profile(uid: str) -> Optional[Dict[str, Any]]:
        if cached_data := _profile_cache.get(uid):
            return cached_data

        if redis_data := await rc.get(f"{PROFILE_CACHE_CONFIG['PREFIX']}{uid}"):
            try:
                data = orjson.loads(redis_data)
                clean_data = ProfileService.clean_dict(data)
                _profile_cache[uid] = clean_data
                return clean_data
            except (orjson.JSONDecodeError, ValueError):
                await rc.delete(f"{PROFILE_CACHE_CONFIG['PREFIX']}{uid}")

        return None

    @staticmethod
    async def set_cached_profile(uid: str, data: Dict[str, Any]) -> None:
        _profile_cache[uid] = data
        await rc.set(
            f"{PROFILE_CACHE_CONFIG['PREFIX']}{uid}",
            orjson.dumps(data),
            ex=PROFILE_CACHE_CONFIG['TTL']
        )

    @staticmethod
    async def fetch_profile_from_db(pool, uid: str) -> Dict[str, Any]:
        async with pool.acquire() as conn:
            if data := await conn.fetchrow(
                    "SELECT name, surname, email, avatar_url, other FROM users WHERE uuid = $1",
                    uid
            ):
                db_data = dict(data)
                return ProfileService.serialize_user_data(
                    ProfileService.clean_dict(db_data)
                )

        raise tbank401u

    @staticmethod
    def clear_password_verify_cache(old_hash: str) -> None:
        keys_to_remove = [
            k for k in VERIFY_CACHE.keys()
            if k.endswith(f":{old_hash}")
        ]
        for k in keys_to_remove:
            VERIFY_CACHE.pop(k, None)


upr = APIRouter(
    prefix="/api/user/profile",
    tags=["user-profile"],
    default_response_class=ORJSONResponse
)


@upr.get("")
async def get_profile(auth: dict = Depends(verify_auth)) -> Dict[str, Any]:
    if cached_profile := await ProfileService.get_cached_profile(auth['uid']):
        return cached_profile

    pool = await get_pool()
    response = await ProfileService.fetch_profile_from_db(pool, auth['uid'])

    asyncio.create_task(ProfileService.set_cached_profile(auth['uid'], response))

    return response


@upr.patch("")
async def update_profile(
        patch: UserPatch,
        auth: dict = Depends(verify_auth)
) -> Dict[str, Any]:
    update_data = {
        k: v for k, v in patch.model_dump(exclude_unset=True, exclude_none=True).items()
        if k in ALLOWED_UPDATE_FIELDS
    }

    if not update_data:
        raise tbank400

    if 'other' in update_data:
        update_data['other'] = orjson.dumps(update_data['other'])

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
                asyncio.create_task(rc.delete(
                    f"auth:data:{auth['uid']}",
                    f"auth:token:{auth['uid']}"
                ))

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

                    response = ProfileService.serialize_user_data(dict(updated))
                    _profile_cache.pop(auth['uid'], None)
                    EntityService.USER_CACHE.pop(updated['email'], None)

                    await rc.set(
                        f"user:data:{updated['email']}",
                        user_data.model_dump_json(),
                        ex=3600
                    )

                    asyncio.create_task(
                        ProfileService.set_cached_profile(auth['uid'], response)
                    )

                    return response

                raise tbank401u
    except Exception:
        raise tbank400