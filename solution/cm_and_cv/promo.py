from asyncpg import Record
from fastapi import APIRouter, Depends, Query, Path, Header, HTTPException
from fastapi.responses import ORJSONResponse
from typing import List, Optional
import asyncpg
from datetime import datetime
import orjson

from models import (
    PromoCreate, PromoPatch, PromoReadOnly, PromoStat,
    PromoMode, Target, CountryStats
)
from cm_and_cv.auth import verify_auth
from avrora import get_pool, rc, tbank400
from pydantic import UUID4

CACHE_CONFIG = {
    'TTL': 3600,
    'PREFIX': 'promo:',
    'FIELDS': """
        id, company_id, name, description, image_url, mode,
        promo_common, promo_unique, target, max_count,
        active_from, active_until, like_count, used_count,
        active, created_at
    """
}

class PromoService:
    @staticmethod
    async def get_cached(promo_id: str, company_id: str) -> Optional[dict]:
        key = f"{CACHE_CONFIG['PREFIX']}{company_id}:{promo_id}"
        if cached := await rc.get(key):
            return orjson.loads(cached)
        return None

    @staticmethod
    async def set_cached(promo_id: str, company_id: str, data: dict) -> None:
        key = f"{CACHE_CONFIG['PREFIX']}{company_id}:{promo_id}"
        await rc.set(key, orjson.dumps(data), ex=CACHE_CONFIG['TTL'])

    @staticmethod
    async def clear_cache(promo_id: str, company_id: str) -> None:
        key = f"{CACHE_CONFIG['PREFIX']}{company_id}:{promo_id}"
        await rc.delete(key)

    @staticmethod
    def is_promo_active(promo: dict) -> bool:
        now = datetime.now().date()
        if promo['active_from'] and now < promo['active_from']:
            return False
        if promo['active_until'] and now > promo['active_until']:
            return False
        if promo['mode'] == PromoMode.COMMON:
            return promo['used_count'] < promo['max_count']
        return bool(promo['promo_unique'])

    @staticmethod
    def format_promo(row: Record) -> dict:
        data = dict(row)
        data['active'] = PromoService.is_promo_active(data)
        return data

promo_router = APIRouter(
    prefix="/api/business/promo",
    tags=["business-promo"],
    default_response_class=ORJSONResponse
)

@promo_router.post("")
async def create_promo(
    promo: PromoCreate,
    auth: dict = Depends(verify_auth)
) -> dict:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                result = await conn.fetchrow(
                    f"""
                    INSERT INTO promos ({CACHE_CONFIG['FIELDS']})
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 0, 0, true, $13)
                    RETURNING id
                    """,
                    *[getattr(promo, field) for field in CACHE_CONFIG['FIELDS'].split(', ')]
                )
                return {"id": result['id']}
            except asyncpg.UniqueViolationError:
                raise HTTPException(status_code=409)
            except Exception:
                raise tbank400


@promo_router.get("")
async def list_promos(
        auth: dict = Depends(verify_auth),
        limit: int = Query(10, ge=1, le=100),
        offset: int = Query(0, ge=0),
        sort_by: Optional[str] = Query(None, regex="^(active_from|active_until)$"),
        country: Optional[str] = Query(None),
        x_total_count: bool = Header(False, alias="X-Total-Count")
) -> List[PromoReadOnly]:
    pool = await get_pool()
    async with pool.acquire() as conn:
        query = f"SELECT {CACHE_CONFIG['FIELDS']} FROM promos WHERE company_id = $1"
        params = [auth['uid']]

        if country:
            countries = [c.strip().lower() for c in country.split(',')]
            query += " AND (target->>'country' = ANY($2) OR target->>'country' IS NULL)"
            params.append(countries)

        count_query = f"SELECT COUNT(*) FROM ({query}) AS filtered"

        if sort_by:
            query += f" ORDER BY {sort_by} DESC NULLS LAST"
        else:
            query += " ORDER BY created_at DESC"

        query += " LIMIT $3 OFFSET $4"
        params.extend([limit, offset])

        async with conn.transaction():
            total = await conn.fetchval(count_query, *params[:2]) if x_total_count else 0
            rows = await conn.fetch(query, *params)

        promos = [PromoReadOnly(**PromoService.format_promo(row)) for row in rows]

        if x_total_count:
            return ORJSONResponse(
                content=promos,
                headers={"X-Total-Count": str(total)}
            )
        return promos


@promo_router.get("/{promo_id}")
async def get_promo(
        promo_id: UUID4,
        auth: dict = Depends(verify_auth)
) -> PromoReadOnly:
    if cached := await PromoService.get_cached(str(promo_id), auth['uid']):
        return PromoReadOnly(**cached)

    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            f"""
            SELECT {CACHE_CONFIG['FIELDS']}
            FROM promos
            WHERE id = $1 AND company_id = $2
            """,
            promo_id, auth['uid']
        )
        if not row:
            raise HTTPException(status_code=404)

        promo = PromoService.format_promo(row)
        await PromoService.set_cached(str(promo_id), auth['uid'], promo)
        return PromoReadOnly(**promo)


@promo_router.patch("/{promo_id}")
async def update_promo(
        promo_id: UUID4,
        patch: PromoPatch,
        auth: dict = Depends(verify_auth)
) -> PromoReadOnly:
    update_data = patch.model_dump(exclude_unset=True)
    if not update_data:
        raise tbank400

    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            current = await conn.fetchrow(
                """
                SELECT used_count, mode
                FROM promos
                WHERE id = $1 AND company_id = $2
                """,
                promo_id, auth['uid']
            )
            if not current:
                raise HTTPException(status_code=404)

            if (max_count := update_data.get('max_count')) is not None:
                if current['mode'] == PromoMode.UNIQUE and max_count != 1:
                    raise tbank400
                if max_count < current['used_count']:
                    raise tbank400

            set_parts = []
            params = [promo_id, auth['uid']]

            for key, value in update_data.items():
                params.append(value)
                set_parts.append(f"{key} = ${len(params)}")

                if key in ('active_from', 'active_until'):
                    set_parts.append(
                        f"active = CASE WHEN used_count < max_count "
                        f"THEN CURRENT_DATE BETWEEN COALESCE(active_from, CURRENT_DATE) "
                        f"AND COALESCE(active_until, CURRENT_DATE) ELSE false END"
                    )

            query = f"""
            UPDATE promos 
            SET {', '.join(set_parts)}
            WHERE id = $1 AND company_id = $2
            RETURNING {CACHE_CONFIG['FIELDS']}
            """

            row = await conn.fetchrow(query, *params)
            if not row:
                raise HTTPException(status_code=404)

            promo = PromoService.format_promo(row)
            await PromoService.clear_cache(str(promo_id), auth['uid'])
            return PromoReadOnly(**promo)


@promo_router.get("/{promo_id}/stat")
async def get_promo_stats(
        promo_id: UUID4,
        auth: dict = Depends(verify_auth)
) -> PromoStat:
    pool = await get_pool()
    async with pool.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM promos WHERE id = $1 AND company_id = $2",
            promo_id, auth['uid']
        )
        if not exists:
            raise HTTPException(status_code=404)
        stats = await conn.fetch(
            """
            SELECT 
                COUNT(*) as activate_count,
                user_country as country,
                COUNT(*) as country_count
            FROM promo_activations
            WHERE promo_id = $1
            GROUP BY user_country
            """,
            promo_id
        )

        if not stats:
            return PromoStat(activate_count=0, countries=[])

        total_activations = sum(row['activate_count'] for row in stats)
        country_stats = [
            CountryStats(
                country=row['country'],
                used_count=row['country_count']
            ) for row in stats if row['country']
        ]

        return PromoStat(
            activate_count=total_activations,
            countries=country_stats
        )
