from fastapi import APIRouter, Depends, Query, Path, HTTPException
from fastapi.responses import ORJSONResponse
from typing import List, Optional
from pydantic import BaseModel, Field, UUID4
from datetime import datetime
from uuid import uuid4

from cm_and_cv.auth import verify_auth
from avrora import get_pool, tbank400, tbank401u
from models import PromoCountry, PromoCreate, PromoPatch, PromoReadOnly, PromoStat

promo_router = APIRouter(
    prefix="/api/business/promo", 
    tags=["business-promo"],
    default_response_class=ORJSONResponse
)

@promo_router.post("", status_code=201)
async def create_promo(
    promo_data: PromoCreate, 
    auth: dict = Depends(verify_auth)
) -> dict:
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                promo_id = await conn.fetchval(
                    """
                    INSERT INTO promos 
                    (id, company_id, name, description, discount_type, 
                    discount_value, active_from, active_until, 
                    countries, max_usage, created_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    RETURNING id
                    """,
                    uuid4(), auth['uid'], promo_data.name, 
                    promo_data.description, promo_data.discount_type, 
                    promo_data.discount_value, promo_data.active_from, 
                    promo_data.active_until, 
                    promo_data.countries, promo_data.max_usage, 
                    datetime.now()
                )
                return {"id": promo_id}
            except Exception:
                raise tbank400

@promo_router.get("")
async def list_promos(
    auth: dict = Depends(verify_auth),
    limit: int = Query(default=10, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    sort_by: Optional[str] = Query(None, regex='^(active_from|active_until)$'),
    countries: Optional[List[PromoCountry]] = Query(None)
) -> List[PromoReadOnly]:
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        query = """
        SELECT id, company_id, name, description, discount_type, 
               discount_value, active_from, active_until, 
               countries, max_usage, created_at
        FROM promos 
        WHERE company_id = $1
        """
        params = [auth['uid']]
        if countries:
            query += " AND (countries IS NULL OR countries && $2)"
            params.append(countries)

        if sort_by == 'active_from':
            query += " ORDER BY COALESCE(active_from, '-infinity') DESC"
        elif sort_by == 'active_until':
            query += " ORDER BY COALESCE(active_until, 'infinity') DESC"
        else:
            query += " ORDER BY created_at DESC"
        
        query += " LIMIT $3 OFFSET $4"
        params.extend([limit, offset])
        total_count = await conn.fetchval(
            "SELECT COUNT(*) FROM promos WHERE company_id = $1", 
            auth['uid']
        )
        
        promos = await conn.fetch(query, *params)
        
        return [
            PromoReadOnly(**dict(promo)) for promo in promos
        ]

@promo_router.get("/{id}")
async def get_promo(
    id: UUID4 = Path(...),
    auth: dict = Depends(verify_auth)
) -> PromoReadOnly:
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        promo = await conn.fetchrow(
            """
            SELECT id, company_id, name, description, discount_type, 
                   discount_value, active_from, active_until, 
                   countries, max_usage, created_at
            FROM promos 
            WHERE id = $1 AND company_id = $2
            """, 
            id, auth['uid']
        )
        
        if not promo:
            raise HTTPException(status_code=404, detail="Promo not found")
        
        return PromoReadOnly(**dict(promo))

@promo_router.patch("/{id}")
async def update_promo(
    id: UUID4 = Path(...),
    promo_data: PromoPatch = None, 
    auth: dict = Depends(verify_auth)
) -> PromoReadOnly:
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        async with conn.transaction():
            update_fields = []
            params = [id, auth['uid']]
            
            if promo_data.name is not None:
                update_fields.append(f"name = ${len(params) + 1}")
                params.append(promo_data.name)
            
            if promo_data.description is not None:
                update_fields.append(f"description = ${len(params) + 1}")
                params.append(promo_data.description)
            
            if promo_data.discount_type is not None:
                update_fields.append(f"discount_type = ${len(params) + 1}")
                params.append(promo_data.discount_type)
            
            if promo_data.discount_value is not None:
                update_fields.append(f"discount_value = ${len(params) + 1}")
                params.append(promo_data.discount_value)
            
            if promo_data.active_from is not None:
                update_fields.append(f"active_from = ${len(params) + 1}")
                params.append(promo_data.active_from)
            
            if promo_data.active_until is not None:
                update_fields.append(f"active_until = ${len(params) + 1}")
                params.append(promo_data.active_until)
            
            if promo_data.countries is not None:
                update_fields.append(f"countries = ${len(params) + 1}")
                params.append(promo_data.countries)
            
            if promo_data.max_usage is not None:
                update_fields.append(f"max_usage = ${len(params) + 1}")
                params.append(promo_data.max_usage)
            
            if not update_fields:
                raise tbank400
            
            query = f"""
            UPDATE promos 
            SET {', '.join(update_fields)}
            WHERE id = $1 AND company_id = $2
            RETURNING id, company_id, name, description, discount_type, 
                      discount_value, active_from, active_until, 
                      countries, max_usage, created_at
            """
            
            updated_promo = await conn.fetchrow(query, *params)
            
            if not updated_promo:
                raise HTTPException(status_code=404, detail="Promo not found")
            
            return PromoReadOnly(**dict(updated_promo))

@promo_router.get("/{id}/stat")
async def get_promo_stat(
    id: UUID4 = Path(...),
    auth: dict = Depends(verify_auth)
) -> PromoStat:
    pool = await get_pool()
    
    async with pool.acquire() as conn:
        promo_exists = await conn.fetchval(
            "SELECT 1 FROM promos WHERE id = $1 AND company_id = $2", 
            id, auth['uid']
        )
        
        if not promo_exists:
            raise HTTPException(status_code=404, detail="Promo not found")

        stat = await conn.fetchrow(
            """
            SELECT 
                COUNT(*) as total_uses,
                COUNT(DISTINCT user_id) as unique_users,
                COALESCE(SUM(discount_amount), 0) as total_discount_amount
            FROM promo_usages
            WHERE promo_id = $1
            """, 
            id
        )
        
        return PromoStat(
            total_uses=stat['total_uses'],
            unique_users=stat['unique_users'], 
            total_discount_amount=stat['total_discount_amount']
        )
