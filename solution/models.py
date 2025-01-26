import re
import uuid
from datetime import date
from enum import Enum
from functools import lru_cache
from typing import Optional, Dict, List
from uuid import UUID

import pycountry
from pydantic import BaseModel, Field, EmailStr, model_validator, ConfigDict, UUID4, field_validator, HttpUrl

__all__ = ["UTS", "BasicModel", "User", "UserPatch", "Company"]
EMAIL_PATTERN = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')

@lru_cache(maxsize=300)
def validate_country(country_code: str) -> bool:
    return pycountry.countries.get(alpha_2=country_code.lower()) is not None


def fast_email_validate(email: str) -> bool:
    return bool(EMAIL_PATTERN.match(email))


class UTS(BaseModel):
    model_config = ConfigDict(frozen=True)

    age: int = Field(ge=0, le=100)
    country: str = Field(min_length=2, max_length=2)

    @model_validator(mode="before")
    @classmethod
    def validate(cls, data: Dict) -> Dict:
        age = data.get("age", 0)
        if not isinstance(age, int):
            raise ValueError("Age must be an integer")
        if not 0 <= age <= 100:
            raise ValueError("Age must be between 0 and 100")

        country = data.get("country", "")
        if not validate_country(country):
            raise ValueError("Invalid country code")
        data["country"].lower()
        return data


class BasicModel(BaseModel):
    model_config = ConfigDict(
        validate_assignment=True,
        arbitrary_types_allowed=True
    )

    email: Optional[EmailStr] = Field(None, min_length=8, max_length=120)
    password: Optional[str] = Field(None)
    uuid: Optional[UUID] = None

    @model_validator(mode="before")
    @classmethod
    def generate_uuid(cls, data: Dict) -> Dict:
        if "email" in data and data["email"] and "uuid" not in data:
            data["uuid"] = uuid.uuid5(uuid.NAMESPACE_URL, data["email"])
        return data

    @model_validator(mode="after")
    def validate_credentials(self) -> 'BasicModel':
        if self.email is not None and not fast_email_validate(str(self.email)):
            raise ValueError("Invalid email format")
        return self


class User(BasicModel):
    name: str = Field(min_length=1, max_length=100)
    surname: str = Field(min_length=1, max_length=120)
    avatar_url: Optional[str] = Field(None, max_length=350)
    other: UTS

    @model_validator(mode="after")
    def validate_user_specific(self) -> 'User':
        if self.avatar_url:
            url_pattern = re.compile(
                r'^https?://'
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
                r'localhost|'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                r'(?::\d+)?'
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(self.avatar_url):
                raise ValueError("Invalid avatar URL format")
        return self


class UserPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    surname: Optional[str] = Field(None, min_length=1, max_length=120)
    avatar_url: Optional[str] = Field(None, max_length=350)
    other: Optional[UTS] = None

    @model_validator(mode="after")
    def validate_patch_data(self) -> 'UserPatch':
        if self.avatar_url:
            url_pattern = re.compile(
                r'^https?://'
                r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
                r'localhost|'
                r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                r'(?::\d+)?'
                r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            if not url_pattern.match(self.avatar_url):
                raise ValueError("Invalid avatar URL format")

        return self


class Company(BasicModel):
    name: str = Field(min_length=5, max_length=50)


class PromoMode(str, Enum):
    COMMON = "COMMON"
    UNIQUE = "UNIQUE"

class PromoCountry(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v: str) -> str:
        code = v.strip().lower()
        if not pycountry.countries.get(alpha_2=code):
            raise ValueError(f"Invalid country code: {code}")
        return code

class Target(BaseModel):
    age_from: Optional[int] = Field(None, ge=0, le=100)
    age_until: Optional[int] = Field(None, ge=0, le=100)
    country: Optional[PromoCountry] = None
    categories: Optional[List[str]] = Field(None)

    @field_validator('age_from', 'age_until', mode="before")
    def validate_age_range(cls, v, values):
        if v is not None and values.get('age_from') is not None:
            if v < values['age_from']:
                raise ValueError("age_until must be greater than or equal to age_from")
        return v

class PromoBase(BaseModel):
    description: Optional[str] = Field(None, min_length=10, max_length=300)
    image_url: Optional[HttpUrl] = Field(None, max_length=350)
    target: Target
    active_from: Optional[date] = None
    active_until: Optional[date] = None

class PromoCreate(PromoBase):
    mode: PromoMode
    description: str = Field(..., min_length=10, max_length=300)
    max_count: int = Field(..., ge=0, le=100000000)
    promo_common: Optional[str] = Field(None, min_length=5, max_length=30)
    promo_unique: Optional[List[str]] = Field()

    @field_validator('max_count', mode="before")
    def validate_max_count(cls, v, values):
        if values.get('mode') == PromoMode.UNIQUE and v != 1:
            raise ValueError("max_count must be 1 for UNIQUE mode")
        return v

    @field_validator('promo_common', 'promo_unique', mode="before")
    def validate_promo_values(cls, v, values):
        mode = values.get('mode')
        if mode == PromoMode.COMMON:
            if not v and not values.get('promo_common'):
                raise ValueError("promo_common is required for COMMON mode")
            if values.get('promo_unique'):
                raise ValueError("promo_unique not allowed for COMMON mode")
        elif mode == PromoMode.UNIQUE:
            if not v and not values.get('promo_unique'):
                raise ValueError("promo_unique is required for UNIQUE mode")
            if values.get('promo_common'):
                raise ValueError("promo_common not allowed for UNIQUE mode")
        return v

class PromoPatch(PromoBase):
    max_count: Optional[int] = Field(None, ge=0, le=100000000)

    @field_validator('max_count', mode="before")
    def validate_max_count_update(cls, v, values):
        if v is not None and v < values.get('used_count', 0):
            raise ValueError("max_count cannot be less than current usage")
        return v

class PromoForUser(BaseModel):
    promo_id: UUID4
    company_id: UUID
    company_name: str
    description: str
    image_url: HttpUrl
    active: bool
    is_activated_by_user: bool
    like_count: int = Field(ge=0)
    is_liked_by_user: bool
    comment_count: int = Field(ge=0)

class PromoReadOnly(PromoCreate):
    promo_id: UUID4
    company_id: UUID
    company_name: str
    like_count: int = Field(ge=0)
    used_count: int = Field(ge=0)
    active: bool

class CountryStats(BaseModel):
    country: PromoCountry
    used_count: int = Field(ge=0)

class PromoStat(BaseModel):
    activate_count: int = Field(ge=0)
    countries: List[CountryStats]