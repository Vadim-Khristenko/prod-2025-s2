from pydantic import BaseModel, Field, EmailStr, model_validator, ConfigDict
from typing import Optional, Dict
import uuid
from uuid import UUID
import pycountry
from functools import lru_cache
import re

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
        if age.is_integer() is False:
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
