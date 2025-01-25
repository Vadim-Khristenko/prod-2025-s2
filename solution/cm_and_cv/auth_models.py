from pydantic import BaseModel, Field, EmailStr, model_validator, AnyUrl, ConfigDict
from typing import Optional, Dict
import uuid
from uuid import UUID
import pycountry
from functools import lru_cache

__all__ = ["UTS", "BasicModel", "User", "UserPatch", "Company"]


@lru_cache(maxsize=300)
def validate_country(country_code: str) -> bool:
    return pycountry.countries.get(alpha_2=country_code) is not None


class UTS(BaseModel):
    model_config = ConfigDict(frozen=True)

    age: int = Field(ge=0, le=100)
    country: str = Field(min_length=2, max_length=2)

    @model_validator(mode="before")
    @classmethod
    def validate(cls, data: Dict) -> Dict:
        age = data.get("age", 0)
        if not 0 <= age <= 100:
            raise ValueError("Age must be between 0 and 100")

        country = data.get("country", "")
        if not validate_country(country):
            raise ValueError("Invalid country code")

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


class User(BasicModel):
    name: str = Field(min_length=1, max_length=100)
    surname: str = Field(min_length=1, max_length=120)
    avatar_url: Optional[str] = Field(None, max_length=350)
    other: UTS


class UserPatch(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    name: Optional[str] = Field(None, min_length=1, max_length=100)
    surname: Optional[str] = Field(None, min_length=1, max_length=120)
    avatar_url: Optional[str] = Field(None, max_length=350)
    other: Optional[UTS] = None


class Company(BasicModel):
    name: str = Field(min_length=5, max_length=50)