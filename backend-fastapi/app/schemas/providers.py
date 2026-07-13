from datetime import datetime

from pydantic import BaseModel, Field, field_validator


class ProviderCreate(BaseModel):
    name: str
    aws_account_id: str
    inventory_role_name: str = "CloudSecureRole"
    active: bool = True

    @field_validator("aws_account_id")
    @classmethod
    def validate_account_id(cls, v: str) -> str:
        if len(v) != 12 or not v.isdigit():
            raise ValueError("aws_account_id must be exactly 12 digits")
        return v


class ProviderUpdate(BaseModel):
    name: str | None = None
    aws_account_id: str | None = None
    inventory_role_name: str | None = None
    active: bool | None = None


class ProviderOut(BaseModel):
    id: int
    name: str
    aws_account_id: str
    inventory_role_name: str
    active: bool
    connection_verified: bool
    last_connection_test: datetime | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class InventoryRunOut(BaseModel):
    id: int
    state: str
    started_at: datetime
    completed_at: datetime | None
    stats: dict

    class Config:
        from_attributes = True


class InventoryPullResponse(BaseModel):
    task_id: str
    status: str = "queued"
