from datetime import datetime

from pydantic import BaseModel


class FindingOut(BaseModel):
    id: int
    arn: str
    resource_type: str
    region: str
    rule_id: str
    rule_name: str
    severity: str
    status: str
    compliance_frameworks: list
    remediation_steps: str
    resource_config: dict | None = None
    first_seen: datetime
    last_seen: datetime

    class Config:
        from_attributes = True


class CustomRuleCreate(BaseModel):
    name: str
    resource_type: str
    rule_id: str
    severity: str = "MEDIUM"
    compliance_frameworks: list = []
    description: str = ""
    rego_policy: str
    enabled: bool = True
    provider: int | None = None


class CustomRuleOut(CustomRuleCreate):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
