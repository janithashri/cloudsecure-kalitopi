from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str = ""
    password: str

#MODEL_VALIDATE: TYPE COERCES SAFE AND FOR UNTRUSTED DATA, USING CORE SCHEMA
#MODEL_CONSTRUCT : FOR TRUSTED DATA NO VALIDATION BYPASSES AND CREATES INSTANCE DICTIONARY 

class UserOut(BaseModel):
    id: int
    email: str
    username: str

    class Config:
        from_attributes = True


class LoginResponse(BaseModel):
    token: str
    user: UserOut


class MeResponse(BaseModel):
    id: int
    email: str
    username: str
    tenant_id: int | None
