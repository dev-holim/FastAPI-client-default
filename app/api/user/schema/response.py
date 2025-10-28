from uuid import UUID
from pydantic import BaseModel


class DefaultResponse(BaseModel):
    id: UUID

class SignUpResponse(DefaultResponse):
    ...

class JWTTokenData(BaseModel):
    access_token: str
    refresh_token: str
    access_expired_at: float
    refresh_expired_at: float

class SignInResponse(JWTTokenData):
    ...

class RefreshTokenResponse(JWTTokenData):
    ...