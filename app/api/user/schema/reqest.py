from pydantic import BaseModel, Field, EmailStr

class SignUpRequest(BaseModel):
    email: EmailStr
    name: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=100)

class SignInRequest(BaseModel):
    email: str
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str