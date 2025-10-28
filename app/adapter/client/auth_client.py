import httpx
from jwt import PyJWKClient, ExpiredSignatureError, InvalidTokenError, decode
from fastapi import HTTPException

from app.abc.client.auth import Auth
from app.config import settings

class AuthClient(Auth):
    def __init__(self):
        self.auth_host = settings.auth.HOST
        self.algorithm = settings.auth.ALGORITHM
        self.timeout = httpx.Timeout(5.0, connect=2.0)

    async def http_request(self, method: str, url: str, **kwargs):
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.request(method, url, **kwargs)
        r.raise_for_status()
        return r.json()

    async def http_post(self, url: str, data: dict = None, json: dict = None, **kwargs):
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as c:
                r = await c.post(url, data=data, json=json, **kwargs)
            r.raise_for_status()
            return r.json()
        except httpx.HTTPStatusError as e:
            detail_result = e.response.json().get("detail", None)
            if not detail_result:
                detail_msg = "Authentication service error"
            elif isinstance(detail_result, list):
                detail_msg = "; ".join([d.get("msg", "Authentication service error") for d in detail_result])
            elif isinstance(detail_result, str):
                detail_msg = detail_result
            else:
                detail_msg = detail_result.get("detail", "Authentication service error")

            raise HTTPException(
                status_code=e.response.status_code,
                detail=detail_msg
            )

    async def login(self, email: str, password: str):
        return await self.http_post(
            f"{self.auth_host}/users/login",
            json={"email": email, "password": password}
        )

    async def register(self, payload: dict):
        return await self.http_post(
            f"{self.auth_host}/users/sign-up",
            json=payload
        )

    async def refresh(self, refresh_token: str):
        return await self.http_post(
            f"{self.auth_host}/users/refresh-token",
            json={"refresh_token": refresh_token}
        )

    def verify_token(self, token: str):
        jwks_client = PyJWKClient(f"{self.auth_host}/.well-known/jwks.json")
        try:
            # JWKS에서 자동으로 올바른 키 찾기 (kid 기반)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # 토큰 검증
            payload = decode(
                token,
                signing_key.key,
                algorithms=[self.algorithm],
                audience="https://api.local",
                issuer="https://auth.local"
            )

            return {
                "sub": payload.get("sub"),
                "typ": payload.get("typ"),
                "exp": payload.get("exp"),
            }
        except ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="토큰이 만료되었습니다")
        except InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f"유효하지 않은 토큰: {str(e)}")