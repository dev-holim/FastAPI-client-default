import httpx
from jwt import PyJWKClient, ExpiredSignatureError, InvalidTokenError, decode
from fastapi import HTTPException

from app.abc.client.auth import Auth
from app.config import settings

class AuthClient(Auth):
    def __init__(self):
        self.auth_host = settings.jwt.AUTH_HOST
        self.timeout = httpx.Timeout(5.0, connect=2.0)

    async def http_request(self, method: str, url: str, **kwargs):
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.request(method, url, **kwargs)
        r.raise_for_status()
        return r.json()

    async def http_post(self, url: str, data: dict = None, json: dict = None, **kwargs):
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(url, data=data, json=json, **kwargs)
        r.raise_for_status()
        return r.json()

    async def login(self, email: str, password: str):
        return await self.http_post(
            f"{self.auth_host}/users/login",
            json={"email": email, "password": password}
        )

    async def register(self, payload: dict):
        # TODO: payload 검증 필요
        return await self.http_post(
            f"{self.auth_host}/users/sign-up",
            json=payload
        )

    async def refresh(self, refresh_token: str, client_id: str):
        # TODO: client_id 검증 필요
        async with httpx.AsyncClient(timeout=self.timeout) as c:
            r = await c.post(f"{self.auth_host}/oauth/token", data={
                "grant_type":"refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id
            })
        r.raise_for_status()
        return r.json()

    def verify_token(self, token: str):
        jwks_client = PyJWKClient(f"{self.auth_host}/.well-known/jwks.json")
        try:
            # JWKS에서 자동으로 올바른 키 찾기 (kid 기반)
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            # 토큰 검증
            payload = decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
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