from uuid import UUID

from fastapi import Depends

from app.adapter.client.auth_client import AuthClient
from app.core.exception import AUTHENTICATION_ERROR_EXCEPTION, ExceptionDetail
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

class Authorization:

    def __init__(self):
        ...

    def __call__(
            self,
            credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer()), # Authorization: Bearer <JWT>
            auth_client: AuthClient = Depends(AuthClient)
            # token_cookie: Optional[str] = Cookie(alias='access_token', default=None),
            # token_header: Optional[str] = Header(alias='Authorization', default=None)
    ) -> UUID:
        if not credentials:
            raise AUTHENTICATION_ERROR_EXCEPTION(
                ExceptionDetail.TOKEN_NOT_FOUND
            )
        payload = auth_client.verify_token(credentials.credentials)

        return UUID(payload.get("sub"))
