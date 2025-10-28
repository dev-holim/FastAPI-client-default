from fastapi import Depends

from app.abc.repository.base import UoW
from app.adapter.client.auth_client import AuthClient
from app.adapter.repository.rdb import RDBUoW, UserRepositoryImpl
from app.adapter.repository.rdb.entities import User
from app.core.exception import ALREADY_EXIST_EXCEPTION, ExceptionDetail
from app.security.crypt import PasswordManager, get_password_manager

from .._base_ import Service
from app.core.enums import UserRole


class VerifyRefreshTokenService(Service):

    def __init__(
            self,
            auth_client=Depends(AuthClient),
    ):
        self.auth_client = auth_client

    async def __call__(self, refresh_token: str):
        return await self.auth_client.refresh(
            refresh_token=refresh_token
        )
