from fastapi import Depends

from app.adapter.client.auth_client import AuthClient
from .._base_ import Service


class SignInService(Service):

    def __init__(
            self,
            auth_client = Depends(AuthClient),
    ):
        self.auth_client = auth_client

    async def __call__(self, email: str, password: str):
        return await self.auth_client.login(email, password)
