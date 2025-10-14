from fastapi import Depends

from app.abc.repository.base import UoW
from app.adapter.client.auth_client import AuthClient
from app.adapter.client.jwt_encoder import JWTEncoder
from app.adapter.repository.rdb import RDBUoW, UserRepositoryImpl
from app.adapter.repository.rdb.entities import User
from app.core.exception import ALREADY_EXIST_EXCEPTION, ExceptionDetail
from app.security.crypt import PasswordManager, get_password_manager

from .._base_ import Service
from app.core.enums import UserRole


class AddUserService(Service):

    def __init__(
            self,
            rdb_uow: UoW = Depends(
                RDBUoW(
                    repositories=[
                        UserRepositoryImpl
                    ]
                )
            ),
        pm: PasswordManager = Depends(
            get_password_manager
        ),
        jwt_client=Depends(JWTEncoder),
        auth_client=Depends(AuthClient),
    ):
        self.rdb_uow = rdb_uow
        self.password_manager = pm
        self.jwt_client = jwt_client
        self.auth_client = auth_client

    async def __call__(self, name: str, email: str, password: str):
        app_token, _ = self.jwt_client.access_token()

        return await self.auth_client.register(
            {
                "name": name,
                "email": email,
                "password": password,
                "app_token": app_token
            }
        )

        async with self.rdb_uow.enter() as rdb_uow:
            if _ := await rdb_uow.user_repository.find_by_email(email):
                raise ALREADY_EXIST_EXCEPTION(
                    ExceptionDetail.USER_ALREADY_EXIST
                )

            user_ = await rdb_uow.user_repository.save(
                User(
                    name=name,
                    email=email,
                    password=self.password_manager.hash(password),
                    role=UserRole.USER.value
                )
            )

            return {"id":user_.id}