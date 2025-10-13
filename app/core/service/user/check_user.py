from fastapi import Depends

from app.abc.repository.base import UoW
from app.adapter.repository.cache import CacheUoW, UserTokenRepo
from app.adapter.repository.rdb import RDBUoW, UserRepositoryImpl
from app.adapter.repository.rdb.entities import User
from app.common.enums.user_status import UserLoginStatus

from .._base_ import Service


class CheckUserService(Service):

    def __init__(
            self,
            rdb_uow: UoW = Depends(
                RDBUoW(
                    repositories=[
                        UserRepositoryImpl
                    ]
                )
            ),
            cache_uow: UoW = Depends(
                CacheUoW(
                    repositories=[
                        UserTokenRepo
                    ]
                )
            ),
    ):
        self.rdb_uow = rdb_uow
        self.cache_uow = cache_uow

    async def __call__(self, user_id: str) -> UserLoginStatus:
        async with self.cache_uow.enter() as cache_uow:
            if _ := await cache_uow.user_token_repo.get_user_hash(user_id):
                return UserLoginStatus.LOGIN

        async with self.rdb_uow.enter() as rdb_uow:
            user_: User = await rdb_uow.user_repository.find_by_id(user_id)

            if user_ is None:
                return UserLoginStatus.NO_AUTH

            return UserLoginStatus.LOGOUT