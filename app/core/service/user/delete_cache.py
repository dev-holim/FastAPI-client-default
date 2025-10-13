from fastapi import Depends

from app.adapter.repository.cache import CacheUoW, UserTokenRepo

from .._base_ import Service


class DeleteCacheTokenService(Service):

    def __init__(
        self,
        uow: CacheUoW = Depends(CacheUoW(
            repositories=[
                UserTokenRepo
            ]
        ))
    ):
        self.uow = uow

    async def __call__(self, user_id: str):
        async with self.uow.enter() as uow:
            # 토큰 존재 여부 확인
            await uow.user.delete_refresh_token(user_id)
