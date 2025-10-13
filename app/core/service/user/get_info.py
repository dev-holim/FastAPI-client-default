from uuid import UUID
from fastapi import Depends

from app.abc.repository.base import UoW
from app.adapter.repository.rdb import RDBUoW, UserRepositoryImpl
from app.core.exception import NOT_FOUND_EXCEPTION, ExceptionDetail

from .._base_ import Service


class GetMyInformationService(Service):

    def __init__(
            self,
            uow: UoW = Depends(
                RDBUoW(
                    repositories=[
                        UserRepositoryImpl
                    ]
                )
            )
    ):
        self.uow = uow

    async def __call__(self, user_id: UUID):
        async with self.uow.enter() as uow:
            user_ = await uow.user_repository.find_by_id(user_id)

            if user_ is None:
                raise NOT_FOUND_EXCEPTION(
                    ExceptionDetail.USER_NOT_FOUND
                )

            return {
                'name': user_.name,
                'email': user_.email
            }