from typing import List, Type, Optional

from sqlalchemy.ext.asyncio import (async_sessionmaker,
                                    create_async_engine)

from app.config import get_async_database_url
from app.abc.repository.base import UoW

from ._base import RDBRepository


class RDBUoW(UoW):
    __session_maker: Optional[async_sessionmaker] = None

    def enter(self, exp_on_commit: bool = True, **kwargs):
        self._exp_on_commit = exp_on_commit

        if kwargs:
            self._kwargs = kwargs

        return self

    @staticmethod
    def initialize_session_maker(session_maker: async_sessionmaker):
        RDBUoW.__session_maker = session_maker

    def __init__(self, repositories: List[Type[RDBRepository]]):
        self._repositories = repositories
        self._bind_repositories = {}

    def __call__(self):
        """
        This Function exist for "fastapi.Depends"
        Because, __init__ function already called before, as static.
        So, "fastapi.Depends" call this function and it must return itself
        """
        return self

    def __getattr__(self, item):
        return self._bind_repositories.get(item)

    async def __aenter__(self):
        self._session = self.__session_maker(
            expire_on_commit=self._exp_on_commit,
            **(self._kwargs if self._kwargs else {})
        )

        self._bind_repositories: dict = (
            {
                repo.__repo_name__: repo(self._session)
                for repo in self._repositories
            }
        )

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            if exc_type is None:
                await self._session.commit()
            else:
                await self._session.rollback()
        finally:
            await self._session.close()


async def init_rdb():
    from . import entities

    url = get_async_database_url()
    engine = create_async_engine(url, echo=True)

    await entities.create_tables(engine)

    RDBUoW.initialize_session_maker(
        session_maker=async_sessionmaker(bind=engine)
    )
