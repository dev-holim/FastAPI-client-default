from app.abc.repository import Repository

from sqlalchemy.ext.asyncio import AsyncSessionTransaction


class RDBRepository(Repository):
    __repo_name__ = None

    def __init__(self, session):
        self.session: AsyncSessionTransaction
        self.session = session

    def __new__(cls, *args, **kwargs):
        if cls.__repo_name__ is None:
            raise AttributeError(f'__repo_name__ was not define in {cls.__name__}')

        return super().__new__(cls)
    
    async def save(self, entity):
        self.session.add(entity)
        await self.session.flush()
        return entity