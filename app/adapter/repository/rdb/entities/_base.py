from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio.engine import AsyncEngine

from app.config import settings

class Base(DeclarativeBase):
    ...

    __table_args__ = {
        'schema': settings.database.SCHEMA,
    }


async def create_tables(engine: AsyncEngine):
    async with engine.begin() as conn:
        metadata = Base.registry.metadata
        print('CREATE TABLE')
        await conn.run_sync(metadata.create_all, checkfirst=True)
