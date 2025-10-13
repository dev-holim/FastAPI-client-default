from uuid import UUID
from typing import Optional, Dict, Any
from sqlalchemy import select

from app.abc.repository.user import UserRepository

from .entities import User
from ._base import RDBRepository


class UserRepositoryImpl(RDBRepository, UserRepository):
    __repo_name__ = 'user_repository'

    async def find_by_id(self, id_: UUID):
        # result = await self.session.execute(
        #     select(User).where(User.id == id)
        # )
        # return result.scalar_one_or_none()
        stmt = select(User).where(User.id == id_)

        return await self.session.scalar(stmt)

    async def find_by_email(self, email: str):
        stmt = select(User).where(User.email == email)

        return await self.session.scalar(stmt)

    async def add_user(self, data: Dict[str, Any]) -> User:
        user = User(**data)
        self.session.add(user)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def update_user(self, id_: UUID, data: Dict[str, Any]) -> Optional[User]:
        user = await self.find_by_id(id_)
        if not user:
            return None

        for key, value in data.items():
            if hasattr(user, key):
                setattr(user, key, value)

        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def delete_user(self, id_: UUID) -> bool:
        user = await self.find_by_id(id_)
        if not user:
            return False

        await self.session.delete(user)
        await self.session.commit()
        return True