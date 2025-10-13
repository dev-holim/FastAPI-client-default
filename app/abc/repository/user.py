from abc import abstractmethod

from .base import Repository


class UserRepository(Repository):

    @abstractmethod
    async def find_by_email(self, email: str):
        pass