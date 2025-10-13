from typing import Self
from abc import ABC, abstractmethod


class Repository(ABC):
    ...

# Unit fo work
class UoW(ABC):

    @abstractmethod
    def __call__(self) -> Self:
        raise NotImplementedError

    def enter(self, *args, **kwargs) -> Self:
        raise NotImplementedError

    @abstractmethod
    async def __aenter__(self):
        raise NotImplementedError
