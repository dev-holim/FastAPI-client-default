from abc import ABC, abstractmethod


class Service(ABC):

    @abstractmethod
    async def __call__(self, *args, **kwargs):
        raise NotImplementedError


__all__ = ['Service']
