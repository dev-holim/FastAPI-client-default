from abc import ABC, abstractmethod

class Auth(ABC):

    ...

    @abstractmethod
    def login(self, email: str, password: str) -> dict:
        raise NotImplementedError