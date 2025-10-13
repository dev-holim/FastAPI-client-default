from uuid import UUID
from typing import Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod


@dataclass(frozen=True)
class JWTPayload:
    sub: str
    typ: str
    exp: float


class JWTEncodeClient(ABC):

    @abstractmethod
    def access_token(self) -> Tuple[str, float]:
        raise NotImplementedError

    @abstractmethod
    def refresh_token(self) -> Tuple[str, float]:
        raise NotImplementedError


class JWTDecodeClient(ABC):

    @abstractmethod
    def access_token(self, token: str) -> JWTPayload:
        raise NotImplementedError

    @abstractmethod
    def refresh_token(self, token: str) -> JWTPayload:
        raise NotImplementedError
