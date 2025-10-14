import hashlib
from typing import Tuple
from pathlib import Path
from dataclasses import dataclass
from abc import ABC, abstractmethod

from app.config import settings

@dataclass(frozen=True)
class JWTPayload:
    sub: str
    typ: str
    iss: str
    aud: str
    exp: float


class JWTClient(ABC):
    def __init__(self):
        self.config = settings.jwt
        self.algorithm = self.config.ALGORITHM
        self.issuer = self.config.ISSUER
        self.audience = self.config.AUDIENCE

        # Load RSA keys
        self._public_key = self._load_public_key()
        self._private_key = self._load_private_key()

        # Generate key ID from public key thumbprint
        self._kid = self._generate_kid()

    def _load_public_key(self) -> str:
        key_path = Path(self.config.PUBLIC_KEY_PATH)
        if not key_path.exists():
            # TODO: Exception 처리 수정
            raise FileNotFoundError(
                f"Public key not found at {key_path}. "
            )
        return key_path.read_text()

    def _load_private_key(self) -> str:
        key_path = Path(self.config.PRIVATE_KEY_PATH)
        if not key_path.exists():
            # TODO: Exception 처리 수정
            raise FileNotFoundError(
                f"Private key not found at {key_path}. "
            )
        return key_path.read_text()

    def _generate_kid(self) -> str:
        # Create a hash of the public key to use as kid
        key_hash = hashlib.sha256(self._public_key.encode()).hexdigest()
        return key_hash[:16]  # Use first 16 characters

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
