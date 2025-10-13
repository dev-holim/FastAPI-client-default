from typing import Dict, Union, Optional

import jwt

from app.config import settings, JWTConfig
from app.abc.client.jwt import JWTDecodeClient, JWTPayload


class JWTDecoder(JWTDecodeClient):
    def __init__(self):
        # TODO: setting jwt => prod, stage, develop으로 구성
        self.config = settings.jwt

    def _decode(
        self,
        key: str,
        token: str,
    ) -> Optional[
        Dict[
            str,
            Union[str, float]
        ]
    ]:
        try:
            return jwt.decode(
                jwt=token,
                key=key,
                algorithms=self.config.ALGORITHM
            )

        except jwt.ExpiredSignatureError as e:
            raise e

        except (
                jwt.InvalidKeyError,
                jwt.InvalidTokenError,
                jwt.InvalidSignatureError,
                jwt.InvalidAlgorithmError,
        ) as e:
            raise e

    def access_token(self, token: str) -> JWTPayload:
        payload = self._decode(
            self.config.ACCESS_KEY,
            token
        )

        return JWTPayload(**payload)

    def refresh_token(self, token: str) -> JWTPayload:
        payload = self._decode(
            self.config.REFRESH_KEY,
            token
        )

        return JWTPayload(**payload)
