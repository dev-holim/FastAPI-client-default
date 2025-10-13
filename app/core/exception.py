from enum import Enum
from http import HTTPStatus
from typing import Optional, Union

from fastapi import HTTPException


class ExceptionDetail(str, Enum):
    # User
    USER_NOT_FOUND = 'USER_NOT_FOUND'
    USER_ALREADY_EXIST = 'USER_ALREADY_EXIST'
    USER_PASSWORD_NOT_MATCH = 'USER_PASSWORD_NOT_MATCH'
    USER_NOT_SIGNED_IN = 'USER_NOT_SIGNED_IN'

    # Token
    TOKEN_NOT_FOUND = 'TOKEN_NOT_FOUND'
    INVALID_TOKEN_NO_SUFFIx = 'INVALID_TOKEN_NO_SUFFIx'


class DefaultException(HTTPException):

    def __init__(
            self,
            status_code: int,
            detail: Optional[str] = None
    ):
        self.status_code = status_code
        self.detail = (
            detail
            if (detail is not None)
            else HTTPStatus(status_code).name
        )

    def __call__(self, detail: Union[str, Enum]):
        if isinstance(detail, Enum):
            self.detail = detail.value

        else:
            self.detail = detail

        return self


AUTHENTICATION_ERROR_EXCEPTION = DefaultException(401)
FORBIDDEN_EXCEPTION = DefaultException(403)
NOT_FOUND_EXCEPTION = DefaultException(404)
ALREADY_EXIST_EXCEPTION = DefaultException(409)
UNPROCESSABLE_ENTITY = DefaultException(422)
INTERNAL_SERVER_ERROR = DefaultException(500)

INTERNAL_SERVER_ERROR = DefaultException(500)