from functools import lru_cache
from passlib.context import CryptContext
import bcrypt

# Monkey patch for passlib compatibility with bcrypt 4.x
if not hasattr(bcrypt, "__about__"):
    class _About:
        __version__ = bcrypt.__version__
    bcrypt.__about__ = _About()


class PasswordManager:
    def __init__(self):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def hash(self, password: str) -> str:
        """비밀번호 해시"""
        return self.pwd_context.hash(password)

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        """비밀번호 검증"""
        return self.pwd_context.verify(plain_password, hashed_password)


@lru_cache
def get_password_manager() -> PasswordManager:
    # 원하는 스킴/옵션 적용
    return PasswordManager()



# pwd_context = CryptContext(schemes=["bcrypt"])
#
# def hash_password(password: str) -> str:
#     return pwd_context.hash(password)
#
# def verify_password(original_password: str, hash_password: str) -> bool:
#     return pwd_context.verify(original_password, hash_password)