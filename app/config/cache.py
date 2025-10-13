from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from .environment import env_config


class RedisConfig(BaseSettings):
    """Redis 설정"""
    USER: str = ""
    HOST: str = "localhost"
    PORT: int = 6379
    PASSWORD: Optional[str] = None
    DB: int = 0
    EXP: int = 0

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_prefix='REDIS_',
        env_file=env_config.env_file,
        extra='ignore'
    )

    @property
    def connection_string(self) -> str:
        """Redis 연결 문자열 생성"""
        if self.PASSWORD:
            return f"redis://{self.USER}:{self.PASSWORD}@{self.HOST}:{self.PORT}/{self.DB}"
        return f"redis://{self.HOST}:{self.PORT}/{self.DB}"