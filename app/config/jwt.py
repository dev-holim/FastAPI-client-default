from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from .environment import env_config


class JWTConfig(BaseSettings):
    """데이터베이스 설정"""
    AUTH_HOST: str
    ALGORITHM: str
    ACCESS_TYP: str
    ACCESS_KEY: str
    ACCESS_EXP: int
    REFRESH_TYP: str
    REFRESH_KEY: str
    REFRESH_EXP: int

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_prefix='JWT_',
        env_file=env_config.env_file,
        extra='ignore'
    )