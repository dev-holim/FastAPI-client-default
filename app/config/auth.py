from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from .environment import env_config


class AuthConfig(BaseSettings):
    """Auth 설정"""
    HOST: str
    ALGORITHM: str

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_prefix='AUTH_',
        env_file=env_config.env_file,
        extra='ignore'
    )