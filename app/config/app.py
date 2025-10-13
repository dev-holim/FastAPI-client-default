from pydantic import Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from .environment import env_config, Environment


class AppConfig(BaseSettings):
    """애플리케이션 전체 설정"""
    NAME: str = "FastAPI Application"
    VERSION: str = "1.0.0"
    SECRET_KEY: str = Field(..., min_length=32)

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_prefix='APP_',
        env_file=env_config.env_file,
        extra='ignore'
    )

