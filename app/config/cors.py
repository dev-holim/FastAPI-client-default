from typing import List, Dict

from pydantic import Field, validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from .environment import env_config, Environment


class CORSConfig(BaseSettings):
    """애플리케이션 전체 설정"""
    ORIGINS :str = "*"
    METHODS :str = "*"
    HEADERS :str = "*"

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_prefix='CORS_ALLOWED_',
        env_file=env_config.env_file,
        extra='ignore'
    )

    @property
    def get_allowed_origins(self):
        origins = self.ORIGINS.split(',')
        methods = self.METHODS.split(',')
        headers = self.HEADERS.split(',')

        return origins, methods, headers