from typing import Optional, Dict, List

from .app import AppConfig
from .cache import RedisConfig
from .cors import CORSConfig
from .environment import env_config, Environment
from .rdb import RDBConfig
from .jwt import JWTConfig

class Settings:
    """중앙화된 설정 관리 클래스"""

    def __init__(self):
        self._app_config: Optional[AppConfig] = None
        self._database_config: Optional[RDBConfig] = None
        self._redis_config: Optional[RedisConfig] = None
        self._cors_config: Optional[CORSConfig] = None
        self._jwt_config: Optional[JWTConfig] = None

    @property
    def app(self) -> AppConfig:
        if self._app_config is None:
            self._app_config = AppConfig()
        return self._app_config

    @property
    def database(self) -> RDBConfig:
        if self._database_config is None:
            self._database_config = RDBConfig()
        return self._database_config

    @property
    def redis(self) -> RedisConfig:
        if self._redis_config is None:
            self._redis_config = RedisConfig()
        return self._redis_config

    @property
    def cors(self) -> CORSConfig:
        if self._cors_config is None:
            self._cors_config = CORSConfig()
        return self._cors_config

    @property
    def jwt(self) -> JWTConfig:
        if self._jwt_config is None:
            self._jwt_config = JWTConfig()
        return self._jwt_config


# 전역 설정 인스턴스
settings = Settings()

def get_cors_kwargs() -> Dict[str, List[str]]:
    origins, methods, headers = settings.cors.get_allowed_origins
    return {
        "allow_origins": origins,
        "allow_methods": methods,
        "allow_headers": headers,
    }


def get_database_url() -> str:
    """데이터베이스 URL 반환"""
    return settings.database.connection_string


def get_async_database_url() -> str:
    """비동기 데이터베이스 URL 반환"""
    return settings.database.async_connection_string


def get_redis_url() -> str:
    """Redis URL 반환"""
    return settings.redis.connection_string


def is_development() -> bool:
    """개발 환경 여부 확인"""
    return env_config.is_development


def is_production() -> bool:
    """프로덕션 환경 여부 확인"""
    return env_config.is_production


def is_local() -> bool:
    """로컬 환경 여부 확인"""
    return env_config.is_local


def is_staging() -> bool:
    """스테이징 환경 여부 확인"""
    return env_config.is_staging


def get_environment() -> Environment:
    """현재 환경 반환"""
    return env_config.environment


def get_log_level() -> str:
    """환경별 로그 레벨 반환"""
    return env_config.log_level


def is_debug_mode() -> bool:
    """디버그 모드 여부 확인"""
    return env_config.debug_mode
