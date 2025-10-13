import os
from typing import Optional

from app.core.enums import Environment


class EnvironmentConfig:
    """환경별 설정 관리 클래스"""
    
    def __init__(self):
        self._environment: Optional[Environment] = None
        self._env_file: Optional[str] = None
    
    @property
    def environment(self) -> Environment:
        """현재 환경 반환"""
        if self._environment is None:
            env_value = os.getenv("APP_ENV", Environment.LOCAL)
            try:
                self._environment = Environment(env_value)
            except ValueError:
                raise ValueError(f"Invalid environment: {env_value}. Must be one of {list(Environment)}")
        return self._environment
    
    @property
    def env_file(self) -> Optional[str]:
        """환경에 따른 .env 파일 경로 반환"""
        if self._env_file is None:
            if self.environment in [Environment.LOCAL, Environment.DEVELOPMENT]:
                self._env_file = ".env"
            else:
                self._env_file = None
        return self._env_file
    
    @property
    def is_local(self) -> bool:
        """로컬 환경 여부"""
        return self.environment == Environment.LOCAL
    
    @property
    def is_development(self) -> bool:
        """개발 환경 여부"""
        return self.environment in [Environment.LOCAL, Environment.DEVELOPMENT]
    
    @property
    def is_staging(self) -> bool:
        """스테이징 환경 여부"""
        return self.environment == Environment.STAGING
    
    @property
    def is_production(self) -> bool:
        """프로덕션 환경 여부"""
        return self.environment == Environment.PRODUCTION
    
    @property
    def debug_mode(self) -> bool:
        """디버그 모드 여부"""
        return self.is_development
    
    @property
    def log_level(self) -> str:
        """환경별 로그 레벨"""
        if self.is_production:
            return "WARNING"
        elif self.is_staging:
            return "INFO"
        else:
            return "DEBUG"


# 전역 환경 설정 인스턴스
env_config = EnvironmentConfig()
