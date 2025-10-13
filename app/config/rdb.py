from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from .environment import env_config


class RDBConfig(BaseSettings):
    """데이터베이스 설정"""
    HOST: str = "localhost"
    PORT: int = 5432
    USER: str = "postgres"
    NAME: str = ""
    PASSWORD: str = Field(..., min_length=1)
    SCHEMA: str = "public"
    POOL_SIZE: int = 10
    MAX_OVERFLOW: int = 20
    POOL_TIMEOUT: int = 30
    POOL_RECYCLE: int = 3600

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_prefix='DB_',
        env_file=env_config.env_file,
        extra='ignore'
    )

    @property
    def connection_string(self) -> str:
        """데이터베이스 연결 문자열 생성"""
        return f"postgresql://{self.USER}:{self.PASSWORD}@{self.HOST}:{self.PORT}/{self.NAME}"

    @property
    def async_connection_string(self) -> str:
        """비동기 데이터베이스 연결 문자열 생성"""
        # f'{dbms}+{driver}://{username}:{password}@{host}:{port}/{database}'
        return f"postgresql+asyncpg://{self.USER}:{self.PASSWORD}@{self.HOST}:{self.PORT}/{self.NAME}"