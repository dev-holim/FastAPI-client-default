from typing import Optional, List, Type, Dict, Any, Self, Protocol, runtime_checkable

from redis.asyncio import Redis
from redis.asyncio.client import Pipeline

from app.config import settings
from app.abc.repository.base import UoW
from app.adapter.repository.cache._base import RedisRepository

class RedisClient:
    instance: Optional[Redis] = None

    @classmethod
    def get_instance(cls) -> Redis:
        if cls.instance is None:
            redis_config = settings.redis
            params: Dict[str, Any] = {
                "host": redis_config.HOST,
                "port": redis_config.PORT,
                "db": redis_config.DB,
            }
            if getattr(redis_config, "PASSWORD", None):
                params["password"] = redis_config.PASSWORD
                params["username"] = redis_config.USER

            cls.instance = Redis(**params)
        return cls.instance


def get_redis_client() -> Redis:
    return RedisClient.get_instance()

class CacheUoW(UoW):
    __client: Optional[Redis] = None

    @staticmethod
    def initialize_client(client: Redis) -> None:
        CacheUoW.__client = client

    def __init__(self, repositories: List[Type[RedisRepository]]):
        self._repositories = repositories
        self._bind_repositories: Dict[str, RedisRepository] = {}
        self._transactional: bool = True
        self._pipeline_kwargs: Dict[str, Any] | None = None
        self._active_conn: Redis | Pipeline | None = None

    def enter(self, transactional: bool = True, **pipeline_kwargs) -> Self:
        self._transactional = transactional
        self._pipeline_kwargs = pipeline_kwargs or None
        return self

    def __call__(self) -> Self:
        return self

    def __getattr__(self, item: str):
        return self._bind_repositories.get(item)

    async def __aenter__(self) -> "CacheUoW":
        if CacheUoW.__client is None:
            CacheUoW.__client = get_redis_client()

        assert CacheUoW.__client is not None, "Redis client is not initialized. Call initialize_client() first."

        if self._transactional:
            kwargs = self._pipeline_kwargs or {}
            self._active_conn = CacheUoW.__client.pipeline(transaction=True, **kwargs)
        else:
            self._active_conn = CacheUoW.__client

        self._bind_repositories = {
            repo.__repo_name__: repo(self._active_conn) for repo in self._repositories
        }
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._transactional and isinstance(self._active_conn, Pipeline):
            pipe: Pipeline = self._active_conn
            try:
                if exc_type is None:
                    # 정상 종료
                    await pipe.execute()
                else:
                    await pipe.reset()
            finally:
                pass

        # 바인딩 해제
        self._bind_repositories.clear()
        self._active_conn = None

async def init_cache() -> None:
    CacheUoW.initialize_client(get_redis_client())

