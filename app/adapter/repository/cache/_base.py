from redis.asyncio import Redis
from redis.asyncio.client import Pipeline

from app.abc.repository.base import Repository

class RedisRepository(Repository):
    __repo_name__: str = "base"
    prefix: str = ""

    def __init__(self, conn: Redis | Pipeline):
        self.conn: Redis | Pipeline = conn