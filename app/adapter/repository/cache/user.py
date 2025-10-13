from typing import Optional
from redis.asyncio.client import Pipeline

from app.adapter.repository.cache._base import RedisRepository
from app.config import settings


class UserTokenRepo(RedisRepository):
    __repo_name__ = "user_token_repo"
    prefix: str = "user_"

    async def get_user_hash(self, user_id: str) -> Optional[str]:
        if isinstance(self.conn, Pipeline):
            return None

        val: Optional[bytes] = await self.conn.get(
            f"{self.prefix}{user_id}"
        )
        return val.decode("utf-8") if val is not None else None

    async def set_user_hash(self, user_id: str, value: str, ex: int | None = settings.redis.EXP) -> bool:
        if isinstance(self.conn, Pipeline):
            await self.conn.set(
                f"{self.prefix}{user_id}",
                value,
                ex=ex
            )
            return True
        else:
            return bool(
                await self.conn.set(
                    f"{self.prefix}{user_id}",
                    value,
                    ex=ex
                )
            )

    async def delete_refresh_token(self, uid: str | int) -> int:
        key = f"{self.prefix}{uid}"
        if isinstance(self.conn, Pipeline):
            self.conn.delete(key)
            return 1
        else:
            return int(
                await self.conn.delete(key)
            )
