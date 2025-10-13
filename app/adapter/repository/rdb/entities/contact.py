from uuid import uuid4
from datetime import datetime

from sqlalchemy import String, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from ._base import Base


class Contact(Base):
    __tablename__ = 'tb_contact'

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, index=True, nullable=False)
    user_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )



    def __init__(
            self,
            user_id: UUID,
            title: str,
            description: str
    ):
        super().__init__()

        self.user_id: UUID = user_id
        self.id = uuid4()
        self.title = title
        self.description = description
