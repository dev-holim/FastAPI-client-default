from uuid import uuid4
from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID

from ._base import Base


class User(Base):
    __tablename__ = 'tb_user'

    id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(150), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_approved : Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False
    )


    def __init__(
            self,
            name: str,
            role: str,
            email: str,
            password: str,
            is_active: bool = True,
            is_approved: bool = False
    ):
        super().__init__()

        self.id = uuid4()
        self.name = name
        self.role = role
        self.email = email
        self.password = password
        self.is_active = is_active
        self.is_approved = is_approved
        self.created_at = datetime.now()
