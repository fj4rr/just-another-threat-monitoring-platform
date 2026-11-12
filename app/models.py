from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(256), default="")
    role: Mapped[str] = mapped_column(String(16), default="analyst")  # admin | analyst | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[object] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    kind: Mapped[str] = mapped_column(String(32))  # rss | bluesky | x | otx | urlscan | anyrun
    category: Mapped[str] = mapped_column(String(16))  # news | social | intel
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_minutes: Mapped[int] = mapped_column(Integer, default=30)
    last_run: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(16), default="never")  # ok | error | skipped | never
    last_error: Mapped[str] = mapped_column(Text, default="")
    items_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Item(Base):
    """A single piece of collected content: news article, social post, OTX pulse, scan..."""

    __tablename__ = "items"
    __table_args__ = (
        UniqueConstraint("source_id", "external_id", name="uq_item_source_ext"),
        Index("ix_items_published", "published_at"),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("sources.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="article")  # article | post | pulse | scan | analysis
    external_id: Mapped[str] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(String(1024), default="")
    url: Mapped[str] = mapped_column(String(2048), default="")
    author: Mapped[str] = mapped_column(String(256), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    published_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    severity: Mapped[int] = mapped_column(Integer, default=0)  # 0-100 heuristic
    raw: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_summary: Mapped[str] = mapped_column(Text, default="")
    llm_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    source: Mapped[Source] = relationship(lazy="joined")
    entity_links: Mapped[list[ItemEntity]] = relationship(
        back_populates="item", cascade="all, delete-orphan"
    )


class Entity(Base):
    """Something worth tracking across sources: a malware family, actor, CVE or IOC."""

    __tablename__ = "entities"
    __table_args__ = (UniqueConstraint("type", "value", name="uq_entity_type_value"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[str] = mapped_column(String(16), index=True)
    # malware | actor | cve | ip | domain | url | md5 | sha1 | sha256 | technique
    value: Mapped[str] = mapped_column(String(2048))  # normalized (lowercase etc.)
    display: Mapped[str] = mapped_column(String(2048), default="")
    category: Mapped[str] = mapped_column(String(32), default="")  # ransomware | stealer | rat ...
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    mention_count: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(16), default="")  # malicious | suspicious | clean | unknown
    meta: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_brief: Mapped[str] = mapped_column(Text, default="")
    llm_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    enriched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ItemEntity(Base):
    __tablename__ = "item_entities"
    __table_args__ = (UniqueConstraint("item_id", "entity_id", name="uq_item_entity"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    item_id: Mapped[int] = mapped_column(ForeignKey("items.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    origin: Mapped[str] = mapped_column(String(16), default="regex")  # regex | kb | feed | llm

    item: Mapped[Item] = relationship(back_populates="entity_links")
    entity: Mapped[Entity] = relationship(lazy="joined")


class EntityLink(Base):
    """Relationship discovered by enrichment, e.g. hash -> malware family (from VT)."""

    __tablename__ = "entity_links"
    __table_args__ = (UniqueConstraint("src_id", "dst_id", "provider", name="uq_entity_link"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    src_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    dst_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    relation: Mapped[str] = mapped_column(String(32), default="related")
    provider: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Enrichment(Base):
    __tablename__ = "enrichments"
    __table_args__ = (UniqueConstraint("entity_id", "provider", name="uq_enrichment"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(32))  # virustotal | otx | urlscan | anyrun
    verdict: Mapped[str] = mapped_column(String(16), default="unknown")
    score: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    permalink: Mapped[str] = mapped_column(String(2048), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Insight(Base):
    __tablename__ = "insights"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # digest | answer
    title: Mapped[str] = mapped_column(String(512), default="")
    content: Mapped[str] = mapped_column(Text, default="")
    model: Mapped[str] = mapped_column(String(128), default="")
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Watch(Base):
    __tablename__ = "watchlist"
    __table_args__ = (UniqueConstraint("user_id", "entity_id", name="uq_watch"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    entity_id: Mapped[int] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    entity: Mapped[Entity] = relationship(lazy="joined")


class CollectorRun(Base):
    __tablename__ = "collector_runs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job: Mapped[str] = mapped_column(String(64))  # source:<id> | enrichment | digest
    source_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")
    new_items: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[str] = mapped_column(Text, default="")


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text, default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
