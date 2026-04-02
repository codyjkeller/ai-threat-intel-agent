"""Database models for the Threat Intel Portal."""

import os
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Boolean,
    DateTime, ForeignKey, Table, JSON
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/threatintel.db")

Base = declarative_base()
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --- ASSOCIATION TABLES ---

user_topics = Table(
    "user_topics", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("topic_id", Integer, ForeignKey("topics.id"), primary_key=True),
)

user_products = Table(
    "user_products", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
    Column("product_id", Integer, ForeignKey("products.id"), primary_key=True),
)


# --- MODELS ---

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    display_name = Column(String, nullable=True)
    tier = Column(String, default="personal")  # "personal" or "professional"
    digest_frequency = Column(String, default="daily")  # "daily", "weekly", "monthly"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_digest_sent = Column(DateTime, nullable=True)

    # Relationships
    subscribed_topics = relationship("Topic", secondary=user_topics, back_populates="subscribers")
    subscribed_products = relationship("Product", secondary=user_products, back_populates="subscribers")


class Topic(Base):
    __tablename__ = "topics"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    category = Column(String, default="security")  # "security", "privacy", "compliance"

    subscribers = relationship("User", secondary=user_topics, back_populates="subscribed_topics")


class Product(Base):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True, index=True)
    slug = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    vendor = Column(String, nullable=False)
    advisory_url = Column(String, nullable=True)  # RSS/API endpoint for advisories
    category = Column(String, default="cloud")  # "cloud", "identity", "endpoint", "network", etc.

    subscribers = relationship("User", secondary=user_products, back_populates="subscribed_products")


class FeedSource(Base):
    __tablename__ = "feed_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    source_type = Column(String, nullable=False)  # "cisa_kev", "nvd", "rss", "api"
    url = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    last_fetched = Column(DateTime, nullable=True)
    topic_slug = Column(String, nullable=True)  # maps items to a topic
    product_slug = Column(String, nullable=True)  # maps items to a product


class FeedItem(Base):
    __tablename__ = "feed_items"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("feed_sources.id"), nullable=False)
    external_id = Column(String, unique=True, index=True, nullable=False)  # CVE ID, advisory ID, etc.
    title = Column(String, nullable=False)
    summary = Column(Text, nullable=True)
    url = Column(String, nullable=True)
    severity = Column(String, nullable=True)  # "critical", "high", "medium", "low", "info"
    cvss_score = Column(String, nullable=True)
    published_at = Column(DateTime, nullable=True)
    ingested_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    tags = Column(JSON, default=list)  # ["ransomware", "aws", "zero-day", etc.]
    topic_slug = Column(String, nullable=True)
    product_slug = Column(String, nullable=True)

    source = relationship("FeedSource")


class DigestLog(Base):
    __tablename__ = "digest_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    sent_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    item_count = Column(Integer, default=0)
    frequency = Column(String, nullable=False)
    status = Column(String, default="sent")  # "sent", "failed", "skipped"

    user = relationship("User")


# --- INIT ---

def init_db():
    """Create all tables."""
    os.makedirs("data", exist_ok=True)
    Base.metadata.create_all(bind=engine)
