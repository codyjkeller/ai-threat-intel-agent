"""Digest builder service.

Assembles personalized threat intelligence digests based on each user's
subscribed topics, products, and delivery frequency. Outputs structured
digest data ready for email rendering.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session

from src.models.database import User, FeedItem, DigestLog

logger = logging.getLogger(__name__)

FREQUENCY_HOURS = {
    "daily": 24,
    "weekly": 168,
    "monthly": 720,
}


def get_users_due_for_digest(db: Session) -> list[User]:
    """Return users whose next digest is due based on their frequency setting."""
    now = datetime.now(timezone.utc)
    due_users = []

    users = db.query(User).filter(User.is_active == True).all()
    for user in users:
        hours = FREQUENCY_HOURS.get(user.digest_frequency, 24)
        if user.last_digest_sent is None:
            due_users.append(user)
        elif (now - user.last_digest_sent).total_seconds() >= hours * 3600:
            due_users.append(user)

    return due_users


def build_digest(db: Session, user: User) -> dict[str, Any]:
    """Build a personalized digest for a single user.

    Returns a dict with structured sections ready for template rendering.
    """
    hours = FREQUENCY_HOURS.get(user.digest_frequency, 24)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Collect topic slugs and product slugs the user subscribes to
    topic_slugs = [t.slug for t in user.subscribed_topics]
    product_slugs = [p.slug for p in user.subscribed_products]

    if not topic_slugs and not product_slugs:
        return {"user": user, "sections": [], "item_count": 0}

    # Query feed items matching subscriptions
    query = db.query(FeedItem).filter(FeedItem.ingested_at >= cutoff)

    topic_items = []
    product_items = []

    if topic_slugs:
        topic_items = query.filter(FeedItem.topic_slug.in_(topic_slugs)).order_by(
            FeedItem.published_at.desc()
        ).limit(30).all()

    if product_slugs:
        product_items = query.filter(FeedItem.product_slug.in_(product_slugs)).order_by(
            FeedItem.published_at.desc()
        ).limit(20).all()

    # Deduplicate
    seen_ids = set()
    all_items = []
    for item in topic_items + product_items:
        if item.id not in seen_ids:
            seen_ids.add(item.id)
            all_items.append(item)

    # Group into sections
    sections = _group_items(all_items)

    return {
        "user": user,
        "sections": sections,
        "item_count": len(all_items),
        "period": user.digest_frequency,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _group_items(items: list[FeedItem]) -> list[dict[str, Any]]:
    """Group feed items into display sections by severity and type."""
    critical = [i for i in items if i.severity in ("critical",)]
    high = [i for i in items if i.severity in ("high",)]
    other = [i for i in items if i.severity not in ("critical", "high")]

    sections = []

    if critical:
        sections.append({
            "title": "Critical Alerts",
            "icon": "🚨",
            "items": [_serialize_item(i) for i in critical],
        })

    if high:
        sections.append({
            "title": "High Severity",
            "icon": "⚠️",
            "items": [_serialize_item(i) for i in high],
        })

    if other:
        sections.append({
            "title": "News & Advisories",
            "icon": "📰",
            "items": [_serialize_item(i) for i in other],
        })

    return sections


def _serialize_item(item: FeedItem) -> dict[str, Any]:
    return {
        "title": item.title,
        "summary": item.summary or "",
        "url": item.url or "",
        "severity": item.severity or "info",
        "cvss": item.cvss_score,
        "published": item.published_at.strftime("%b %d, %Y") if item.published_at else "",
        "tags": item.tags or [],
    }


def log_digest_sent(db: Session, user: User, item_count: int):
    """Record that a digest was sent to a user."""
    now = datetime.now(timezone.utc)
    log = DigestLog(
        user_id=user.id,
        item_count=item_count,
        frequency=user.digest_frequency,
        status="sent",
    )
    db.add(log)
    user.last_digest_sent = now
    db.commit()
