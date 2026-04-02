"""API routes for the Threat Intel Portal."""

import logging
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Header
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from src.models.database import get_db, User, Topic, Product, FeedItem
from src.services.auth import hash_password, verify_password, create_token, decode_token
from src.services.digest import build_digest

logger = logging.getLogger(__name__)

router = APIRouter()


# --- REQUEST/RESPONSE MODELS ---

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    display_name: str | None = None
    tier: str = "personal"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class SubscriptionUpdate(BaseModel):
    topic_slugs: list[str] = []
    product_slugs: list[str] = []
    digest_frequency: str = "daily"  # "daily", "weekly", "monthly"

class UserProfile(BaseModel):
    id: int
    email: str
    display_name: str | None
    tier: str
    digest_frequency: str
    subscribed_topics: list[str]
    subscribed_products: list[str]


# --- AUTH DEPENDENCY ---

def get_current_user(authorization: str = Header(None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header.")
    token = authorization.split(" ", 1)[1]
    try:
        payload = decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = db.query(User).filter(User.id == int(payload["sub"])).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or deactivated.")
    return user


# --- AUTH ROUTES ---

@router.post("/auth/signup", response_model=TokenResponse)
def signup(req: SignupRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered.")

    if len(req.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")

    user = User(
        email=req.email,
        hashed_password=hash_password(req.password),
        display_name=req.display_name,
        tier=req.tier,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_token(user.id, user.email)
    return TokenResponse(access_token=token)


@router.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_token(user.id, user.email)
    return TokenResponse(access_token=token)


# --- USER PROFILE ---

@router.get("/me", response_model=UserProfile)
def get_profile(user: User = Depends(get_current_user)):
    return UserProfile(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        tier=user.tier,
        digest_frequency=user.digest_frequency,
        subscribed_topics=[t.slug for t in user.subscribed_topics],
        subscribed_products=[p.slug for p in user.subscribed_products],
    )


# --- SUBSCRIPTIONS ---

@router.get("/topics")
def list_topics(db: Session = Depends(get_db)):
    topics = db.query(Topic).order_by(Topic.category, Topic.name).all()
    return [{"slug": t.slug, "name": t.name, "description": t.description, "category": t.category} for t in topics]


@router.get("/products")
def list_products(db: Session = Depends(get_db)):
    products = db.query(Product).order_by(Product.category, Product.name).all()
    return [{"slug": p.slug, "name": p.name, "vendor": p.vendor, "category": p.category} for p in products]


@router.put("/subscriptions")
def update_subscriptions(
    req: SubscriptionUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if req.digest_frequency not in ("daily", "weekly", "monthly"):
        raise HTTPException(status_code=422, detail="Frequency must be daily, weekly, or monthly.")

    # Resolve topics
    topics = db.query(Topic).filter(Topic.slug.in_(req.topic_slugs)).all()
    products = db.query(Product).filter(Product.slug.in_(req.product_slugs)).all()

    user.subscribed_topics = topics
    user.subscribed_products = products
    user.digest_frequency = req.digest_frequency
    db.commit()

    return {
        "subscribed_topics": [t.slug for t in topics],
        "subscribed_products": [p.slug for p in products],
        "digest_frequency": req.digest_frequency,
    }


# --- DIGEST PREVIEW ---

@router.get("/digest/preview")
def preview_digest(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Preview what the user's next digest would contain."""
    digest = build_digest(db, user)
    return {
        "item_count": digest["item_count"],
        "period": digest["period"],
        "sections": digest["sections"],
    }


# --- FEED BROWSE ---

@router.get("/feed")
def browse_feed(
    severity: str | None = None,
    topic: str | None = None,
    product: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
):
    """Browse recent feed items with optional filters."""
    query = db.query(FeedItem).order_by(FeedItem.published_at.desc())

    if severity:
        query = query.filter(FeedItem.severity == severity)
    if topic:
        query = query.filter(FeedItem.topic_slug == topic)
    if product:
        query = query.filter(FeedItem.product_slug == product)

    items = query.limit(min(limit, 100)).all()
    return [{
        "id": i.id,
        "title": i.title,
        "summary": i.summary,
        "url": i.url,
        "severity": i.severity,
        "cvss": i.cvss_score,
        "published": i.published_at.isoformat() if i.published_at else None,
        "tags": i.tags,
        "topic": i.topic_slug,
        "product": i.product_slug,
    } for i in items]
