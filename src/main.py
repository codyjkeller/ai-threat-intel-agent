"""Threat Intel Portal — FastAPI Application.

Self-hosted threat intelligence digest service.
Aggregates CISA KEV, NVD CVEs, vendor advisories, and privacy news.
Users subscribe to topics and products, receive personalized digests.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.models.database import init_db
from src.models.seed import run_seed
from src.api.routes import router
from src.feeds.ingest import ingest_all_feeds

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)

INGEST_INTERVAL_HOURS = int(os.getenv("INGEST_INTERVAL_HOURS", "4"))


async def scheduled_ingestion():
    """Background task that runs feed ingestion on a fixed interval."""
    while True:
        try:
            logger.info("Running scheduled feed ingestion...")
            await ingest_all_feeds()
            logger.info("Feed ingestion complete.")
        except Exception as e:
            logger.error("Scheduled ingestion failed: %s", e)
        await asyncio.sleep(INGEST_INTERVAL_HOURS * 3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    # Startup
    logger.info("Initializing database...")
    init_db()
    run_seed()
    logger.info("Database ready. Seed data loaded.")

    # Start background ingestion
    task = asyncio.create_task(scheduled_ingestion())
    logger.info("Background ingestion scheduled every %d hours.", INGEST_INTERVAL_HOURS)

    yield

    # Shutdown
    task.cancel()
    logger.info("Shutting down.")


app = FastAPI(
    title="Threat Intel Portal",
    description=(
        "Self-hosted threat intelligence digest service. "
        "Subscribe to topics and products, receive personalized security briefings."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — adjust origins for your domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount routes
app.include_router(router, prefix="/api/v1")


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "service": "threat-intel-portal",
    }


DISCLAIMER = (
    "This service aggregates publicly available threat intelligence for informational purposes only. "
    "Subscribing to product-specific alerts does not indicate or acknowledge use of those products "
    "in your environment. This service is not a substitute for a formal threat intelligence program, "
    "incident response capability, or professional security advisory. Use at your own risk."
)


@app.get("/disclaimer")
def get_disclaimer():
    return {"disclaimer": DISCLAIMER}
