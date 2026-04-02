"""Feed ingestion service.

Fetches threat intelligence from public sources:
- CISA Known Exploited Vulnerabilities (KEV) catalog
- NVD CVE API (CVSS >= 7.0)
- RSS feeds (security news, vendor advisories, privacy)
"""

import logging
import hashlib
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Optional

import httpx

from src.models.database import SessionLocal, FeedSource, FeedItem

logger = logging.getLogger(__name__)

FETCH_TIMEOUT = 30.0
NVD_CVSS_THRESHOLD = 7.0


async def ingest_all_feeds():
    """Run ingestion across all active feed sources."""
    db = SessionLocal()
    try:
        sources = db.query(FeedSource).filter(FeedSource.is_active == True).all()
        logger.info("Starting feed ingestion for %d active sources.", len(sources))

        for source in sources:
            try:
                if source.source_type == "cisa_kev":
                    count = await ingest_cisa_kev(db, source)
                elif source.source_type == "nvd":
                    count = await ingest_nvd(db, source)
                elif source.source_type == "rss":
                    count = await ingest_rss(db, source)
                else:
                    logger.warning("Unknown source type: %s", source.source_type)
                    continue

                source.last_fetched = datetime.now(timezone.utc)
                db.commit()
                logger.info("Ingested %d items from %s", count, source.name)

            except Exception as e:
                logger.error("Failed to ingest %s: %s", source.name, e)
                db.rollback()

    finally:
        db.close()


async def ingest_cisa_kev(db, source: FeedSource) -> int:
    """Ingest CISA Known Exploited Vulnerabilities catalog."""
    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
        resp = await client.get(source.url)
        resp.raise_for_status()
        data = resp.json()

    count = 0
    for vuln in data.get("vulnerabilities", []):
        ext_id = vuln.get("cveID", "")
        if not ext_id:
            continue

        exists = db.query(FeedItem).filter(FeedItem.external_id == ext_id).first()
        if exists:
            continue

        pub_date = None
        if vuln.get("dateAdded"):
            try:
                pub_date = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            except ValueError:
                pass

        # Only ingest items from the last 30 days to avoid flooding on first run
        if pub_date and pub_date < datetime.now(timezone.utc) - timedelta(days=30):
            continue

        item = FeedItem(
            source_id=source.id,
            external_id=ext_id,
            title=f"{ext_id}: {vuln.get('vulnerabilityName', 'Unknown')}",
            summary=vuln.get("shortDescription", ""),
            url=f"https://nvd.nist.gov/vuln/detail/{ext_id}",
            severity="critical",  # KEV = actively exploited
            published_at=pub_date,
            tags=["cisa-kev", "actively-exploited"],
            topic_slug=source.topic_slug,
            product_slug=source.product_slug,
        )
        db.add(item)
        count += 1

    db.commit()
    return count


async def ingest_nvd(db, source: FeedSource) -> int:
    """Ingest recent high/critical CVEs from NVD API 2.0."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": start,
        "pubEndDate": end,
        "cvssV3Severity": "HIGH",  # HIGH and CRITICAL
        "resultsPerPage": 50,
    }

    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT) as client:
        resp = await client.get(source.url, params=params)
        resp.raise_for_status()
        data = resp.json()

    count = 0
    for item_data in data.get("vulnerabilities", []):
        cve = item_data.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue

        exists = db.query(FeedItem).filter(FeedItem.external_id == cve_id).first()
        if exists:
            continue

        # Extract CVSS score
        cvss_score = _extract_cvss(cve)
        if cvss_score and float(cvss_score) < NVD_CVSS_THRESHOLD:
            continue

        # Extract description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        severity = "critical" if cvss_score and float(cvss_score) >= 9.0 else "high"

        pub_date = None
        if cve.get("published"):
            try:
                pub_date = datetime.fromisoformat(cve["published"].replace("Z", "+00:00"))
            except ValueError:
                pass

        item = FeedItem(
            source_id=source.id,
            external_id=cve_id,
            title=f"{cve_id} (CVSS {cvss_score or '?'})",
            summary=desc[:500] if desc else "",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            severity=severity,
            cvss_score=cvss_score,
            published_at=pub_date,
            tags=["nvd", "cve"],
            topic_slug=source.topic_slug,
            product_slug=source.product_slug,
        )
        db.add(item)
        count += 1

    db.commit()
    return count


def _extract_cvss(cve: dict) -> Optional[str]:
    """Extract the highest CVSS v3.x score from a CVE record."""
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30"]:
        entries = metrics.get(key, [])
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return str(score)
    return None


async def ingest_rss(db, source: FeedSource) -> int:
    """Ingest items from an RSS/Atom feed."""
    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=True) as client:
        resp = await client.get(source.url)
        resp.raise_for_status()

    count = 0
    try:
        root = ET.fromstring(resp.text)
    except ET.ParseError as e:
        logger.error("RSS parse error for %s: %s", source.name, e)
        return 0

    # Handle both RSS 2.0 and Atom
    items = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry")

    for entry in items[:20]:  # Cap at 20 per fetch
        title = _get_text(entry, "title") or _get_text(entry, "{http://www.w3.org/2005/Atom}title") or ""
        link = _get_text(entry, "link") or ""
        if not link:
            link_el = entry.find("{http://www.w3.org/2005/Atom}link")
            if link_el is not None:
                link = link_el.get("href", "")

        description = _get_text(entry, "description") or _get_text(entry, "{http://www.w3.org/2005/Atom}summary") or ""
        pub_date_str = _get_text(entry, "pubDate") or _get_text(entry, "{http://www.w3.org/2005/Atom}updated") or ""

        if not title:
            continue

        # Generate a stable external ID from title + link
        ext_id = hashlib.sha256(f"{title}{link}".encode()).hexdigest()[:16]

        exists = db.query(FeedItem).filter(FeedItem.external_id == ext_id).first()
        if exists:
            continue

        pub_date = _parse_date(pub_date_str)

        # Skip items older than 7 days
        if pub_date and pub_date < datetime.now(timezone.utc) - timedelta(days=7):
            continue

        # Strip HTML from description
        clean_desc = _strip_html(description)[:500]

        item = FeedItem(
            source_id=source.id,
            external_id=ext_id,
            title=title[:300],
            summary=clean_desc,
            url=link,
            severity="info",
            published_at=pub_date,
            tags=["rss", source.name.lower().replace(" ", "-")],
            topic_slug=source.topic_slug,
            product_slug=source.product_slug,
        )
        db.add(item)
        count += 1

    db.commit()
    return count


def _get_text(element, tag: str) -> Optional[str]:
    el = element.find(tag)
    return el.text.strip() if el is not None and el.text else None


def _strip_html(text: str) -> str:
    """Rough HTML tag stripper."""
    import re
    return re.sub(r"<[^>]+>", "", text).strip()


def _parse_date(date_str: str) -> Optional[datetime]:
    """Best-effort date parsing for RSS feeds."""
    if not date_str:
        return None
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None
