"""
CVE Enricher — Fetch EPSS + KEV data with Redis caching
"""

import asyncio
import json
import logging
from typing import Optional
import aiohttp
import aioredis

logger = logging.getLogger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_EPSS = 86400  # 24 hours
CACHE_TTL_KEV = 21600   # 6 hours


async def enrich_cves(
    cve_ids: list[str], 
    redis: aioredis.Redis
) -> dict[str, dict]:
    """
    Enrich CVEs with EPSS scores and KEV status.
    Returns: { cve_id: { epss_score: float | None, is_in_kev: bool } }
    
    Uses Redis cache to avoid hammering external APIs.
    """
    if not cve_ids:
        return {}

    missing = []
    enriched: dict[str, dict] = {}

    # Check cache
    for cve_id in cve_ids:
        try:
            cached = await redis.get(f"enrich:{cve_id}")
            if cached:
                enriched[cve_id] = json.loads(cached)
            else:
                missing.append(cve_id)
        except Exception as exc:
            logger.warning("Cache lookup failed for %s: %s", cve_id, exc)
            missing.append(cve_id)

    if not missing:
        return enriched

    # Fetch missing data
    logger.info("🔍 Fetching enrichment data for %d CVEs", len(missing))

    try:
        kev_set = await _get_kev_set(redis)
        epss_map = await _fetch_epss_batch(missing)
    except Exception as exc:
        logger.error("❌ Enrichment fetch failed: %s — returning empty scores", exc)
        # Fail gracefully — return zeros rather than blocking scan
        epss_map = {}
        kev_set = set()

    # Cache results
    for cve_id in missing:
        data = {
            "epss_score": epss_map.get(cve_id),
            "is_in_kev": cve_id in kev_set,
        }
        enriched[cve_id] = data
        try:
            await redis.setex(f"enrich:{cve_id}", CACHE_TTL_EPSS, json.dumps(data))
        except Exception as exc:
            logger.warning("Failed to cache enrichment for %s: %s", cve_id, exc)

    logger.info("✅ Enriched %d CVEs", len(missing))
    return enriched


async def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """
    Fetch EPSS scores from FIRST.org API in batches (API limit: ~100 per request).
    Returns: { cve_id: epss_score }
    """
    results: dict[str, float] = {}

    async with aiohttp.ClientSession() as session:
        for i in range(0, len(cve_ids), 100):
            chunk = cve_ids[i:i+100]
            params = {"cve": ",".join(chunk)}

            try:
                async with session.get(
                    EPSS_API,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status != 200:
                        logger.warning("EPSS API returned %d", resp.status)
                        continue

                    data = await resp.json()
                    for entry in data.get("data", []):
                        cve = entry.get("cve")
                        score = entry.get("epss")
                        if cve and score is not None:
                            results[cve] = float(score)

            except asyncio.TimeoutError:
                logger.warning("EPSS API timeout for batch %d", i // 100)
            except Exception as exc:
                logger.warning("EPSS API error: %s", exc)

    logger.info("✅ Fetched EPSS scores for %d CVEs", len(results))
    return results


async def _get_kev_set(redis: aioredis.Redis) -> set[str]:
    """
    Fetch CISA Known Exploited Vulnerabilities catalogue.
    Caches in Redis for 6 hours.
    """
    try:
        cached = await redis.get("kev:set")
        if cached:
            logger.info("✅ Using cached KEV set")
            return set(json.loads(cached))
    except Exception as exc:
        logger.warning("Cache lookup failed for KEV: %s", exc)

    logger.info("🔍 Fetching KEV catalogue from CISA...")

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                KEV_URL,
                timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    logger.warning("KEV API returned %d", resp.status)
                    return set()

                data = await resp.json(content_type=None)

        kev_set = {v["cveID"] for v in data.get("vulnerabilities", [])}
        logger.info("✅ Fetched %d CVEs from KEV catalogue", len(kev_set))

        # Cache
        try:
            await redis.setex("kev:set", CACHE_TTL_KEV, json.dumps(list(kev_set)))
        except Exception as exc:
            logger.warning("Failed to cache KEV set: %s", exc)

        return kev_set

    except Exception as exc:
        logger.error("❌ Failed to fetch KEV catalogue: %s — returning empty set", exc)
        return set()
