"""OSV.dev CVE enrichment with parallel fetching and caching."""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

from docker_monitor.config import Config

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    requests = None


class CloudCVEFetcher:
    """Fetch CVE severity data from OSV.dev with local caching."""

    def __init__(self, config: Config):
        cloud = config.cloud
        self.enabled = cloud.get("enabled", False)
        self.sync_interval_hours = cloud.get("sync_interval_hours", 6)
        self.max_concurrent = cloud.get("max_concurrent_fetches", 5)
        self.cache_file = Path("cve_cache.json")

    def _is_cache_stale(self) -> bool:
        if not self.cache_file.exists():
            return True
        age_hours = (time.time() - self.cache_file.stat().st_mtime) / 3600
        return age_hours > self.sync_interval_hours

    def _load_cache(self) -> Dict[str, Any]:
        if not self.cache_file.exists():
            return {}
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_cache(self, data: Dict[str, Any]):
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(data, f)

    def _fetch_single(self, cve_id: str) -> tuple[str, str]:
        """Fetch a single CVE from OSV.dev."""
        try:
            resp = requests.get(f"https://api.osv.dev/v1/vulns/{cve_id}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for severity in data.get("severity", []):
                    if severity.get("type") == "CVSS_V3":
                        return cve_id, severity.get("score", "UNKNOWN")
                return cve_id, "UNKNOWN"
            return cve_id, "NOT_FOUND"
        except Exception as e:
            logger.warning(f"Failed to fetch {cve_id} from OSV.dev: {e}")
            return cve_id, "ERROR"

    def fetch_severity(self, cve_ids: List[str]) -> Dict[str, str]:
        """Fetch severities for CVE IDs, using cache and parallel OSV.dev requests."""
        if not self.enabled or not requests:
            return {}

        cache = self._load_cache()
        stale = self._is_cache_stale()

        results = {}
        to_fetch = []

        for cve in cve_ids:
            if cve in cache and not stale:
                results[cve] = cache[cve]
            else:
                to_fetch.append(cve)

        if not to_fetch:
            return results

        logger.info(f"Fetching cloud CVE data for {len(to_fetch)} items via OSV.dev")

        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = {executor.submit(self._fetch_single, cve): cve for cve in to_fetch}
            for future in as_completed(futures):
                try:
                    cve_id, severity = future.result(timeout=10)
                    cache[cve_id] = severity
                    results[cve_id] = severity
                except Exception as e:
                    cve_id = futures[future]
                    logger.warning(f"CVE fetch failed for {cve_id}: {e}")

        if to_fetch:
            self._save_cache(cache)

        return results
