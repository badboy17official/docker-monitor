"""
Docker Stats Collector — Stream container metrics every 15 seconds
"""

import asyncio
import json
import logging
import time
from typing import Optional
import docker
import aioredis

logger = logging.getLogger(__name__)
METRICS_STREAM_KEY = "stream:container_metrics"
POLL_INTERVAL = 15  # seconds


class DockerStatsCollector:
    """Collects Docker container statistics and publishes to Redis stream"""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self.redis: Optional[aioredis.Redis] = None
        self.docker_client: Optional[docker.DockerClient] = None

    async def connect(self) -> None:
        """Initialize connections"""
        try:
            self.redis = await aioredis.from_url(self.redis_url, decode_responses=True)
            self.docker_client = docker.from_env()
            logger.info("✅ Connected to Docker and Redis")
        except Exception as exc:
            logger.error("❌ Failed to initialize: %s", exc)
            raise

    async def collect_stats(self) -> None:
        """Main loop — poll container stats periodically"""
        await self.connect()
        logger.info("🚀 Docker stats collector started, polling every %ds", POLL_INTERVAL)

        while True:
            try:
                containers = self.docker_client.containers.list()
                tasks = [self._collect_one(c) for c in containers]
                await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(POLL_INTERVAL)

            except docker.errors.DockerException as exc:
                logger.error("❌ Docker API error: %s", exc)
                await asyncio.sleep(5)

            except Exception as exc:
                logger.exception("❌ Unexpected error: %s", exc)
                await asyncio.sleep(5)

    async def _collect_one(self, container) -> None:
        """Collect stats for a single container"""
        try:
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(
                None,
                lambda: container.stats(stream=False),
            )
            metric = self._normalize(container.id[:12], container.name, raw)
            await self.redis.rpush(METRICS_STREAM_KEY, json.dumps(metric))

        except Exception as exc:
            logger.warning("Failed to collect stats for %s: %s", container.name, exc)

    @staticmethod
    def _normalize(container_id: str, container_name: str, raw: dict) -> dict:
        """Normalize Docker stats to standard format"""
        cpu_pct = DockerStatsCollector._calc_cpu_percent(raw)
        mem_usage = raw.get("memory_stats", {}).get("usage", 0)
        mem_limit = raw.get("memory_stats", {}).get("limit", 1)
        mem_pct = round(mem_usage / mem_limit * 100, 2) if mem_limit else 0.0

        return {
            "container_id":   container_id,
            "container_name": container_name,
            "cpu_pct":        cpu_pct,
            "mem_pct":        mem_pct,
            "mem_usage_mb":   round(mem_usage / 1_048_576, 2),
            "timestamp":      int(time.time()),
        }

    @staticmethod
    def _calc_cpu_percent(stats: dict) -> float:
        """Calculate CPU usage as percentage of available CPUs"""
        try:
            cpu_delta = (
                stats["cpu_stats"]["cpu_usage"]["total_usage"]
                - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            )
            sys_delta = (
                stats["cpu_stats"]["system_cpu_usage"]
                - stats["precpu_stats"]["system_cpu_usage"]
            )
            num_cpus = len(stats["cpu_stats"]["cpu_usage"].get("percpu_usage") or [1])

            if sys_delta <= 0 or cpu_delta < 0:
                return 0.0

            return round((cpu_delta / sys_delta) * num_cpus * 100.0, 2)

        except (KeyError, ZeroDivisionError, TypeError):
            return 0.0
