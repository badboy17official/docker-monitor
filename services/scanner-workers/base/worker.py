"""
Base Worker class — Abstract base for all scanner workers
"""

import abc
import json
import logging
import os
import asyncio
from dataclasses import dataclass, field, asdict
from typing import Any, Optional
import aioredis

logger = logging.getLogger(__name__)


@dataclass
class JobMessage:
    """Message sent from orchestrator to worker via Redis queue"""
    job_id: str
    scan_id: str
    target_image: str
    worker_type: str
    policy: dict = field(default_factory=dict)


@dataclass
class WorkerResult:
    """Result sent from worker back to orchestrator via results queue"""
    job_id: str
    scan_id: str
    worker_type: str
    success: bool
    payload: dict = field(default_factory=dict)
    error: Optional[str] = None


class BaseWorker(abc.ABC):
    """
    Base contract for scanner workers.
    
    Each worker:
    1. Connects to Redis and listens on its queue key
    2. Deserializes job messages
    3. Calls execute() (implemented by subclass)
    4. Publishes results back to results queue
    5. Updates job status via database or direct queue updates
    """

    QUEUE_KEY: str = ""  # Override in subclass, e.g. "queue:trivy"
    RESULTS_KEY = "queue:results"
    HEARTBEAT_INTERVAL = 10  # seconds

    def __init__(self) -> None:
        self._redis: Optional[aioredis.Redis] = None

    async def connect(self) -> None:
        """Establish Redis connection"""
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")
        try:
            self._redis = await aioredis.from_url(redis_url, decode_responses=True)
            await self._redis.ping()
            logger.info("✅ Connected to Redis at %s", redis_url)
        except Exception as exc:
            logger.error("❌ Failed to connect to Redis: %s", exc)
            raise

    async def run(self) -> None:
        """Main worker loop — listen for jobs and process them"""
        await self.connect()
        logger.info(
            "🚀 %s worker listening on queue: %s",
            self.__class__.__name__,
            self.QUEUE_KEY
        )

        while True:
            try:
                # BLPOP blocks until a job is available (timeout to allow reconnection)
                raw = await self._redis.blpop(self.QUEUE_KEY, timeout=self.HEARTBEAT_INTERVAL)
                if raw is None:
                    # Timeout — can check health here if needed
                    continue

                _, payload = raw
                job = JobMessage(**json.loads(payload))
                await self._process(job)

            except aioredis.RedisError as exc:
                logger.error("❌ Redis error: %s — reconnecting in 2s", exc)
                await asyncio.sleep(2)
                try:
                    await self.connect()
                except Exception:
                    pass

            except Exception as exc:
                logger.exception("❌ Unhandled error processing job: %s", exc)

    async def _process(self, job: JobMessage) -> None:
        """
        Process a single job:
        1. Extract parameters
        2. Call worker-specific execute() method
        3. Publish result to results queue
        """
        logger.info(
            "🔍 Processing job %s: scanning %s (worker: %s)",
            job.job_id,
            job.target_image,
            self.QUEUE_KEY
        )

        try:
            payload = await self.execute(job)
            result = WorkerResult(
                job_id=job.job_id,
                scan_id=job.scan_id,
                worker_type=job.worker_type,
                success=True,
                payload=payload,
            )
            logger.info("✅ Job %s completed successfully", job.job_id)

        except Exception as exc:
            logger.exception("❌ Worker execution failed for job %s: %s", job.job_id, exc)
            result = WorkerResult(
                job_id=job.job_id,
                scan_id=job.scan_id,
                worker_type=job.worker_type,
                success=False,
                error=str(exc)[:500],  # truncate for database
            )

        await self._publish_result(result)

    async def _publish_result(self, result: WorkerResult) -> None:
        """Publish result back to orchestrator"""
        try:
            result_json = json.dumps(asdict(result))
            await self._redis.rpush(self.RESULTS_KEY, result_json)
            logger.info("📤 Published result for job %s", result.job_id)
        except Exception as exc:
            logger.error("❌ Failed to publish result for job %s: %s", result.job_id, exc)

    @abc.abstractmethod
    async def execute(self, job: JobMessage) -> dict[str, Any]:
        """
        Execute the scanning tool (implemented by subclass).
        
        Must return a normalized result dict with:
        - source_worker: str (e.g. 'trivy')
        - vulnerabilities or misconfigurations or components: list
        
        Must raise an exception on unrecoverable failure.
        """
        pass
