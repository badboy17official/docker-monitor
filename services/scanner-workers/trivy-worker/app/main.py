"""
Trivy Worker — Main entry point
"""

import asyncio
import logging
import sys

# Add parent directory to path to import base worker
sys.path.insert(0, '/app/services/scanner-workers')

from base.worker import BaseWorker, JobMessage
from .runner import run_trivy_scan

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TrivyWorker(BaseWorker):
    """Trivy vulnerability scanner worker"""

    QUEUE_KEY = "queue:trivy"

    async def execute(self, job: JobMessage) -> dict:
        """Run trivy scan and return normalised results"""
        return await run_trivy_scan(job.target_image)


async def main():
    """Main entry point"""
    worker = TrivyWorker()
    try:
        await worker.run()
    except KeyboardInterrupt:
        logger.info("🛑 Trivy worker shutting down...")
    except Exception as exc:
        logger.error("❌ Worker error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
