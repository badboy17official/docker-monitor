"""
Runtime Monitor — Main application
"""

import asyncio
import logging
from contextlib import asynccontextmanager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app):
    """Lifecycle management"""
    logger.info("🚀 Runtime Monitor starting...")
    yield
    logger.info("🛑 Runtime Monitor shutting down...")


async def main():
    """Main entry point"""
    import os
    from .collectors.docker_stats import DockerStatsCollector
    from .detectors.anomaly import AnomalyDetector

    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")

    collector = DockerStatsCollector(redis_url)
    detector = AnomalyDetector()

    logger.info("🚀 Starting Runtime Monitor")

    try:
        await collector.connect()
        # Start collector in background
        asyncio.create_task(collector.collect_stats())

        # Keep the app running
        while True:
            await asyncio.sleep(60)

    except KeyboardInterrupt:
        logger.info("🛑 Runtime Monitor shutting down...")
    except Exception as exc:
        logger.error("❌ Error: %s", exc)
        return 1

    return 0


if __name__ == "__main__":
    import sys
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
