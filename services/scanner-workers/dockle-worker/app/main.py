"""
Dockle Worker — Main entry point
"""

import asyncio
import logging
import sys
import json
import tempfile
import os

sys.path.insert(0, '/app/services/scanner-workers')

from base.worker import BaseWorker, JobMessage

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DOCKLE_PATH = os.environ.get("DOCKLE_PATH", "dockle")
MAX_TIMEOUT = int(os.environ.get("DOCKLE_TIMEOUT", "120"))


async def run_dockle_scan(target_image: str) -> dict:
    """
    Invoke dockle as subprocess, capture JSON output.
    Returns normalised misconfig results.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    cmd = [
        DOCKLE_PATH,
        "--format", "json",
        "--output", output_path,
        "--exit-level", "ignore",  # Capture everything
        target_image,
    ]

    logger.info("🔍 Running dockle: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=MAX_TIMEOUT)
    except asyncio.TimeoutError:
        proc.kill()
        logger.error("❌ Dockle scan timed out")
        raise RuntimeError("Dockle scan timed out")

    # Dockle exits 1 when issues found — that's expected
    if proc.returncode not in (0, 1):
        error_msg = stderr.decode()[:500] if stderr else "unknown error"
        logger.error("❌ Dockle failed: %s", error_msg)
        raise RuntimeError(f"Dockle failed: {error_msg}")

    try:
        with open(output_path) as f:
            raw = json.load(f)
        os.unlink(output_path)
    except Exception as exc:
        logger.error("❌ Failed to read dockle output: %s", exc)
        raise

    details = []
    for item in raw.get("details", []):
        details.append({
            "check_id":    item.get("code"),
            "title":       item.get("title"),
            "severity":    item.get("level", "INFO").upper(),
            "description": item.get("details"),
            "remediation": item.get("alert"),
        })

    logger.info("✅ Parsed %d misconfigurations from dockle output", len(details))

    return {
        "source_worker": "dockle",
        "misconfigurations": details,
        "total_count": len(details),
    }


class DockleWorker(BaseWorker):
    """Dockle misconfig scanner worker"""

    QUEUE_KEY = "queue:dockle"

    async def execute(self, job: JobMessage) -> dict:
        """Run dockle scan and return results"""
        return await run_dockle_scan(job.target_image)


async def main():
    """Main entry point"""
    worker = DockleWorker()
    try:
        await worker.run()
    except KeyboardInterrupt:
        logger.info("🛑 Dockle worker shutting down...")
    except Exception as exc:
        logger.error("❌ Worker error: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
