"""
Trivy Worker Runner — Subprocess invocation and output parsing
"""

import asyncio
import json
import logging
import os
import shlex
import tempfile
from typing import Any
import re

logger = logging.getLogger(__name__)

TRIVY_PATH = os.environ.get("TRIVY_PATH", "trivy")
TRIVY_CACHE_DIR = os.environ.get("TRIVY_CACHE_DIR", "/tmp/trivy-cache")
MAX_TIMEOUT_SECONDS = int(os.environ.get("TRIVY_TIMEOUT", "300"))


async def run_trivy_scan(target_image: str) -> dict[str, Any]:
    """
    Invoke trivy as a subprocess, capture JSON output.
    Returns normalised vulnerability list.
    Raises RuntimeError on non-zero exit.
    """
    # Validate image reference to prevent command injection
    safe_image = _validate_image_ref(target_image)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        output_path = tmp.name

    cmd = [
        TRIVY_PATH, "image",
        "--format", "json",
        "--output", output_path,
        "--cache-dir", TRIVY_CACHE_DIR,
        "--timeout", f"{MAX_TIMEOUT_SECONDS}s",
        "--exit-code", "0",   # Don't fail on vulns found
        safe_image,
    ]

    logger.info("🔍 Running trivy: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=MAX_TIMEOUT_SECONDS + 10
        )
    except asyncio.TimeoutError:
        proc.kill()
        logger.error("❌ Trivy scan timed out for %s", safe_image)
        raise RuntimeError(f"Trivy scan timed out for {safe_image}")

    if proc.returncode not in (0, 1):  # 1 = vulns found (expected)
        error_msg = stderr.decode()[:500] if stderr else "unknown error"
        logger.error("❌ Trivy failed with exit code %d: %s", proc.returncode, error_msg)
        raise RuntimeError(f"Trivy exited {proc.returncode}: {error_msg}")

    try:
        with open(output_path) as f:
            raw = json.load(f)
        os.unlink(output_path)
    except Exception as exc:
        logger.error("❌ Failed to read trivy output: %s", exc)
        raise

    return parse_trivy_output(raw)


def parse_trivy_output(raw: dict) -> dict[str, Any]:
    """Flatten trivy JSON → internal vulnerability schema."""
    vulnerabilities = []

    for result in raw.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            vulnerabilities.append({
                "cve_id":        vuln.get("VulnerabilityID"),
                "package_name":  vuln.get("PkgName"),
                "installed_ver": vuln.get("InstalledVersion"),
                "fixed_ver":     vuln.get("FixedVersion"),
                "severity":      vuln.get("Severity", "UNKNOWN").upper(),
                "cvss_score":    _extract_cvss(vuln),
                "title":         vuln.get("Title"),
                "description":   vuln.get("Description"),
                "references":    vuln.get("References", []),
            })

    logger.info("✅ Parsed %d vulnerabilities from trivy output", len(vulnerabilities))

    return {
        "source_worker": "trivy",
        "vulnerabilities": vulnerabilities,
        "total_count": len(vulnerabilities),
    }


def _extract_cvss(vuln: dict) -> float | None:
    """
    Extract CVSS score from trivy vulnerability object.
    Prefer NVD V3 score, fall back to V2, then any available.
    """
    cvss_map = vuln.get("CVSS") or {}

    for vendor in ("nvd", "redhat", "ghsa"):
        vendor_data = cvss_map.get(vendor, {})
        v3 = vendor_data.get("V3Score")
        if v3 is not None:
            return float(v3)
        v2 = vendor_data.get("V2Score")
        if v2 is not None:
            return float(v2)

    return None


def _validate_image_ref(image: str) -> str:
    """
    Validate Docker image reference to prevent command injection.
    Pattern: [registry/]name[:tag|@digest]
    Raises ValueError if invalid.
    """
    if not image or len(image) > 512:
        raise ValueError(f"Invalid image reference length: {len(image)}")

    # Allow alphanumerics, dots, underscores, hyphens, colons, slashes, @
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$'
    if not re.fullmatch(pattern, image):
        raise ValueError(f"Invalid image reference format: {image!r}")

    # Explicitly reject shell metacharacters
    forbidden = set(';|&`$(){}!<>\\"\' \n\t\r')
    if any(c in forbidden for c in image):
        raise ValueError(f"Image reference contains forbidden characters: {image!r}")

    logger.info("✅ Image reference validated: %s", image)
    return image
