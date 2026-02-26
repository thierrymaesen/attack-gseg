"""Module for ingesting MITRE ATT&CK Enterprise STIX data.

This module downloads the ATT&CK Enterprise STIX bundle from the official
MITRE GitHub repository, parses techniques, mitigations, and their
relationships, then saves structured JSON files for downstream processing.

Usage:
    poetry run python -m gseg.ingest_attack
    poetry run python -m gseg.ingest_attack --force-download --verbose
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import requests
from tqdm import tqdm

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTACK_STIX_URL: str = (
    "https://raw.githubusercontent.com/mitre/cti/" "master/enterprise-attack/enterprise-attack.json"
)
DEFAULT_OUTPUT_DIR: Path = Path("data")
REQUEST_TIMEOUT: int = 30
MAX_RETRIES: int = 3
RETRY_BACKOFF: float = 2.0
DESCRIPTION_MAX_LENGTH: int = 500

logger: logging.Logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def download_attack_stix(output_path: Path, force: bool = False) -> Path:
    """Download the ATT&CK Enterprise STIX bundle from GitHub.

    Args:
        output_path: Destination file path for the raw STIX JSON.
        force: If True, re-download even when the file already exists.

    Returns:
        Path to the downloaded (or already existing) STIX JSON file.

    Raises:
        SystemExit: If download fails after all retry attempts.
    """
    if output_path.exists() and not force:
        size_mb: float = output_path.stat().st_size / (1024 * 1024)
        logger.info(
            "STIX bundle already exists at %s (%.1f MB) \u2014 skipping download",
            output_path,
            size_mb,
        )
        return output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info(
                "Downloading ATT&CK STIX bundle (attempt %d/%d)\u2026",
                attempt,
                MAX_RETRIES,
            )
            response: requests.Response = requests.get(
                ATTACK_STIX_URL, stream=True, timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()

            total_bytes: int | None = (
                int(response.headers["Content-Length"])
                if "Content-Length" in response.headers
                else None
            )

            with (
                open(output_path, "wb") as fh,
                tqdm(
                    total=total_bytes,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc="enterprise-attack.json",
                    disable=None,
                ) as progress_bar,
            ):
                for chunk in response.iter_content(chunk_size=8192):
                    fh.write(chunk)
                    progress_bar.update(len(chunk))

            size_mb = output_path.stat().st_size / (1024 * 1024)
            logger.info(
                "Download complete \u2014 saved to %s (%.1f MB)",
                output_path,
                size_mb,
            )
            return output_path

        except (
            requests.ConnectionError,
            requests.Timeout,
            requests.HTTPError,
        ) as exc:
            logger.error(
                "Download attempt %d/%d failed: %s",
                attempt,
                MAX_RETRIES,
                exc,
            )
            if attempt < MAX_RETRIES:
                wait_seconds: float = RETRY_BACKOFF**attempt
                logger.info("Retrying in %.0f s\u2026", wait_seconds)
                time.sleep(wait_seconds)

    logger.critical("All %d download attempts failed \u2014 aborting.", MAX_RETRIES)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def _truncate(text: str, max_length: int = DESCRIPTION_MAX_LENGTH) -> str:
    """Truncate *text* to *max_length* characters, adding ellipsis if trimmed."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 1] + "\u2026"


def _get_external_id(stix_object: dict[str, Any]) -> str | None:
    """Return the first external_id from a STIX object's external_references."""
    for ref in stix_object.get("external_references", []):
        if ref.get("external_id"):
            return ref["external_id"]
    return None


def _get_external_url(stix_object: dict[str, Any]) -> str | None:
    """Return the first URL from a STIX object's external_references."""
    for ref in stix_object.get("external_references", []):
        if ref.get("url"):
            return ref["url"]
    return None


def parse_techniques(stix_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract ATT&CK techniques from STIX bundle objects.

    Args:
        stix_data: Parsed STIX bundle as a dict (the full JSON).

    Returns:
        List of technique dicts with keys: technique_id, name,
        description, tactics, url.
    """
    techniques: list[dict[str, Any]] = []
    stix_objects: list[dict[str, Any]] = stix_data.get("objects", [])

    attack_patterns = [
        obj
        for obj in stix_objects
        if obj.get("type") == "attack-pattern"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]

    for obj in tqdm(attack_patterns, desc="Parsing techniques", unit="tech"):
        technique_id: str | None = _get_external_id(obj)
        if not technique_id:
            logger.warning(
                "Skipping attack-pattern without external_id: %s",
                obj.get("id", "unknown"),
            )
            continue

        tactics: list[str] = [
            phase.get("phase_name", "unknown") for phase in obj.get("kill_chain_phases", [])
        ]

        technique: dict[str, Any] = {
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": _truncate(obj.get("description", "")),
            "tactics": tactics,
            "url": _get_external_url(obj) or "",
        }
        techniques.append(technique)

    logger.info("Parsed %d techniques", len(techniques))
    return techniques


def parse_mitigations(stix_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract ATT&CK mitigations from STIX bundle objects.

    Args:
        stix_data: Parsed STIX bundle as a dict.

    Returns:
        List of mitigation dicts with keys: mitigation_id, name,
        description, url.
    """
    mitigations: list[dict[str, Any]] = []
    stix_objects: list[dict[str, Any]] = stix_data.get("objects", [])

    courses_of_action = [
        obj
        for obj in stix_objects
        if obj.get("type") == "course-of-action"
        and not obj.get("revoked", False)
        and not obj.get("x_mitre_deprecated", False)
    ]

    for obj in tqdm(courses_of_action, desc="Parsing mitigations", unit="mit"):
        mitigation_id: str | None = _get_external_id(obj)
        if not mitigation_id:
            logger.warning(
                "Skipping course-of-action without external_id: %s",
                obj.get("id", "unknown"),
            )
            continue

        mitigation: dict[str, Any] = {
            "mitigation_id": mitigation_id,
            "name": obj.get("name", ""),
            "description": _truncate(obj.get("description", "")),
            "url": _get_external_url(obj) or "",
        }
        mitigations.append(mitigation)

    logger.info("Parsed %d mitigations", len(mitigations))
    return mitigations


def parse_relations(
    stix_data: dict[str, Any],
    techniques: list[dict[str, Any]],
    mitigations: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Extract mitigation-to-technique relationships and resolve STIX IDs.

    Builds a lookup table from STIX internal IDs (e.g.
    attack-pattern--abc123) to ATT&CK human-readable IDs (e.g. T1055,
    M1013), then maps each mitigates relationship accordingly.

    Args:
        stix_data: Parsed STIX bundle as a dict.
        techniques: Previously parsed technique list (from parse_techniques).
        mitigations: Previously parsed mitigation list (from parse_mitigations).

    Returns:
        List of relation dicts with keys: technique_id, mitigation_id.
    """
    stix_objects: list[dict[str, Any]] = stix_data.get("objects", [])

    # Build STIX-ID to ATT&CK-ID lookup tables
    stix_to_attack: dict[str, str] = {}
    for obj in stix_objects:
        if obj.get("type") in ("attack-pattern", "course-of-action"):
            attack_id: str | None = _get_external_id(obj)
            if attack_id:
                stix_to_attack[obj["id"]] = attack_id

    mitigates_relationships = [
        obj
        for obj in stix_objects
        if obj.get("type") == "relationship"
        and obj.get("relationship_type") == "mitigates"
        and not obj.get("revoked", False)
    ]

    # Build sets of known ATT&CK IDs for validation
    known_technique_ids: set[str] = {t["technique_id"] for t in techniques}
    known_mitigation_ids: set[str] = {m["mitigation_id"] for m in mitigations}

    relations: list[dict[str, str]] = []

    for obj in tqdm(mitigates_relationships, desc="Parsing relations", unit="rel"):
        source_stix_id: str = obj.get("source_ref", "")
        target_stix_id: str = obj.get("target_ref", "")

        resolved_mitigation: str | None = stix_to_attack.get(source_stix_id)
        resolved_technique: str | None = stix_to_attack.get(target_stix_id)

        if not resolved_mitigation or not resolved_technique:
            logger.warning(
                "Unresolvable relation: source=%s target=%s \u2014 skipping",
                source_stix_id,
                target_stix_id,
            )
            continue

        if (
            resolved_technique not in known_technique_ids
            or resolved_mitigation not in known_mitigation_ids
        ):
            logger.warning(
                "Relation references revoked/deprecated object: " "%s -> %s \u2014 skipping",
                resolved_mitigation,
                resolved_technique,
            )
            continue

        relations.append(
            {
                "technique_id": resolved_technique,
                "mitigation_id": resolved_mitigation,
            }
        )

    logger.info("Parsed %d mitigation->technique relations", len(relations))
    return relations


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def save_json(data: list[dict[str, Any]], output_path: Path) -> None:
    """Save a list of dicts as a pretty-printed JSON file.

    Args:
        data: The data to serialise.
        output_path: Destination file path.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    size_kb: float = output_path.stat().st_size / 1024
    logger.info(
        "Saved %d entries to %s (%.1f KB)",
        len(data),
        output_path,
        size_kb,
    )


# ---------------------------------------------------------------------------
# CLI & pipeline
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> None:
    """Set up root logging format and level."""
    level: int = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> None:
    """CLI entry-point: download, parse, and save ATT&CK STIX data."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Ingest MITRE ATT&CK Enterprise STIX data.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory for output JSON files",
    )
    parser.add_argument(
        "--force-download",
        action="store_true",
        help="Force re-download even if STIX file exists",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )

    args: argparse.Namespace = parser.parse_args()
    output_dir: Path = args.output_dir

    _configure_logging(args.verbose)

    try:
        # 1. Download raw STIX bundle
        stix_path: Path = output_dir / "enterprise-attack.json"
        download_attack_stix(stix_path, force=args.force_download)

        # 2. Load JSON into memory
        logger.info("Loading STIX bundle into memory\u2026")
        with open(stix_path, "r", encoding="utf-8") as fh:
            stix_data: dict[str, Any] = json.load(fh)

        object_count: int = len(stix_data.get("objects", []))
        logger.info("Loaded %d STIX objects", object_count)

        # 3. Parse entities
        techniques: list[dict[str, Any]] = parse_techniques(stix_data)
        mitigations: list[dict[str, Any]] = parse_mitigations(stix_data)
        relations: list[dict[str, str]] = parse_relations(stix_data, techniques, mitigations)

        # 4. Save structured JSON files
        save_json(techniques, output_dir / "techniques.json")
        save_json(mitigations, output_dir / "mitigations.json")
        save_json(relations, output_dir / "relations.json")

        # 5. Summary
        print("\n" + "=" * 50)
        print("  ATT&CK STIX Ingestion \u2014 Complete")
        print("=" * 50)
        print(f"  Techniques : {len(techniques)}")
        print(f"  Mitigations: {len(mitigations)}")
        print(f"  Relations  : {len(relations)}")
        print(f"  Output dir : {output_dir.resolve()}")
        print("=" * 50 + "\n")

    except json.JSONDecodeError as exc:
        logger.exception("Failed to parse STIX JSON: %s", exc)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        logger.exception("Unexpected error during ingestion: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
