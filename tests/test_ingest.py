"""Tests for the STIX ingestion module (gseg.ingest_attack).

Covers downloading, parsing techniques, mitigations, and relations
from a MITRE ATT&CK STIX bundle.  All network calls are mocked.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from gseg.ingest_attack import (
    download_attack_stix,
    parse_mitigations,
    parse_relations,
    parse_techniques,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_stix_data() -> Dict[str, Any]:
      """Return a minimal valid STIX bundle with one technique, one
          mitigation, and one mitigates relationship."""
      return {
          "type": "bundle",
          "id": "bundle--test",
          "objects": [
              # --- technique (attack-pattern) ---
              {
                  "type": "attack-pattern",
                  "id": "attack-pattern--aaa111",
                  "name": "Process Injection",
                  "description": "Inject code into processes.",
                  "kill_chain_phases": [
                      {"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"},
                      {"kill_chain_name": "mitre-attack", "phase_name": "privilege-escalation"},
                  ],
                  "external_references": [
                      {
                          "source_name": "mitre-attack",
                          "external_id": "T1055",
                          "url": "https://attack.mitre.org/techniques/T1055",
                      }
                  ],
              },
              # --- revoked technique (should be skipped) ---
              {
                  "type": "attack-pattern",
                  "id": "attack-pattern--revoked",
                  "name": "Revoked Technique",
                  "description": "This was revoked.",
                  "revoked": True,
                  "external_references": [
                      {"source_name": "mitre-attack", "external_id": "T9999"}
                  ],
              },
              # --- mitigation (course-of-action) ---
              {
                  "type": "course-of-action",
                  "id": "course-of-action--bbb222",
                  "name": "Privileged Account Management",
                  "description": "Manage privileged accounts.",
                  "external_references": [
                      {
                          "source_name": "mitre-attack",
                          "external_id": "M1026",
                          "url": "https://attack.mitre.org/mitigations/M1026",
                      }
                  ],
              },
              # --- mitigates relationship ---
              {
                  "type": "relationship",
                  "id": "relationship--ccc333",
                  "relationship_type": "mitigates",
                  "source_ref": "course-of-action--bbb222",
                  "target_ref": "attack-pattern--aaa111",
              },
              # --- unrelated relationship (should be ignored) ---
              {
                  "type": "relationship",
                  "id": "relationship--ddd444",
                  "relationship_type": "uses",
                  "source_ref": "intrusion-set--eee555",
                  "target_ref": "attack-pattern--aaa111",
              },
          ],
      }


# ---------------------------------------------------------------------------
# Download tests
# ---------------------------------------------------------------------------


class TestDownloadAttackStix:
      """Tests for ``download_attack_stix``."""

    @patch("gseg.ingest_attack.requests.get")
    def test_success(self, mock_get: MagicMock, tmp_path: Path) -> None:
              """Successful download writes the STIX bundle to disk."""
              # --- arrange ---
              fake_content: bytes = b'{"type":"bundle","objects":[]}'
              mock_response: MagicMock = MagicMock()
              mock_response.status_code = 200
              mock_response.headers = {"Content-Length": str(len(fake_content))}
              mock_response.iter_content.return_value = [fake_content]
              mock_response.raise_for_status.return_value = None
              mock_get.return_value.__enter__ = MagicMock(return_value=mock_response)
              mock_get.return_value = mock_response

        output_path: Path = tmp_path / "enterprise-attack.json"

        # --- act ---
        result: Path = download_attack_stix(output_path, force=True)

        # --- assert ---
        assert result == output_path
        assert output_path.exists()
        mock_get.assert_called_once()

    def test_skip_existing(self, tmp_path: Path) -> None:
              """Existing file is not re-downloaded when force=False."""
              output_path: Path = tmp_path / "enterprise-attack.json"
              output_path.write_text('{"type":"bundle","objects":[]}')

        result: Path = download_attack_stix(output_path, force=False)

        assert result == output_path

    @patch("gseg.ingest_attack.requests.get")
    def test_failure_exits(self, mock_get: MagicMock, tmp_path: Path) -> None:
              """Download failure after all retries triggers SystemExit."""
              mock_get.side_effect = ConnectionError("Network unreachable")

        output_path: Path = tmp_path / "enterprise-attack.json"

        with pytest.raises(SystemExit):
                      download_attack_stix(output_path, force=True)


# ---------------------------------------------------------------------------
# Parsing tests
# ---------------------------------------------------------------------------


class TestParseTechniques:
      """Tests for ``parse_techniques``."""

    def test_extracts_valid_technique(
              self, sample_stix_data: Dict[str, Any]
    ) -> None:
              """A non-revoked attack-pattern is extracted with correct fields."""
              techniques: List[Dict[str, Any]] = parse_techniques(sample_stix_data)

        assert len(techniques) == 1
        tech: Dict[str, Any] = techniques[0]
        assert tech["technique_id"] == "T1055"
        assert tech["name"] == "Process Injection"
        assert "defense-evasion" in tech["tactics"]
        assert "privilege-escalation" in tech["tactics"]
        assert tech["url"] == "https://attack.mitre.org/techniques/T1055"

    def test_skips_revoked(self, sample_stix_data: Dict[str, Any]) -> None:
              """Revoked techniques are excluded from the result."""
              techniques: List[Dict[str, Any]] = parse_techniques(sample_stix_data)

        ids: List[str] = [t["technique_id"] for t in techniques]
        assert "T9999" not in ids

    def test_empty_bundle(self) -> None:
              """An empty objects list returns no techniques."""
              data: Dict[str, Any] = {"objects": []}
              assert parse_techniques(data) == []


class TestParseMitigations:
      """Tests for ``parse_mitigations``."""

    def test_extracts_valid_mitigation(
              self, sample_stix_data: Dict[str, Any]
    ) -> None:
              """A non-revoked course-of-action is extracted with correct fields."""
              mitigations: List[Dict[str, Any]] = parse_mitigations(sample_stix_data)

        assert len(mitigations) == 1
        mit: Dict[str, Any] = mitigations[0]
        assert mit["mitigation_id"] == "M1026"
        assert mit["name"] == "Privileged Account Management"
        assert mit["url"] == "https://attack.mitre.org/mitigations/M1026"

    def test_empty_bundle(self) -> None:
              """An empty objects list returns no mitigations."""
              data: Dict[str, Any] = {"objects": []}
              assert parse_mitigations(data) == []


class TestParseRelations:
      """Tests for ``parse_relations``."""

    def test_extracts_mitigates_relation(
              self, sample_stix_data: Dict[str, Any]
    ) -> None:
              """A mitigates relationship is resolved to ATT&CK IDs."""
              techniques: List[Dict[str, Any]] = parse_techniques(sample_stix_data)
              mitigations: List[Dict[str, Any]] = parse_mitigations(sample_stix_data)
              relations: List[Dict[str, str]] = parse_relations(
                  sample_stix_data, techniques, mitigations
              )

        assert len(relations) == 1
        rel: Dict[str, str] = relations[0]
        assert rel["technique_id"] == "T1055"
        assert rel["mitigation_id"] == "M1026"

    def test_ignores_non_mitigates(
              self, sample_stix_data: Dict[str, Any]
    ) -> None:
              """Non-mitigates relationships (e.g. 'uses') are excluded."""
              techniques: List[Dict[str, Any]] = parse_techniques(sample_stix_data)
              mitigations: List[Dict[str, Any]] = parse_mitigations(sample_stix_data)
              relations: List[Dict[str, str]] = parse_relations(
                  sample_stix_data, techniques, mitigations
              )

        # Only the mitigates relation should survive
              assert all(r["mitigation_id"].startswith("M") for r in relations)

    def test_empty_bundle(self) -> None:
              """An empty STIX bundle yields no relations."""
              data: Dict[str, Any] = {"objects": []}
              assert parse_relations(data, [], []) == []
