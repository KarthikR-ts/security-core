#!/usr/bin/env python3
"""
Person 3 acceptance tests — Remediation Safety.

Covers the remediation safety contract:
  1. Dry-run mode must NEVER invoke subprocess / kubectl.
  2. Default configuration is safe (dry_run=True, human-in-loop approval).
  3. Decision gate rejects below-threshold actions.
  4. Human-in-loop mode stages a recommendation (pending_approval) instead
     of executing anything.

Run with:
    pytest tests/test_remediation_safety.py -v
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation.config import RemediationConfig
from remediation.decision_gate import DecisionGate
from remediation.executor import ExecutionEngine


class _StubAuditLogger:
    """In-memory audit logger stub — no Redis dependency in tests."""

    def __init__(self):
        self.records = []

    def log_action(self, **kwargs):
        self.records.append(kwargs)

    def query_by_event_id(self, event_id):
        return [r for r in self.records if r.get("event_id") == event_id]


@pytest.fixture
def make_agent(monkeypatch):
    """Build a RemediationAgent whose AuditLogger is stubbed (no Redis)."""
    import remediation.agent as agent_mod

    monkeypatch.setattr(agent_mod, "AuditLogger", lambda: _StubAuditLogger())

    def _make(config=None):
        agent = agent_mod.RemediationAgent(config or RemediationConfig())
        agent.audit_logger = _StubAuditLogger()
        return agent

    return _make


def _state(event_id="evt-safety-1", confidence=0.95, tactic="Execution"):
    return {
        "event_id": event_id,
        "raw_event": {
            "telemetry": {"pod": "test-pod", "namespace": "default", "pid": 4242},
        },
        "guide_grade": "TP",
        "guide_score": confidence,
        "mitre_techniques": [
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": tactic}
        ],
        "yaml_fix": "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\n",
    }


# ── 1. Dry-run never touches the system ─────────────────────────────


class TestDryRunNeverExecutes:
    def test_dry_run_sigkill_does_not_call_subprocess(self, monkeypatch):
        calls = []

        def _explode(*args, **kwargs):
            calls.append(args)
            raise AssertionError("subprocess.run must never fire during dry-run")

        monkeypatch.setattr("remediation.executor.subprocess.run", _explode)

        engine = ExecutionEngine(kubeconfig_path=None)
        result = engine.execute_sigkill("test-pod", "default", 4242, dry_run=True)

        assert result["status"] == "dry_run"
        assert calls == []

    def test_dry_run_yaml_does_not_call_subprocess(self, monkeypatch):
        calls = []

        def _explode(*args, **kwargs):
            calls.append(args)
            raise AssertionError("subprocess.run must never fire during dry-run")

        monkeypatch.setattr("remediation.executor.subprocess.run", _explode)

        engine = ExecutionEngine(kubeconfig_path=None)
        result = engine.execute_yaml(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\n",
            dry_run=True,
        )

        assert result["status"] == "dry_run"
        assert calls == []

    def test_autonomous_mode_with_dry_run_still_never_executes(self, monkeypatch, make_agent):
        """Even when approval is not required, dry_run must short-circuit execution."""

        def _explode(*args, **kwargs):
            raise AssertionError("subprocess.run must never fire during dry-run")

        monkeypatch.setattr("remediation.executor.subprocess.run", _explode)

        agent = make_agent(RemediationConfig(autonomy_mode="autonomous", dry_run=True))

        result = agent.process_event(_state())

        assert result["remediation_status"] == "dry_run"
        assert result["remediation_action"] == "SIGKILL"


# ── 2. Safe defaults ────────────────────────────────────────────────


class TestSafeDefaults:
    def test_dataclass_defaults_are_safe(self):
        cfg = RemediationConfig()
        assert cfg.dry_run is True
        assert cfg.autonomy_mode == "human-in-loop"

    def test_from_env_defaults_are_safe(self, monkeypatch):
        for var in (
            "REMEDIATION_AUTONOMY_MODE",
            "REMEDIATION_DRY_RUN",
            "REMEDIATION_SIGKILL_THRESHOLD",
            "REMEDIATION_YAML_THRESHOLD",
        ):
            monkeypatch.delenv(var, raising=False)

        cfg = RemediationConfig.from_env()
        assert cfg.autonomy_mode == "human-in-loop"
        assert cfg.dry_run is True
        assert cfg.sigkill_threshold == 0.85
        assert cfg.yaml_threshold == 0.75

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError):
            RemediationConfig(autonomy_mode="yolo")


# ── 3. Decision gate thresholds ─────────────────────────────────────


class TestDecisionGate:
    def test_sigkill_below_threshold_rejected(self):
        gate = DecisionGate()
        approved, reason = gate.evaluate_action(0.80, "SIGKILL")
        assert approved is False
        assert "confidence_too_low" in reason

    def test_sigkill_at_threshold_approved(self):
        gate = DecisionGate()
        approved, reason = gate.evaluate_action(0.85, "SIGKILL")
        assert approved is True
        assert reason == ""

    def test_yaml_below_threshold_rejected(self):
        gate = DecisionGate()
        approved, _ = gate.evaluate_action(0.60, "YAML")
        assert approved is False

    def test_yaml_at_threshold_approved(self):
        gate = DecisionGate()
        approved, _ = gate.evaluate_action(0.75, "YAML")
        assert approved is True


# ── 4. Human approval gate ──────────────────────────────────────────


class TestHumanApprovalGate:
    def test_human_in_loop_requires_approval_for_all_actions(self, make_agent):
        agent = make_agent(RemediationConfig(autonomy_mode="human-in-loop"))
        assert agent._requires_human_approval("SIGKILL") is True
        assert agent._requires_human_approval("YAML") is True

    def test_tiered_requires_approval_only_for_sigkill(self, make_agent):
        agent = make_agent(RemediationConfig(autonomy_mode="tiered"))
        assert agent._requires_human_approval("SIGKILL") is True
        assert agent._requires_human_approval("YAML") is False

    def test_process_event_stages_recommendation(self, monkeypatch, make_agent):
        """Default mode: nothing executes; the result is a staged recommendation."""

        def _explode(*args, **kwargs):
            raise AssertionError("subprocess.run must never fire without approval")

        monkeypatch.setattr("remediation.executor.subprocess.run", _explode)

        agent = make_agent()
        result = agent.process_event(_state())

        assert result["remediation_status"] == "pending_approval"
        assert result["remediation_action"] == "SIGKILL"
        assert result["remediation_error"] == "Awaiting human confirmation"

    def test_low_confidence_skipped_before_approval(self, make_agent):
        agent = make_agent()
        result = agent.process_event(_state(confidence=0.30))

        assert result["remediation_status"] == "skipped"
        assert "confidence_too_low" in result["remediation_error"]

    def test_missing_event_id_skipped_not_executed(self, make_agent):
        agent = make_agent()

        state = _state()
        del state["event_id"]

        result = agent.process_event(state)

        # Agent falls back to raw_event.event_id; here it is absent too, so the
        # event must end up skipped rather than executed.
        assert result["remediation_status"] in ("skipped", "pending_approval")
        assert result["remediation_status"] != "succeeded"
