import json
import logging
from pathlib import Path
from typing import Any

try:
    import numpy as np
    import pandas as pd
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    np = None  # type: ignore
    pd = None  # type: ignore
    xgb = None  # type: ignore
    XGB_AVAILABLE = False

logger = logging.getLogger("security.ml_triage")


class MLTriage:
    """Handles ML-based triage for Security events with pure-Python heuristic fallback."""

    def __init__(self, model_path: Path, feature_list_path: Path):
        self.model_path = model_path
        self.feature_list_path = feature_list_path
        self.model = None
        self.features = []
        self.label_map = {}
        self.reverse_label_map = {}

        if XGB_AVAILABLE:
            self._load_resources()
        else:
            logger.info("XGBoost not available; running in rule-based heuristic triage mode (s390x compatible).")

    def _load_resources(self):
        """Load the model and feature/label metadata."""
        if not self.model_path.exists():
            logger.warning("ML model not found at %s. Running in rule-based fallback mode.", self.model_path)
            return

        try:
            self.model = xgb.Booster()
            self.model.load_model(str(self.model_path))
            logger.info("ML model loaded from %s", self.model_path)

            if self.feature_list_path.exists():
                with open(self.feature_list_path, "r") as f:
                    data = json.load(f)
                    self.features = data.get("features", [])
                    self.label_map = data.get("labels", {})
                    self.reverse_label_map = {int(k): v for k, v in self.label_map.items()}
                logger.info("Feature list loaded: %d features", len(self.features))
            else:
                logger.warning("Feature list not found. Running in rule-based fallback mode.")
                self.model = None

        except Exception as e:
            logger.error("Failed to load ML resources: %s. Using rule-based fallback.", e)
            self.model = None

    def triage_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """
        Predict triage status for a Security event.

        Every result carries explicit provenance so downstream consumers can tell
        which signal produced it:

          triage.basis        "heuristic_rules" (deterministic rule engine)
                              or "model+heuristic_gates" (XGBoost + safety gates)
          triage.score_type   "risk_score" (additive 0-14 feature score)
          triage.risk_score   the additive score value
          triage.evidence     human-readable list of matched contributing signals
          explanation.confidence_semantics  plain-language meaning of `confidence`
          explanation.recommended_action    suggested analyst next step
        """
        feature_data = self._prepare_features(event)
        risk_score, evidence = self._risk_assessment(feature_data)

        if not XGB_AVAILABLE or self.model is None or not self.features:
            # Deterministic rule-based triage fallback (architecture portable)
            if risk_score >= 5:
                grade = "TP"
                confidence = min(0.75 + risk_score * 0.03, 0.95)
            elif risk_score >= 3:
                grade = "BP"
                confidence = min(0.60 + risk_score * 0.05, 0.85)
            else:
                grade = "FP"
                confidence = 0.80

            status_formatted = {"TP": "True Positive", "BP": "Benign Positive", "FP": "False Positive"}.get(grade, grade)
            return {
                "triage": {
                    "grade": grade,
                    "confidence": round(confidence, 2),
                    "basis": "heuristic_rules",
                    "score_type": "risk_score",
                    "risk_score": risk_score,
                    "evidence": evidence,
                },
                "explanation": {
                    "mitre_id": "N/A",
                    "guidance": (
                        f"Heuristic rule engine identified {status_formatted} "
                        f"(risk_score={risk_score}; rules: {'; '.join(evidence) or 'no risk signals'})."
                    ),
                    "confidence_semantics": (
                        "Rule-engine confidence (0-1) reflects how strongly the matched "
                        "risk signals support the grade. It is not a calibrated probability."
                    ),
                    "recommended_action": self._recommended_action(grade),
                },
                "deliverable": (
                    f"Classified as {status_formatted} by deterministic security heuristics "
                    f"(risk score {risk_score}/14, rule confidence {round(confidence, 2)})."
                ),
            }


        try:
            # Prepare features for inference
            feature_data = self._prepare_features(event)
            
            # Ensure order matches training
            ordered_features = [feature_data.get(f, 0) for f in self.features]
            
            # Use raw numpy array to avoid pandas type mismatch completely
            dmat = xgb.DMatrix(np.array([ordered_features]), feature_names=self.features)
            
            # Predict
            preds = self.model.predict(dmat)
            
            # Multi-class softprob gives an array of probabilities per class
            if len(preds.shape) > 1 and preds.shape[1] > 1:
                probs = preds[0]
                prediction = int(np.argmax(probs))
                confidence = float(np.max(probs))
            else:
                prediction = int(preds[0])
                confidence = 1.0

            status = self.reverse_label_map.get(prediction, "TruePositive")

            grade_map = {
                "FalsePositive": "FP",
                "BenignPositive": "BP",
                "TruePositive": "TP"
            }
            grade = grade_map.get(status, "TP")

            # ── Rule-based override ──────────────────────────────────
            # The synthetic XGBoost model is heavily biased toward FP.
            # Use security heuristic features to correct obvious misclassifications.
            risk_score, evidence = self._risk_assessment(feature_data)
            original_grade = grade
            if grade == "FP" and risk_score >= 5:
                grade = "TP"
                confidence = min(0.70 + risk_score * 0.03, 0.95)
            elif grade == "FP" and risk_score >= 3:
                grade = "BP"
                confidence = min(0.60 + risk_score * 0.05, 0.85)
            # ─────────────────────────────────────────────────────────

            status_formatted = {"TP": "True Positive", "BP": "Benign Positive", "FP": "False Positive"}.get(grade, grade)

            if original_grade != grade:
                note = f"model predicted {original_grade}; heuristic gate overrode to {grade} (risk_score={risk_score})"
                evidence.append(note)
                logger.info("Triage override: %s -> %s (risk_score=%d)", original_grade, grade, risk_score)

            return {
                "triage": {
                    "grade": grade,
                    "confidence": round(confidence, 2),
                    "basis": "model+heuristic_gates",
                    "score_type": "risk_score",
                    "risk_score": risk_score,
                    "evidence": evidence,
                },
                "explanation": {
                    "mitre_id": "N/A",
                    "guidance": (
                        f"ML model graded {status_formatted} (model score {round(confidence, 2)}); "
                        f"heuristic gate risk_score={risk_score}."
                    ),
                    "confidence_semantics": (
                        "Model confidence is the classifier's softmax score for the predicted "
                        "class. Heuristic gate overrides, when applied, are listed in triage.evidence."
                    ),
                    "recommended_action": self._recommended_action(grade),
                },
                "deliverable": (
                    f"Graded {status_formatted} by ML model with heuristic gates applied "
                    f"(model score {round(confidence, 2)}, risk score {risk_score}/14)."
                ),
            }

        except Exception as e:
            logger.error(f"ML Inference failed: {e}")
            return {
                "triage": {
                    "grade": "TP",
                    "confidence": 0.0,
                    "basis": "fail_safe",
                    "score_type": "risk_score",
                    "risk_score": risk_score,
                    "evidence": evidence + [f"inference error: {e}"],
                },
                "explanation": {
                    "mitre_id": "N/A",
                    "guidance": f"ML Inference failed: {str(e)}",
                    "confidence_semantics": "Fail-safe default: no calibrated confidence available.",
                    "recommended_action": "Treat as suspicious until a human analyst reviews the raw event.",
                },
                "deliverable": "Triage analysis error, treating as serious.",
            }

    @staticmethod
    def _risk_assessment(feature_data: dict[str, Any]) -> tuple[int, list[str]]:
        """
        Compute the additive risk score and human-readable evidence for it.

        Weights (max total 14):
          sensitive_path    x3   (credential/secret locations)
          binary_risk       x2   (network/dual-use tooling)
          has_network_args  x2   (IPs or ports in arguments)
          is_root           x2   (uid 0)
          parent_is_shell   x1   (shell-spawned process)
          syscall_risk      x1   (execve/ptrace/bpf vs connect/write/openat)
        """
        evidence: list[str] = []

        binary_risk = feature_data.get("binary_risk", 0)
        sensitive_path = feature_data.get("sensitive_path", 0)
        has_network_args = feature_data.get("has_network_args", 0)
        parent_is_shell = feature_data.get("parent_is_shell", 0)
        is_root = feature_data.get("is_root", 0)
        syscall_risk = feature_data.get("syscall_risk", 0)

        if binary_risk >= 2:
            evidence.append("binary on high-risk list (network/dual-use tool) +2")
        elif binary_risk == 1:
            evidence.append("binary is a scripting/interpreter binary +1")

        if sensitive_path:
            evidence.append("arguments/binary reference a credential or secret path +3")

        if has_network_args:
            evidence.append("arguments contain an IP address or port +2")

        if is_root:
            evidence.append("process runs as uid 0 (root) +2")

        if parent_is_shell:
            evidence.append("parent process is a shell +1")

        if syscall_risk >= 2:
            evidence.append("high-risk syscall (execve/ptrace/bpf) +1")
        elif syscall_risk == 1:
            evidence.append("dual-use syscall (connect/write/openat) +1")

        risk_score = (
            binary_risk * 2
            + sensitive_path * 3
            + has_network_args * 2
            + parent_is_shell * 1
            + is_root * 2
            + syscall_risk * 1
        )
        return risk_score, evidence

    @staticmethod
    def _recommended_action(grade: str) -> str:
        """Map a triage grade to a conservative analyst next step."""
        return {
            "TP": "Escalate to a human analyst; consider isolating the pod and collect process lineage before any remediation.",
            "BP": "Verify the activity against change records; keep in audit trail, do not auto-remediate.",
            "FP": "Suppress from the active queue and feed back to rule tuning; no remediation.",
        }.get(grade, "Review manually; automatic remediation is not advised for unknown grades.")

    def _prepare_features(self, event: dict[str, Any]) -> dict[str, Any]:
        """Map Security event fields to ML features using security heuristics."""
        telemetry = event.get("telemetry", {})
        
        # 1. Base ID/Auth 
        uid = int(telemetry.get("uid", 1000))
        pid = int(telemetry.get("pid", 0))
        is_root = 1 if uid == 0 else 0
        
        # 2. Binary Risk
        binary = telemetry.get("binary", "").lower()
        if any(b in binary for b in ["curl", "wget", "nc", "netcat", "nmap", "socat"]):
            binary_risk = 2
        elif any(b in binary for b in ["bash", "sh", "python", "perl", "ruby"]):
            binary_risk = 1
        else:
            binary_risk = 0
            
        # 3. Syscall Risk
        syscall = event.get("syscall", "").lower()
        if any(s in syscall for s in ["execve", "ptrace", "bpf"]):
            syscall_risk = 2
        elif any(s in syscall for s in ["connect", "write", "openat"]):
            syscall_risk = 1
        else:
            syscall_risk = 0
            
        # 4. Sensitive Path Access
        path = telemetry.get("file_path", telemetry.get("path", "")).lower()
        args = str(telemetry.get("args", [])).lower()
        target_str = path + " " + args
        sensitive_paths = ["/etc/shadow", "/etc/passwd", "/root", "/var/run/secrets", "/proc", ".ssh"]
        sensitive_path = 1 if any(p in target_str for p in sensitive_paths) else 0
        
        # 5. Event Type mapping
        evt_type_str = event.get("event_type", "process_exec")
        evt_map = {"process_exec": 0, "process_kprobe": 1, "process_exit": 2}
        event_type = evt_map.get(evt_type_str, 0)
        
        # 6. Network Indicators
        # Super simple check for IPs or ports in arguments
        import re
        has_network_args = 1 if re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(:\d+)', args) else 0
        
        # 7. Container
        is_container = 1 if telemetry.get("container_id") or telemetry.get("pod") else 0
        
        # 8. Parent process
        parent = telemetry.get("parent_binary", "").lower()
        parent_is_shell = 1 if any(b in parent for b in ["bash", "sh", "dash", "zsh"]) else 0

        return {
            "uid": uid,
            "pid": pid,
            "is_root": is_root,
            "binary_risk": binary_risk,
            "syscall_risk": syscall_risk,
            "sensitive_path": sensitive_path,
            "event_type": event_type,
            "has_network_args": has_network_args,
            "is_container": is_container,
            "parent_is_shell": parent_is_shell
        }
