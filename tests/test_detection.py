"""
Tests for the SentinelX Detection Engine.
Covers rule matching, threshold detection, IOC matching, and MITRE mapping.
"""
import pytest
from datetime import datetime, timezone


class TestRuleMatching:
    """Test the detection engine's rule matching capabilities."""

    def test_keyword_match_powershell(self):
        from backend.detection.engine import _match_signature
        from backend.models import Log

        log = Log(
            event_type="process_creation",
            command="powershell.exe -EncodedCommand SGVsbG8gV29ybGQ=",
            raw_log="PowerShell encoded command execution",
        )
        rule = {
            "logic": {
                "event_type": "process_creation",
                "contains_any": ["EncodedCommand"],
            }
        }
        assert _match_signature(rule, log) is True

    def test_keyword_no_match(self):
        from backend.detection.engine import _match_signature
        from backend.models import Log

        log = Log(
            event_type="authentication_success",
            raw_log="User john logged in successfully",
        )
        rule = {
            "logic": {
                "event_type": "process_creation",
                "contains_any": ["mimikatz", "psexec"],
            }
        }
        assert _match_signature(rule, log) is False

    def test_event_type_filter(self):
        from backend.detection.engine import _match_signature
        from backend.models import Log

        log = Log(
            event_type="file_modification",
            raw_log="File modified: /etc/passwd",
            file_path="/etc/passwd",
        )
        rule = {
            "logic": {
                "event_type": "process_creation",  # Wrong event type
                "file_path_contains_any": ["passwd"],
            }
        }
        assert _match_signature(rule, log) is False


class TestMITREMapper:
    """Test the MITRE ATT&CK mapper."""

    def test_known_technique(self):
        from backend.detection.mitre_mapper import get_technique_details

        details = get_technique_details("T1059.001")
        assert details["technique"] == "PowerShell"
        assert details["tactic"] == "Execution"

    def test_unknown_technique(self):
        from backend.detection.mitre_mapper import get_technique_details

        details = get_technique_details("T9999")
        assert details["tactic"] == "Unknown"

    def test_all_techniques_valid(self):
        from backend.detection.mitre_mapper import get_all_techniques

        techniques = get_all_techniques()
        assert len(techniques) > 30
        for t in techniques:
            assert "id" in t
            assert "technique" in t
            assert "tactic" in t

    def test_tactics_order(self):
        from backend.detection.mitre_mapper import get_tactics_list

        tactics = get_tactics_list()
        assert tactics[0] == "Initial Access"
        assert tactics[-1] == "Impact"
        assert len(tactics) == 12

    def test_technique_with_subtechnique(self):
        from backend.detection.mitre_mapper import get_technique_details

        # T1003.001 = LSASS Memory (sub-technique of OS Credential Dumping)
        details = get_technique_details("T1003.001")
        assert details["technique"] == "LSASS Memory"
        assert details["sub"] == "T1003.001"

    def test_parent_technique(self):
        from backend.detection.mitre_mapper import get_technique_details

        details = get_technique_details("T1003")
        assert details["technique"] == "OS Credential Dumping"
        assert details["sub"] is None


class TestAnomalyDetection:
    """Test the ML anomaly detection fallback (rule-based)."""

    def test_off_hours_detection(self):
        from backend.ml.anomaly import _rule_based_anomaly

        log = {
            "timestamp": datetime(2024, 6, 15, 3, 30, tzinfo=timezone.utc),
            "event_type": "authentication_success",
            "user": "john",
        }
        result = _rule_based_anomaly(log)
        assert "off_hours_activity" in result["reasons"]

    def test_encoded_command_detection(self):
        from backend.ml.anomaly import _rule_based_anomaly

        log = {
            "timestamp": datetime(2024, 6, 15, 14, 0, tzinfo=timezone.utc),
            "command": "powershell.exe -enc SGVsbG8gV29ybGQ=",
            "event_type": "process_creation",
        }
        result = _rule_based_anomaly(log)
        assert result["is_anomaly"] is True
        assert "encoded_command_detected" in result["reasons"]

    def test_malicious_process(self):
        from backend.ml.anomaly import _rule_based_anomaly

        log = {
            "timestamp": datetime(2024, 6, 15, 10, 0, tzinfo=timezone.utc),
            "process_name": "mimikatz.exe",
            "event_type": "process_creation",
        }
        result = _rule_based_anomaly(log)
        assert result["is_anomaly"] is True
        assert "known_malicious_process" in result["reasons"]

    def test_normal_activity(self):
        from backend.ml.anomaly import _rule_based_anomaly

        log = {
            "timestamp": datetime(2024, 6, 13, 10, 0, tzinfo=timezone.utc),  # Thursday 10am
            "event_type": "authentication_success",
            "user": "john",
            "command": "dir",
            "process_name": "explorer.exe",
        }
        result = _rule_based_anomaly(log)
        assert result["is_anomaly"] is False

    def test_model_status(self):
        from backend.ml.anomaly import get_model_status

        status = get_model_status()
        assert "ml_available" in status
        assert "methods" in status
        assert "impossible_travel" in status["methods"]


class TestImpossibleTravel:
    """Test the impossible travel detection."""

    def test_impossible_travel_detected(self):
        from backend.ml.anomaly import detect_impossible_travel

        events = [
            {"user": "alice", "timestamp": "2024-06-15T10:00:00+00:00", "country": "US"},
            {"user": "alice", "timestamp": "2024-06-15T11:00:00+00:00", "country": "RU"},
        ]
        result = detect_impossible_travel(events)
        assert result["impossible_travel_detected"] >= 1
        assert result["alerts"][0]["verdict"] == "impossible_travel"

    def test_possible_travel_ok(self):
        from backend.ml.anomaly import detect_impossible_travel

        events = [
            {"user": "bob", "timestamp": "2024-06-15T08:00:00+00:00", "country": "US"},
            {"user": "bob", "timestamp": "2024-06-16T20:00:00+00:00", "country": "GB"},
        ]
        result = detect_impossible_travel(events)
        assert result["impossible_travel_detected"] == 0

    def test_same_country_no_alert(self):
        from backend.ml.anomaly import detect_impossible_travel

        events = [
            {"user": "carol", "timestamp": "2024-06-15T10:00:00+00:00", "country": "US"},
            {"user": "carol", "timestamp": "2024-06-15T11:00:00+00:00", "country": "US"},
        ]
        result = detect_impossible_travel(events)
        assert result["impossible_travel_detected"] == 0
