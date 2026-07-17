"""
Tests for the SentinelX Log Normalization Engine.
Covers schema mapping, Windows Event ID resolution, and field enrichment.
"""
import pytest
from datetime import datetime, timezone


class TestNormalizer:
    """Test the log normalizer."""

    def test_normalize_windows_log(self):
        from backend.normalization.normalizer import normalize_log

        raw = {
            "hostname": "WIN-DC01",
            "event_id": "4625",
            "source": "windows",
            "source_ip": "192.168.1.100",
            "raw_log": "Failed login for administrator from 192.168.1.100",
        }
        result = normalize_log(raw)
        assert result["hostname"] == "WIN-DC01"
        assert result["event_type"] == "authentication_failure"  # Mapped from 4625
        assert result["severity"] in ("medium", "high")
        assert "tags" in result

    def test_normalize_linux_log(self):
        from backend.normalization.normalizer import normalize_log

        raw = {
            "hostname": "LINUX-PROD01",
            "source": "linux",
            "event_type": "authentication_failure",
            "source_ip": "10.0.0.50",
            "raw_log": "Failed password for root from 10.0.0.50",
        }
        result = normalize_log(raw)
        assert result["source"] == "linux"
        assert result["event_type"] == "authentication_failure"

    def test_normalize_adds_timestamp(self):
        from backend.normalization.normalizer import normalize_log

        raw = {
            "hostname": "TEST",
            "source": "test",
            "raw_log": "test event",
        }
        result = normalize_log(raw)
        assert "timestamp" in result
        assert result["timestamp"] is not None

    def test_normalize_preserves_fields(self):
        from backend.normalization.normalizer import normalize_log

        raw = {
            "hostname": "SERVER01",
            "source": "firewall",
            "source_ip": "1.2.3.4",
            "destination_ip": "10.0.0.1",
            "user": "admin",
            "process_name": "sshd",
            "raw_log": "SSH connection from 1.2.3.4",
        }
        result = normalize_log(raw)
        assert result["source_ip"] == "1.2.3.4"
        assert result["destination_ip"] == "10.0.0.1"
        assert result["user"] == "admin"

    def test_normalize_event_id_mapping(self):
        from backend.normalization.normalizer import normalize_log

        # Test multiple Windows Event ID mappings
        mappings = {
            "4624": "authentication_success",
            "4625": "authentication_failure",
            "4688": "process_creation",
            "4720": "user_account_created",
        }
        for event_id, expected_type in mappings.items():
            result = normalize_log({
                "hostname": "TEST",
                "source": "windows",
                "event_id": event_id,
                "raw_log": "test",
            })
            assert result["event_type"] == expected_type, f"Event ID {event_id} should map to {expected_type}"


class TestTagEnrichment:
    """Test that the normalizer adds appropriate tags."""

    def test_admin_tag(self):
        from backend.normalization.normalizer import normalize_log

        result = normalize_log({
            "hostname": "DC01",
            "source": "windows",
            "user": "administrator",
            "raw_log": "admin login",
        })
        assert "admin_activity" in result.get("tags", [])

    def test_brute_force_tag(self):
        from backend.normalization.normalizer import normalize_log

        result = normalize_log({
            "hostname": "DC01",
            "source": "windows",
            "event_type": "authentication_failure",
            "raw_log": "failed password",
        })
        tags = result.get("tags", [])
        assert "auth_failure" in tags or "brute_force_candidate" in tags
