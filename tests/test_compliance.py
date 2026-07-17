"""
Tests for the SentinelX Compliance Engine.
Covers framework definitions, control evaluation, and scoring.
"""
import pytest


class TestFrameworkDefinitions:
    """Test that all compliance frameworks are properly defined."""

    def test_all_frameworks_exist(self):
        from backend.compliance import FRAMEWORKS

        expected = {"pci_dss", "soc2", "iso27001", "hipaa", "gdpr"}
        assert set(FRAMEWORKS.keys()) == expected

    def test_pci_dss_has_12_controls(self):
        from backend.compliance import PCI_DSS_CONTROLS

        assert len(PCI_DSS_CONTROLS) == 12

    def test_controls_have_required_fields(self):
        from backend.compliance import FRAMEWORKS

        for fw_id, fw in FRAMEWORKS.items():
            for control in fw["controls"]:
                assert "id" in control, f"Missing 'id' in {fw_id}"
                assert "check" in control, f"Missing 'check' in {fw_id} control {control.get('id')}"
                assert "weight" in control, f"Missing 'weight' in {fw_id} control {control.get('id')}"

    def test_control_weights_valid(self):
        from backend.compliance import FRAMEWORKS

        for fw_id, fw in FRAMEWORKS.items():
            for control in fw["controls"]:
                weight = int(control["weight"])
                assert 1 <= weight <= 10, f"Weight {weight} out of range in {fw_id}"


class TestStaticChecks:
    """Test the static compliance checks."""

    @pytest.mark.asyncio
    async def test_static_check_returns_valid_result(self):
        from backend.compliance import _check_static

        result = await _check_static("firewall_rules_active")
        assert "score" in result
        assert "status" in result
        assert result["status"] in ("pass", "fail")
        assert 0 <= result["score"] <= 100

    @pytest.mark.asyncio
    async def test_unknown_check_returns_default(self):
        from backend.compliance import _check_static

        result = await _check_static("nonexistent_check_xyz")
        assert result["score"] == 50
        assert result["status"] == "fail"

    @pytest.mark.asyncio
    async def test_all_static_checks_have_recommendations(self):
        from backend.compliance import _check_static

        known_checks = [
            "firewall_rules_active", "secure_configurations", "data_encryption",
            "transit_encryption", "rbac_enforcement", "security_policies",
        ]
        for check_name in known_checks:
            result = await _check_static(check_name)
            assert "recommendations" in result, f"Missing recommendations for {check_name}"
            assert len(result["recommendations"]) > 0


class TestAggregateRecommendations:
    """Test the recommendation aggregation logic."""

    def test_recommendations_limited_to_10(self):
        from backend.compliance import _aggregate_recommendations

        results = []
        for i in range(20):
            results.append({
                "score": i * 5,
                "recommendations": [f"Fix issue {i}a", f"Fix issue {i}b"],
            })
        recs = _aggregate_recommendations(results)
        assert len(recs) <= 10

    def test_recommendations_sorted_by_score(self):
        from backend.compliance import _aggregate_recommendations

        results = [
            {"score": 90, "recommendations": ["Low priority"]},
            {"score": 20, "recommendations": ["High priority"]},
            {"score": 50, "recommendations": ["Medium priority"]},
        ]
        recs = _aggregate_recommendations(results)
        assert recs[0] == "High priority"  # Lowest score = highest priority

    def test_no_duplicate_recommendations(self):
        from backend.compliance import _aggregate_recommendations

        results = [
            {"score": 30, "recommendations": ["Enable MFA"]},
            {"score": 40, "recommendations": ["Enable MFA", "Update policies"]},
        ]
        recs = _aggregate_recommendations(results)
        assert recs.count("Enable MFA") == 1


class TestNotificationChannels:
    """Test the notification channel status logic."""

    def test_channel_status_structure(self):
        from backend.notifications import get_channel_status

        status = get_channel_status()
        assert "email" in status
        assert "slack" in status
        assert "telegram" in status
        assert "discord" in status
        assert "teams" in status
        assert "routing" in status

    def test_routing_has_all_severities(self):
        from backend.notifications import DEFAULT_ROUTING

        assert "critical" in DEFAULT_ROUTING
        assert "high" in DEFAULT_ROUTING
        assert "medium" in DEFAULT_ROUTING
        assert "low" in DEFAULT_ROUTING
        assert "info" in DEFAULT_ROUTING

    def test_critical_routes_to_all_channels(self):
        from backend.notifications import DEFAULT_ROUTING

        critical_channels = DEFAULT_ROUTING["critical"]
        assert len(critical_channels) >= 4  # Should notify on most channels
