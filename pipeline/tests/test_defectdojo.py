"""Tests for DefectDojo API client."""
from __future__ import annotations


from pipeline.defectdojo_client import (
    DefectDojoClient,
    import_to_defectdojo,
)
from pipeline.models import Finding


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        scanner="nuclei",
        product="test_app",
        title="SQL Injection in /login",
        severity="high",
        cve="CVE-2024-1234",
        cwe="CWE-89",
        endpoint="/login",
        score=85.0,
        dedup_key="test-001",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestDefectDojoClient:
    def test_not_configured_by_default(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        client = DefectDojoClient()
        assert not client.configured

    def test_configured_with_env(self, monkeypatch):
        monkeypatch.setenv("DEFECTDOJO_URL", "http://localhost:8080")
        monkeypatch.setenv("DEFECTDOJO_API_KEY", "test-key-123")
        client = DefectDojoClient()
        assert client.configured

    def test_list_products_not_configured(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        client = DefectDojoClient()
        assert client.list_products() == []

    def test_import_not_configured(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        client = DefectDojoClient()
        findings = [_make_finding()]
        result = client.import_findings(findings, engagement_id=1)
        assert result["configured"] is False

    def test_connection_not_configured(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        client = DefectDojoClient()
        result = client.test_connection()
        assert result["configured"] is False
        assert "Missing" in result["error"]

    def test_parse_cwe(self):
        assert DefectDojoClient._parse_cwe("CWE-89") == 89
        assert DefectDojoClient._parse_cwe("cwe-79") == 79
        assert DefectDojoClient._parse_cwe(None) is None
        assert DefectDojoClient._parse_cwe("") is None
        assert DefectDojoClient._parse_cwe("invalid") is None

    def test_get_or_create_product_not_configured(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        client = DefectDojoClient()
        assert client.get_or_create_product("test") is None

    def test_create_engagement_not_configured(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        client = DefectDojoClient()
        assert client.create_engagement("test", product_id=1) is None


class TestImportToDefectdojo:
    def test_not_configured(self, monkeypatch):
        monkeypatch.delenv("DEFECTDOJO_URL", raising=False)
        monkeypatch.delenv("DEFECTDOJO_API_KEY", raising=False)
        findings = [_make_finding()]
        result = import_to_defectdojo(findings, "test_product")
        assert result["configured"] is False

    def test_import_with_no_findings(self, monkeypatch):
        monkeypatch.setenv("DEFECTDOJO_URL", "http://localhost:8080")
        monkeypatch.setenv("DEFECTDOJO_API_KEY", "test-key")
        # This will fail at connection but tests the code path
        client = DefectDojoClient()
        result = client.import_findings([], engagement_id=1)
        assert result["configured"] is True
        assert result["imported"] == 0
