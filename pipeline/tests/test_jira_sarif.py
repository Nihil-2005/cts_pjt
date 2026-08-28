"""Tests for Jira integration and SARIF/CycloneDX/DefectDojo export."""
from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import patch


from pipeline.sarif_export import (
    findings_to_sarif,
    finding_to_sarif_result,
    write_sarif,
    findings_to_cyclonedx,
    write_cyclonedx,
    findings_to_defectdojo,
    finding_to_defectdojo,
    write_defectdojo,
    SEVERITY_LEVEL,
)
from pipeline.jira_client import (
    JiraClient,
    PRIORITY_MAP,
    JIRA_STATUS_MAP,
    LIFECYCLE_TO_JIRA_TRANSITION,
)
from pipeline.models import Finding


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        scanner="nuclei",
        product="test_app",
        title="SQL Injection in /api/login",
        severity="high",
        cve="CVE-2024-1234",
        cwe="CWE-89",
        endpoint="/api/login",
        score=85.0,
        priority="P1",
        description="SQL injection allows authentication bypass",
        remediation="Use parameterized queries",
        dedup_key="test-001",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestSARIFExport:
    def test_finding_to_sarif_result(self):
        f = _make_finding()
        result = finding_to_sarif_result(f)
        assert result["ruleId"] == "CWE-89"  # CWE preferred over CVE for consistent rule keying
        assert result["level"] == "error"  # high → error
        assert result["properties"]["severity"] == "high"
        assert result["properties"]["score"] == 85.0
        assert result["properties"]["scanner"] == "nuclei"

    def test_findings_to_sarif(self):
        findings = [_make_finding(dedup_key=f"f{i}") for i in range(3)]
        sarif = findings_to_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "devsecops-pipeline"
        assert len(sarif["runs"][0]["results"]) == 3

    def test_sarif_excludes_quarantined(self):
        active = _make_finding(dedup_key="active")
        quarantined = _make_finding(dedup_key="quarantined", status="quarantined")
        sarif = findings_to_sarif([active, quarantined])
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_rules_grouped(self):
        # Same CWE = grouped into 1 rule
        f1 = _make_finding(dedup_key="f1", cwe="CWE-89", cve="CVE-2024-1111")
        f2 = _make_finding(dedup_key="f2", cwe="CWE-89", cve="CVE-2024-2222")
        sarif = findings_to_sarif([f1, f2])
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # same CWE = 1 rule

        # Different CWE = 2 rules
        f3 = _make_finding(dedup_key="f3", cwe="CWE-79", cve="CVE-2024-3333")
        sarif2 = findings_to_sarif([f1, f3])
        rules2 = sarif2["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules2) == 2

    def test_write_sarif(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "results.sarif")
            findings = [_make_finding()]
            write_sarif(path, findings)
            assert os.path.exists(path)
            with open(path) as fh:
                data = json.load(fh)
            assert data["version"] == "2.1.0"

    def test_severity_mapping(self):
        assert SEVERITY_LEVEL["critical"] == "error"
        assert SEVERITY_LEVEL["high"] == "error"
        assert SEVERITY_LEVEL["medium"] == "warning"
        assert SEVERITY_LEVEL["low"] == "note"
        assert SEVERITY_LEVEL["info"] == "none"


class TestCycloneDXExport:
    def test_finding_with_package(self):
        f = _make_finding(package="lodash", installed_version="4.17.20", fixed_version="4.17.21")
        bom = findings_to_cyclonedx([f])
        assert bom["specVersion"] == "1.5"
        assert len(bom["components"]) == 1
        assert bom["components"][0]["name"] == "lodash"

    def test_no_packages(self):
        f = _make_finding()  # no package
        bom = findings_to_cyclonedx([f])
        assert len(bom["components"]) == 0

    def test_dedup_packages(self):
        f1 = _make_finding(dedup_key="f1", package="lodash", installed_version="4.17.20")
        f2 = _make_finding(dedup_key="f2", package="lodash", installed_version="4.17.20")
        bom = findings_to_cyclonedx([f1, f2])
        assert len(bom["components"]) == 1

    def test_write_cyclonedx(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bom.json")
            f = _make_finding(package="express", installed_version="4.18.0", fixed_version="4.18.2")
            write_cyclonedx(path, [f])
            assert os.path.exists(path)
            with open(path) as fh:
                data = json.load(fh)
            assert data["bomFormat"] == "CycloneDX"


class TestDefectDojoExport:
    def test_finding_to_defectdojo(self):
        f = _make_finding()
        dd = finding_to_defectdojo(f)
        assert dd["title"] == "SQL Injection in /api/login"
        assert dd["severity"] == "HIGH"
        assert dd["cwe"] == 89
        assert dd["cve"] == "CVE-2024-1234"
        assert dd["active"] is True

    def test_quarantined_not_active(self):
        f = _make_finding(status="quarantined")
        dd = finding_to_defectdojo(f)
        assert dd["active"] is False
        assert dd["false_p"] is True

    def test_findings_to_defectdojo(self):
        findings = [_make_finding(dedup_key=f"f{i}") for i in range(5)]
        data = findings_to_defectdojo(findings, engagement_name="Test Run")
        assert data["engagement"]["name"] == "Test Run"
        assert len(data["findings"]) == 5

    def test_write_defectdojo(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "defectdojo.json")
            findings = [_make_finding()]
            write_defectdojo(path, findings)
            assert os.path.exists(path)
            with open(path) as fh:
                data = json.load(fh)
            assert "findings" in data
            assert len(data["findings"]) == 1


class TestJiraClient:
    @patch.dict(os.environ, {"JIRA_URL": "", "JIRA_USER": "", "JIRA_TOKEN": "", "JIRA_PROJECT": ""}, clear=False)
    def test_not_configured_by_default(self):
        client = JiraClient()
        assert not client.configured

    def test_priority_map(self):
        assert PRIORITY_MAP["P1"]["jira"] == "Highest"
        assert PRIORITY_MAP["P4"]["jira"] == "Low"

    def test_jira_status_map(self):
        assert JIRA_STATUS_MAP["in progress"] == "in_progress"
        assert JIRA_STATUS_MAP["done"] == "fixed"

    def test_lifecycle_to_jira(self):
        assert LIFECYCLE_TO_JIRA_TRANSITION["in_progress"] == "In Progress"
        assert LIFECYCLE_TO_JIRA_TRANSITION["fixed"] == "Done"

    @patch.dict(os.environ, {"JIRA_URL": "", "JIRA_USER": "", "JIRA_TOKEN": "", "JIRA_PROJECT": ""}, clear=False)
    def test_create_issue_not_configured(self):
        client = JiraClient()
        f = _make_finding()
        result = client.create_issue(f)
        assert result["configured"] is False

    @patch.dict(os.environ, {"JIRA_URL": "", "JIRA_USER": "", "JIRA_TOKEN": "", "JIRA_PROJECT": ""}, clear=False)
    def test_bulk_create_not_configured(self):
        client = JiraClient()
        findings = [_make_finding(dedup_key=f"f{i}") for i in range(3)]
        result = client.create_issues_bulk(findings)
        assert result["created"] == 0

    @patch.dict(os.environ, {"JIRA_URL": "", "JIRA_USER": "", "JIRA_TOKEN": "", "JIRA_PROJECT": ""}, clear=False)
    def test_test_connection_not_configured(self):
        client = JiraClient()
        result = client.test_connection()
        assert result["configured"] is False
        assert "Missing" in result["error"]
