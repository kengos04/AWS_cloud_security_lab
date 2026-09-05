def test_high_severity_finding_is_detected():
    findings = [
        {
            "rule_id": "TEST-001",
            "severity": "High",
            "title": "Test high severity finding",
            "description": "Test description",
            "recommendation": "Test recommendation",
            "resource": "test-resource"
        }
    ]

    blocking_findings = [
        finding for finding in findings
        if finding.get("severity") in ["Critical", "High"]
    ]

    assert len(blocking_findings) == 1

def test_medium_finding_does_not_block():
    findings = [
        {
            "rule_id": "TEST-002",
            "severity": "Medium",
            "title": "Test medium severity finding",
            "description": "Test description",
            "recommendation": "Test recommendation",
            "resource": "test-resource"
        }
    ]

    blocking_findings = [
        finding for finding in findings
        if finding.get("severity") in ["Critical", "High"]
    ]

    assert blocking_findings == []