from scanner.checks.security_groups import (
    check_ssh_exposure,
    check_rdp_exposure,
    check_database_exposure,
)

def test_ssh_exposed_to_internet():
    security_group = {
        "GroupId" : "sg-test123",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    }
    findings = check_ssh_exposure(security_group)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SG-001"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["resource"] == "sg-test123"

def test_ssh_not_exposed():
    security_group = {
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {"CidrIp": "10.0.0.0/16"}
                ]
            }
        ]
    }

    findings = check_ssh_exposure(security_group)

    assert findings == []

def test_rdp_exposed_to_internet():
    security_group = {
        "GroupId" : "sg-test123",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    }
    findings = check_rdp_exposure(security_group)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SG-002"
    assert findings[0]["severity"] == "Critical"

def test_rdp_not_exposed_to_internet():
    security_group = {
        "GroupId" : "sg-test123",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "192.0.10.0/24"}],
        }]
    }
    findings = check_rdp_exposure(security_group)
    assert findings == []

def test_database_exposed_to_internet():
    security_group = {
        "GroupId" : "sg-test123",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 3306,
            "ToPort": 3306,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }]
    }
    findings = check_database_exposure(security_group)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SG-003"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["resource"] == "sg-test123"

def test_database_not_exposed_to_internet():
    security_group = {
        "GroupId" : "sg-test123",
        "IpPermissions": [{
            "IpProtocol": "tcp",
            "FromPort": 3389,
            "ToPort": 3389,
            "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
        }]
    }
    findings = check_database_exposure(security_group)
    assert findings == []