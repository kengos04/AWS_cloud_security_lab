from scanner.checks.ec2 import(
    check_ec2_public_address,
    check_ec2_metadata_service,
    check_ec2_ebs_encryption,
    check_ec2_termination_protection,
)

#Testing EC2-001
def test_ec2_public_address():
    instance = {"PublicIp": "1.2.3.4"}
    findings = check_ec2_public_address(instance,"test-instance")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EC2-001"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-instance"

def test_ec2_no_public_address():
    instance = {"PublicIp": None}
    findings = check_ec2_public_address(instance,"test-instance")

    assert findings == []

#Testing EC-002
def test_ec2_metadata_service_imdsv1():
    instance = {
        "MetadataOptions": {
            "HttpTokens": "optional"
        }
    }
    findings = check_ec2_metadata_service(instance,"test-instance")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EC2-002"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-instance"

def test_ec2_metadata_service_imdsv2():
    instance = {
        "MetadataOptions": {
            "HttpTokens": "required"
        }
    }
    findings = check_ec2_metadata_service(instance,"test-instance")

    assert findings == []

#Testing EC2-003
def test_ec2_ebs_unencrypted():
    instance = {
        "BlockDeviceMappings": [{
            "DeviceName": "/dev/sda1",
            "Ebs":{
                "VolumeId": "volume-test123",
            }
        }]
    }
    ec2_volumes = {
        "Volumes": [{
            "VolumeId": "volume-test123",
            "Encrypted": False
        }]
    }
    findings = check_ec2_ebs_encryption(instance,"test-instance",ec2_volumes)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EC2-003"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-instance"

def test_ec2_ebs_encrypted():
    instance = {
        "BlockDeviceMappings": [{
            "DeviceName": "/dev/sda1",
            "Ebs": {
                "VolumeId": "volume-test123",
            }
        }]
    }
    ec2_volumes = {
        "Volumes": [{
            "VolumeId": "volume-test123",
            "Encrypted": True
        }]
    }
    findings = check_ec2_ebs_encryption(instance,"test-instance",ec2_volumes)

    assert findings == []

#Testing EC2-004
def test_ec2_termination_protection_disabled():
    instance_attributes = {
        "DisableApiTermination": {
            "Value": False
        }
    }
    findings = check_ec2_termination_protection(instance_attributes,"test-instance")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EC2-004"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-instance"

def test_ec2_termination_protection_enabled():
    instance_attributes = {
        "DisableApiTermination": {
            "Value": True
        }
    }
    findings = check_ec2_termination_protection(instance_attributes,"test-instance")

    assert findings == []