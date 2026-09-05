from scanner.checks.iam import (
    check_iam_unrestricted_permission,
    check_iam_wildcard_permission,
    check_iam_sensitive_iam_permission,
    check_iam_broad_permission,
    check_iam_pass_role,
)

#Testing IAM-001
def test_iam_unrestricted_permission():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*"
        }]
    }
    findings = check_iam_unrestricted_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-001"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["resource"] == "test-policy"

def test_iam_restricted_permission():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::test-bucket"
        }]
    }
    findings = check_iam_unrestricted_permission(document,"test-policy")

    assert findings == []

#Testing IAM-002
def test_iam_wildcard_permission():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:*",
            "Resource": "*"
        }]
    }
    findings = check_iam_wildcard_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-002"
    assert findings[0]["severity"] == "High"
    assert findings[0]["resource"] == "test-policy"

def test_iam_wildcard_permission_safe():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "*"
        }]
    }
    findings = check_iam_wildcard_permission(document,"test-policy")

    assert findings == []

def test_iam_wildcard_permission_list():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject","ec2:*"],
            "Resource": "*"
        }]
    }
    findings = check_iam_wildcard_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-002"
    assert findings[0]["severity"] == "High"
    assert findings[0]["resource"] == "test-policy"

#Testing IAM-003
def test_iam_sensitive_create_user():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:CreateUser",
            "Resource": "*"
        }]
    }
    findings = check_iam_sensitive_iam_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-003"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"

def test_iam_sensitive_attach_policy():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:AttachUserPolicy",
            "Resource": "*"
        }]
    }
    findings = check_iam_sensitive_iam_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-003"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"

def test_iam_sensitive_permission_safe():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "*"
        }]
    }
    findings = check_iam_sensitive_iam_permission(document,"test-policy")

    assert findings == []

def test_iam_sensitive_permission_list():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject","iam:CreateAccessKey"],
            "Resource": "*"
        }]
    }
    findings = check_iam_sensitive_iam_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-003"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"

#Testing IAM-004
def test_iam_broad_permission():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*"
        }]
    }
    findings = check_iam_broad_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-004"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"

def test_iam_broad_permission_safe():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:ListUsers",
            "Resource": "*"
        }]
    }
    findings = check_iam_broad_permission(document,"test-policy")

    assert findings == []

def test_iam_broad_permission_list():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject","iam:ListUsers"],
            "Resource": "*"
        }]
    }
    findings = check_iam_broad_permission(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-004"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"


#Testing IAM-005
def test_iam_pass_role():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "*"
        }]
    }
    findings = check_iam_pass_role(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-005"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"

def test_iam_pass_role_safe():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "*"
        }]
    }
    findings = check_iam_pass_role(document,"test-policy")

    assert findings == []

def test_iam_pass_role_list():
    document = {
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject","iam:PassRole"],
            "Resource": "*"
        }]
    }
    findings = check_iam_pass_role(document,"test-policy")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "IAM-005"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test-policy"