def check_iam_unrestricted_permission(document,policyname):
    findings = []
    for statement in document["Statement"]:
        action = statement.get("Action")
        effect = statement.get("Effect")
        resource = statement.get("Resource")
        if effect == "Allow" and action == "*" and resource == "*":
            findings.append({
                "rule_id": "IAM-001",
                "severity": "Critical",
                "title": "Policy with unrestricted access",
                "description": "This policy allows for any action on any resource.",
                "recommendation": "Usage of Least Privilage is recommended.",
                "resource": policyname
            })


    return findings

def check_iam_wildcard_permission(document,policyname):
    findings = []
    for statement in document["Statement"]:
        action = statement.get("Action")
        effect = statement.get("Effect")
        resource = statement.get("Resource")
        if effect != "Allow" or resource != "*":
            continue
        if isinstance(action, str):
            actions = [action]
        else:
            actions = action or []
        for action_item in actions:
            if  action_item.endswith(":*"):
                findings.append({
                    "rule_id": "IAM-002",
                    "severity": "High",
                    "title": "Policy grants wildcard service permissions",
                    "description": "This policy allows for all action on specific resource.",
                    "recommendation": "Usage of Least Privilage is recommended.",
                    "resource": policyname
                })
    return findings

def check_iam_sensitive_iam_permission(document,policyname):
    findings = []
    sensitive_iam = {
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:AttachUserPolicy",
        "iam:AttachRolePolicy",
        "iam:PutUserPolicy",
        "iam:PutRolePolicy",
        "iam:PassRole",
                     }
    for statement in document["Statement"]:
        action = statement.get("Action")
        effect = statement.get("Effect")
        resource = statement.get("Resource")
        if effect != "Allow" or resource != "*":
            continue
        if isinstance(action, str):
            actions = [action]
        else:
            actions = action or []
        for iam_policy in sensitive_iam:
            for action_item in actions:
                if  action_item == iam_policy:
                    findings.append({
                        "rule_id": "IAM-003",
                        "severity": "Medium",
                        "title": "Sensitive IAM policies are being permitted",
                        "description": "Possibly allows user or roles to escalate access and permissions.",
                        "recommendation": "Enforcing Least Privilage is recommended.",
                        "resource": policyname
                    })
    return findings

def check_iam_broad_permission(document,policyname):
    findings = []
    necessary_iam = {
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListGroups",
        "iam:ListPolicies",
        "iam:GetAccountSummary",
    }
    for statement in document["Statement"]:
        action = statement.get("Action")
        effect = statement.get("Effect")
        resource = statement.get("Resource")
        if effect != "Allow" or resource != "*":
            continue
        if isinstance(action, str):
            actions = [action]
        else:
            actions = action or []
        for action_item in actions:
            if action_item not in necessary_iam:
                findings.append({
                    "rule_id": "IAM-004",
                    "severity": "Medium",
                    "title": "Possibly too broad IAM policies are being permitted",
                    "description": "Possibly too broad of permission for the required IAM.",
                    "recommendation": "Review policy and enforce Least Privilage if possible.",
                    "resource": policyname
                })
                break


    return findings

def check_iam_pass_role(document,policyname):
    findings = []
    for statement in document["Statement"]:
        action = statement.get("Action")
        effect = statement.get("Effect")
        resource = statement.get("Resource")
        if effect != "Allow" or resource != "*":
            continue
        if isinstance(action, str):
            actions = [action]
        else:
            actions = action or []
        for action_item in actions:
            if action_item == "iam:PassRole":
                findings.append({
                    "rule_id": "IAM-005",
                    "severity": "Medium",
                    "title": "iam:PassRole being allowed on all resources",
                    "description": "Allowing pass role is a possible vulnerability for attackers to escalate privilege.",
                    "recommendation": "Usage of Least Privilage and condition keys are recommended.",
                    "resource": policyname
                })
                break


    return findings