
def check_ssh_exposure(security_group):
    for rule in security_group["IpPermissions"]:
        if rule["IpProtocol"] != "tcp":
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is None or to_port is None:
            continue
        if from_port <= 22 <= to_port:
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    return[{
                        "rule_id": "SG-001",
                        "severity": "Critical",
                        "title": "SSH exposed to internet",
                        "description": "SSH can be publicly accessed, allowing instance to be compromised.",
                        "recommendation": "Either removal of SSH or strict network isolation is recommended.",
                        "resource": security_group["GroupId"]
                    }]



    return []

def check_rdp_exposure(security_group):
    for rule in security_group["IpPermissions"]:
        if rule["IpProtocol"] != "tcp":
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is None or to_port is None:
            continue
        if from_port <= 3389 <= to_port:
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    return[{
                        "rule_id": "SG-002",
                        "severity": "Critical",
                        "title": "RDP exposed to internet",
                        "description": "Remote Desktop Protocol is exposed, leaving instance vulnerable to randomware and data breach.",
                        "recommendation": "Closing port 3389 or usage of EC2 instance connect is recommended.",
                        "resource": security_group["GroupId"]
                    }]


    return []

def check_database_exposure(security_group):
    database = {
        3306: "MYSQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB",
    }
    for rule in security_group["IpPermissions"]:
        if rule["IpProtocol"] != "tcp":
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is None or to_port is None:
            continue
        for port, name in database.items():
            if from_port <= port<= to_port:
                for cidr in rule.get("IpRanges", []):
                    if cidr.get("CidrIp") == "0.0.0.0/0":
                        return[{
                            "rule_id": "SG-003",
                            "severity": "Critical",
                            "title": f"{name} exposed to internet",
                            "description": "Current database being used for the instance is vulnerable, risk of data theft, leaks and ransomware.",
                            "recommendation": "Network isolation through private subnets or tightening the security group is recommended.",
                            "resource": security_group["GroupId"]
                        }]


    return []