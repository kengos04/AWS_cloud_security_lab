import boto3

def cloud_security_check(security_group):
    print("\n==============================\n    CLOUD SECURITY SCANNER     \n==============================\n")

    pass

def check_ssh_exposure(security_group):
    for rule in security_group["IpPermissions"]:
        if rule["IpProtocol"] != "tcp":
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is None or to_port is None:
            continue
        if from_port < 22 < to_port:
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    print("Critical problem")
                    print("SSH exposed to internet")

    pass

def check_rdp_exposure(security_group):
    for rule in security_group["IpPermissions"]:
        if rule["IpProtocol"] != "tcp":
            continue
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        if from_port is None or to_port is None:
            continue
        if from_port < 3389< to_port:
            for cidr in rule.get("IpRanges", []):
                if cidr.get("CidrIp") == "0.0.0.0/0":
                    print("Critical problem")
                    print("RDP exposed to internet")

    pass

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
            if from_port < port< to_port:
                for cidr in rule.get("IpRanges", []):
                    if cidr.get("CidrIp") == "0.0.0.0/0":
                        print("Critical problem")
                        print(f"{name} exposed to internet")

    pass

endpoint_url = "http://localhost.localstack.cloud:4566"
def main():
    ec2_client = boto3.client("ec2", endpoint_url=endpoint_url,region_name="eu-west-1",aws_access_key_id="test",aws_secret_access_key = "test")
    result = ec2_client.describe_security_groups()
    for sg in result["SecurityGroups"]:
        print("\n==============================")
        print("Name:", sg["GroupName"])
        print("ID:", sg["GroupId"])
        print("VPC:", sg["VpcId"])
        print("Rules:")
        has_rules = False
        for rule in sg["IpPermissions"]:
            print(rule)
            has_rules = True
        if has_rules:
            print(sg["IpPermissions"][0]["IpProtocol"])
        check_ssh_exposure(sg)
        check_database_exposure(sg)

if __name__ == "__main__":
    main()

