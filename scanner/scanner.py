import boto3
from boto3 import s3
from botocore.retries import bucket


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

def check_s3_public_access(client, bucketname):
    public_access_block = client.get_public_access_block(Bucket = bucketname)["PublicAccessBlockConfiguration"]
    block_public_acls = public_access_block["BlockPublicAcls"]
    ignore_public_acls = public_access_block["IgnorePublicAcls"]
    block_public_policy = public_access_block["BlockPublicPolicy"]
    restrict_public_buckets = public_access_block["RestrictPublicBuckets"]
    if not block_public_acls or not ignore_public_acls or not restrict_public_buckets or not block_public_policy:
        print("Rule: S3-001")
        print("Crucial")
        print("S3 bucket has missing public access blocks")
        print(f"Resource: {bucketname}")

    pass

def check_s3_approved_encryption(client, bucketname):
    encryption_rules = client.get_bucket_encryption(Bucket = bucketname)["ServerSideEncryptionConfiguration"]["Rules"]
    for rule in encryption_rules:
        encryption = rule["ApplyServerSideEncryptionByDefault"]
        algorithm = encryption.get("SSEAlgorithm")
        if algorithm in ["AES256","aws:kms"]:
            print("Using approved encryption: ", algorithm)
        else:
            print("Rule: S3-002")
            print("Medium")
            print("Using unapproved encryption: ", algorithm)
            print(f"Resource: {bucketname}")

    pass

def check_s3_versioning(client,bucketname):
    versioning = client.get_bucket_versioning(Bucket = bucketname)
    if versioning.get("Status") == "Enabled":
        print("Versioning Enabled")
    else:
        print("Rule S3-003")
        print("Medium")
        print("Versioning Disabled")
        print(f"Resource: {bucketname}")

    pass
endpoint_url = "http://localhost.localstack.cloud:4566"
def main():
    ec2_client = boto3.client("ec2", endpoint_url=endpoint_url,region_name="eu-west-1",aws_access_key_id="test",aws_secret_access_key = "test")
    ec2_result = ec2_client.describe_security_groups()
    s3_client = boto3.client("s3",endpoint_url=endpoint_url,aws_access_key_id="test",aws_secret_access_key = "test")
    s3_result = s3_client.list_buckets()
    for bucket in s3_result["Buckets"]:
        bucket_name = bucket["Name"]
        print(bucket_name)
        versioning = s3_client.get_bucket_versioning(Bucket = bucket_name)
        #print(versioning)
        check_s3_versioning(s3_client,bucket_name)


if __name__ == "__main__":
    main()

