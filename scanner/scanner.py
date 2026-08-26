import json
import boto3
from boto3 import s3
from botocore.retries import bucket
from checks.s3 import check_s3_versioning,check_s3_public_access,check_s3_approved_encryption
from checks.security_groups import check_database_exposure,check_ssh_exposure,check_rdp_exposure

def cloud_security_check(security_group,s3_client,buckets):
    findings = []
    #Security Group Checks
    findings.extend(check_database_exposure(security_group))
    findings.extend(check_ssh_exposure(security_group))
    findings.extend(check_rdp_exposure(security_group))

    #S3 checks
    for bucket in buckets["Buckets"]:
        bucket_name = bucket["Name"]
        findings.extend(check_s3_approved_encryption(s3_client,bucket_name))
        findings.extend(check_s3_public_access(s3_client,bucket_name))
        findings.extend(check_s3_versioning(s3_client,bucket_name))

    return findings

def print_findings(findings):
    if not findings:
        print("No security findings.")
        return

    print(f"\nFound {len(findings)} security finding(s):\n")

    for finding in findings:
        print("=" * 50)
        print(f"Rule:     {finding['rule_id']}")
        print(f"Severity: {finding['severity']}")
        print(f"Title:    {finding['title']}")
        print(f"Resource: {finding.get('resource', 'N/A')}")

def save_findings(findings):
    report = {
        "target": "LocalStack",
        "region": "eu-west-1",
        "findings": findings
    }
    with open("findings.json", "w") as file:
        json.dump(report, file,indent=4)

endpoint_url = "http://localhost.localstack.cloud:4566"
def main():
    ec2_client = boto3.client("ec2", endpoint_url=endpoint_url,region_name="eu-west-1",aws_access_key_id="test",aws_secret_access_key = "test")
    ec2_result = ec2_client.describe_security_groups()
    s3_client = boto3.client("s3",endpoint_url=endpoint_url,aws_access_key_id="test",aws_secret_access_key = "test")
    s3_result = s3_client.list_buckets()
    findings = cloud_security_check(ec2_result["SecurityGroups"][0],s3_client,s3_result)
    print_findings(findings)
    save_findings(findings)




if __name__ == "__main__":
    main()

