import sys
import argparse
from report import create_report
from client import create_client
from checks.s3 import check_s3_versioning,check_s3_public_access,check_s3_approved_encryption
from checks.security_groups import check_database_exposure,check_ssh_exposure,check_rdp_exposure
from checks.iam import check_iam_unrestricted_permission,check_iam_wildcard_permission,check_iam_sensitive_iam_permission,check_iam_broad_permission,check_iam_pass_role
from checks.ec2 import check_ec2_public_address,check_ec2_metadata_service,check_ec2_ebs_encryption,check_ec2_termination_protection

def cloud_security_check(ec2_client,s3_client,iam_client):
    findings = []
    #Security Group Checks
    ec2_security_groups = ec2_client.describe_security_groups()
    findings.extend(check_database_exposure(ec2_security_groups["SecurityGroups"][0]))
    findings.extend(check_ssh_exposure(ec2_security_groups["SecurityGroups"][0]))
    findings.extend(check_rdp_exposure(ec2_security_groups["SecurityGroups"][0]))

    #S3 checks
    s3_buckets = s3_client.list_buckets()
    for bucket in s3_buckets["Buckets"]:
        bucket_name = bucket["Name"]
        findings.extend(check_s3_approved_encryption(s3_client,bucket_name))
        findings.extend(check_s3_public_access(s3_client,bucket_name))
        findings.extend(check_s3_versioning(s3_client,bucket_name))

    #IAM Checks
    iam_policies = iam_client.list_policies(Scope="Local")
    for policy in iam_policies["Policies"]:
        policy_version = iam_client.get_policy_version(PolicyArn=policy["Arn"],VersionId = policy["DefaultVersionId"])
        document = policy_version["PolicyVersion"]["Document"]
        findings.extend(check_iam_unrestricted_permission(document,policy["PolicyName"]))
        findings.extend(check_iam_wildcard_permission(document,policy["PolicyName"]))
        findings.extend(check_iam_sensitive_iam_permission(document,policy["PolicyName"]))
        findings.extend(check_iam_broad_permission(document,policy["PolicyName"]))
        findings.extend(check_iam_pass_role(document,policy["PolicyName"]))

    #EC2 Check
    ec2_volumes = ec2_client.describe_volumes()
    ec2_reservations = ec2_client.describe_instances()
    for reservation in ec2_reservations["Reservations"]:
        for instance in reservation["Instances"]:
            ec2_instance_attribute = ec2_client.describe_instance_attribute(InstanceId=instance["InstanceId"],Attribute="disableApiTermination")
            instance_name = instance.get("Tags")[0]["Value"]
            findings.extend(check_ec2_public_address(instance,instance_name))
            findings.extend(check_ec2_metadata_service(instance,instance_name))
            findings.extend(check_ec2_ebs_encryption(instance,instance_name,ec2_volumes))
            findings.extend(check_ec2_termination_protection(ec2_instance_attribute,instance_name))

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
        print(f"Description:  {finding['description']}")
        print(f"Recommendation: {finding['recommendation']}")
        print(f"Resource: {finding.get('resource', 'N/A')}")



def parse_arguments():
    parser = argparse.ArgumentParser(description="Cloud Security Checker")
    parser.add_argument(
        "--endpoint",
        default="http://localhost:4566",
        help="AWS endpoint URL"
    )
    parser.add_argument(
        "--region",
        default="ew-west-1",
        help="AWS region"
    )
    return parser.parse_args()

#endpoint_url = "http://localhost.localstack.cloud:4566"
def main():
    args = parse_arguments()
    endpoint_url = args.endpoint
    region = args.region
    ec2_client,s3_client,iam_client = create_client(endpoint_url,"eu-west-1")
    findings = cloud_security_check(ec2_client,s3_client,iam_client)
    #print_findings(findings)
    create_report(findings)
    for finding in findings:
        if finding.get("severity") in ["Critical","High"]:
            sys.exit(1)
    sys.exit(0)





if __name__ == "__main__":
    main()

