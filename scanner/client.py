import boto3
def create_client(endpoint_url,region_name):
    ec2_client = boto3.client(
        "ec2",
        endpoint_url=endpoint_url,
        region_name="eu-west-1",
        aws_access_key_id="test",
        aws_secret_access_key = "test"
    )
    s3_client = boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id="test",
        aws_secret_access_key = "test"
    )
    iam_client = boto3.client(
        "iam",
        endpoint_url=endpoint_url,
        region_name = "eu-west-1",
        aws_access_key_id="test",
        aws_secret_access_key = "test"
    )
    return ec2_client,s3_client,iam_client