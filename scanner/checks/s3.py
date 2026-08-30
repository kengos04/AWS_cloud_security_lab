

def check_s3_public_access(client, bucketname):
    public_access_block = client.get_public_access_block(Bucket = bucketname)["PublicAccessBlockConfiguration"]
    block_public_acls = public_access_block["BlockPublicAcls"]
    ignore_public_acls = public_access_block["IgnorePublicAcls"]
    block_public_policy = public_access_block["BlockPublicPolicy"]
    restrict_public_buckets = public_access_block["RestrictPublicBuckets"]
    if not block_public_acls or not ignore_public_acls or not restrict_public_buckets or not block_public_policy:
        return [{
            "rule_id": "S3-001",
            "severity": "Critical",
            "title": "S3 bucket has missing public access blocks",
            "description": "This S3 bucket allows for unauthroized users to access content.",
            "recommendation": "Enable Block Public Access is recommended.",
            "resource": bucketname
        }]

    return []

def check_s3_approved_encryption(client, bucketname):
    encryption_rules = client.get_bucket_encryption(Bucket = bucketname)["ServerSideEncryptionConfiguration"]["Rules"]
    for rule in encryption_rules:
        encryption = rule["ApplyServerSideEncryptionByDefault"]
        algorithm = encryption.get("SSEAlgorithm")
        if algorithm in ["AES256","aws:kms"]:
            None
        else:
            return[{
                "rule_id": "S3-002",
                "severity": "Medium",
                "title": f"Using unapproved encryption: {algorithm}",
                "description": "Current S3 bucket is not using the required encryption.",
                "recommendation": "Change the encryption method to either AES256 or aws:kms.",
                "resource": bucketname
            }]

    return []

def check_s3_versioning(client,bucketname):
    versioning = client.get_bucket_versioning(Bucket = bucketname)
    if versioning.get("Status") == "Enabled":
        None
    else:
        return[{
            "rule_id": "S3-003",
            "severity": "Medium",
            "title": "S3 bucket versioning is disabled",
            "description": "S3 versioning is disabled, so previous versions of objects cannot be recovered.",
            "recommendation": "Enable versioning on the S3 bucket.",
            "resource": bucketname
        }]

    return []