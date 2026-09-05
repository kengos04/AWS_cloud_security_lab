from scanner.checks.s3 import(
    check_s3_public_access,
    check_s3_versioning,
    check_s3_approved_encryption,
)

class FakeS3Client:
    def __init__(self,public_access_block=None,status = None,algorithm = None):
        self.public_access_block = public_access_block
        self.status = status
        self.algorithm = algorithm

    def get_public_access_block(self,Bucket):
        return{
            "PublicAccessBlockConfiguration": self.public_access_block
        }

    def get_bucket_encryption(self, Bucket):
        return {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": self.algorithm
                    }
                }]
            }
        }

    def get_bucket_versioning(self,Bucket):
        return {
            "Status": self.status
        }

def test_s3_public_access_block_missing():
    client = FakeS3Client(
        public_access_block={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
    )
    findings = check_s3_public_access(client,"test_bucket")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "S3-001"
    assert findings[0]["severity"] == "Critical"
    assert findings[0]["resource"] == "test_bucket"

def test_s3_public_access_block_enabled():
    client = FakeS3Client(
        public_access_block={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    )
    findings = check_s3_public_access(client,"test_bucket")

    assert findings == []

def test_s3_approved_aes256_encryption():
    client = FakeS3Client(algorithm = "AES256")
    findings = check_s3_approved_encryption(client,"test_bucket")

    assert findings == []

def test_s3_approved_kms_encryption():
    client = FakeS3Client(algorithm ="aws:kms")
    findings = check_s3_approved_encryption(client,"test_bucket")

    assert findings == []

def test_s3_unapproved_encryption():
    client = FakeS3Client(algorithm ="SSE-C")
    findings = check_s3_approved_encryption(client,"test_bucket")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "S3-002"
    assert findings[0]["severity"] == "Medium"
    assert findings[0]["resource"] == "test_bucket"

def test_s3_versioning_enabled():
    client = FakeS3Client(status="Enabled")
    findings = check_s3_versioning(client,"test_bucket")

    assert findings == []

def test_s3_versioning_disabled():
    client = FakeS3Client(None)
    findings = check_s3_versioning(client,"test_bucket")

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "S3-003"
    assert findings[0]["severity"] == ("Medium")
    assert findings[0]["resource"] == "test_bucket"