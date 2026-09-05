
# Cloud Security Scanner

A Python-based cloud security scanner for AWS-compatible environments.

This project uses **Python, boto3, Terraform, and LocalStack** to provision cloud resources locally and identify common security misconfigurations through automated security checks.

The project was built as a practical security engineering exercise covering cloud security, Infrastructure as Code, AWS APIs, automated security checks, reporting, and CI testing.

----------

## Features

The scanner currently checks for security issues across several AWS services.

### Amazon S3

-   **S3-001** — S3 public access blocks are missing or disabled
    
-   **S3-002** — S3 bucket encryption configuration
    
-   **S3-003** — S3 bucket versioning is disabled
    

### IAM

-   **IAM-001** — Unrestricted IAM access
    
-   **IAM-002** — Wildcard IAM actions
    
-   **IAM-003** — Sensitive IAM permissions
    
-   **IAM-004** — Broad IAM permissions
    
-   **IAM-005** — `iam:PassRole` permissions
    

### Security Groups

-   **SG-001** — SSH exposed to the internet
    
-   **SG-002** — RDP exposed to the internet
    
-   **SG-003** — Database ports exposed to the internet
    

### EC2

-   **EC2-001** — IMDSv1 is allowed
    
-   **EC2-002** — EBS volume is unencrypted
    
-   **EC2-003** — EC2 termination protection is disabled
    

The scanner produces structured findings containing:

-   Rule ID
    
-   Severity
    
-   Title
    
-   Description
    
-   Recommendation
    
-   Affected resource
    

----------

## Architecture

```text
Terraform
    │
    ▼
AWS-compatible environment
(LocalStack)
    │
    ▼
boto3
    │
    ▼
Python Security Scanner
    │
    ├── Security Group checks
    ├── S3 checks
    ├── IAM checks
    └── EC2 checks
    │
    ▼
Security Findings
    │
    ▼
JSON Security Report

```

----------

## Project Structure

```text
localstack_lab/
│
├── main.tf
├── variables.tf
├── outputs.tf
├── requirements.txt
├── README.md
├── .gitignore
│
├── scanner/
│   ├── scanner.py
│   ├── clients.py
│   ├── report.py
│   │
│   └── checks/
│       ├── __init__.py
│       ├── ec2.py
│       ├── iam.py
│       ├── s3.py
│       └── security_groups.py
│
└── tests/
    ├── test_ec2.py
    ├── test_iam.py
    ├── test_s3.py
    └── test_security_groups.py

```

----------


## Technologies

- **Python** — scanner implementation

- **boto3** — AWS API interaction
- **Terraform** — infrastructure provisioning
- **LocalStack** — local AWS-compatible testing environment
- **Docker** — container runtime for the local cloud environment
- **pytest** — automated testing
- **GitHub Actions** — continuous integration
- **Git** — source control
    

----------

## Requirements

Before running the project, install:

-   Python 3.x
    
-   Terraform
    
-   LocalStack

-  Docker
    
-   AWS CLI
    
-   Git
    

Python dependencies are listed in `requirements.txt`.

----------

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd localstack_lab

```

Create a virtual environment:

```bash
python -m venv .venv

```

Activate it on Windows:

```powershell
.venv\Scripts\activate

```

Install the Python dependencies:

```bash
pip install -r requirements.txt

```

----------

## Deploy the Test Infrastructure

Initialize Terraform:

```bash
tflocal init

```

Review the planned infrastructure:

```bash
tflocal plan

```

Apply the infrastructure:

```bash
tflocal apply

```

The Terraform configuration creates intentionally vulnerable resources that can be used to test the scanner.

----------

## Running the Scanner

Start the local AWS-compatible environment first.

Then run:

```bash
python scanner/scanner.py

```

The scanner connects to the configured AWS-compatible endpoint and evaluates the deployed resources.

The scanner generates a JSON report containing the security findings and severity summary.

Example:

```json
{
    "target": "LocalStack",
    "region": "eu-west-1",
    "summary": {
        "Critical": 2,
        "High": 3,
        "Medium": 2,
        "Low": 0
    },
    "findings": [
        {
            "rule_id": "S3-001",
            "severity": "Critical",
            "title": "S3 bucket has missing public access blocks",
            "description": "...",
            "recommendation": "...",
            "resource": "example-bucket"
        }
    ]
}

```

----------

## Command-Line Options

The scanner supports configuration through command-line arguments.

Example:

```bash
python scanner/scanner.py --endpoint http://localhost:4566 --region eu-west-1

```

Available options:

```text
--endpoint    AWS-compatible API endpoint
--region      AWS region

```

The default endpoint is:

```text
http://localhost:4566

```

The default region is:

```text
eu-west-1

```

----------

## Severity Levels

Findings are classified by severity.

Severity

Meaning

Critical

Severe security exposure that should be addressed immediately

High

Significant security risk requiring prompt remediation

Medium

Security weakness that should be reviewed and remediated

Low

Lower-risk security improvement

----------

## Exit Codes

The scanner can be used in automation and CI pipelines.

If a **Critical** or **High** severity finding is detected, the scanner exits with status code `1`.

If no Critical or High findings are detected, the scanner exits with status code `0`.

This allows CI/CD systems to fail automatically when serious security issues are detected.

Example:

```powershell
python scanner/scanner.py

$LASTEXITCODE

```

----------

## Testing

The project uses `pytest` for automated testing.

Run the test suite with:

```bash
pytest

```

The tests focus on the scanner's security-checking logic using representative AWS API responses.

Both vulnerable and secure configurations are tested to reduce false positives and verify that each security rule behaves as expected.

----------

## Security Checks

Each security check is implemented as an independent rule.

For example:

```text
Security Group
      │
      ▼
Is TCP/22 open?
      │
   ┌──┴──┐
   │     │
  Yes    No
   │     │
Finding  Pass

```

This structure makes individual checks easier to test, maintain, and extend.

----------

## Example Findings

A vulnerable environment may produce findings such as:

```text
[CRITICAL] SG-001
SSH exposed to the internet

[CRITICAL] S3-001
S3 bucket has missing public access blocks

[HIGH] IAM-005
iam:PassRole permission detected

[MEDIUM] EC2-003
EC2 termination protection is disabled

```

The full results are stored in the generated JSON security report.

----------

## Infrastructure as Code

Terraform is used to create the test environment.

This makes the security scenarios reproducible rather than relying on manually configured cloud resources.

The infrastructure can be destroyed with:

```bash
tflocal destroy

```

This allows the environment to be recreated and tested repeatedly.

----------

## CI/CD

GitHub Actions is used to automatically run the project's tests.

The intended workflow is:

```text
Git Push
   │
   ▼
GitHub Actions
   │
   ▼
Install dependencies
   │
   ▼
Run pytest
   │
   ▼
Run security scanner
   │
   ▼
Check scanner exit code
   │
   ├── Critical/High → Fail
   │
   └── No Critical/High → Pass

```

This demonstrates how security checks can be incorporated into an automated development workflow.

----------

## Future Improvements

Potential future improvements include:

-   Additional AWS security checks
    
-   More comprehensive IAM policy analysis
    
-   Improved finding metadata
    
-   HTML report generation
    
-   SARIF output for GitHub Security integration
    
-   Support for scanning real AWS accounts
    
-   Configuration files for custom rules
    
-   Improved test coverage
    
-   Parallel scanning of AWS resources
    
-   Additional CI security tooling
    

----------

## Purpose

This project was created to develop practical experience with:

-   Cloud security
    
-   AWS security controls
    
-   Python automation
    
-   AWS APIs
    
-   Infrastructure as Code
    
-   Security testing
    
-   Vulnerability detection
    
-   Automated reporting
    
-   CI/CD security
    

It is designed as a reproducible security lab where intentionally insecure cloud configurations can be provisioned and detected automatically.

----------
