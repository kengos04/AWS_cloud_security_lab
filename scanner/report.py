import json
def create_report(findings,filename="security_report.json"):
    summary = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    for finding in findings:
        severity = finding.get("severity")
        if severity in summary:
            summary[severity] += 1

    report = {
        "target": "LocalStack",
        "region": "eu-west-1",
        "summary": summary,
        "findings": findings
    }
    with open(filename, "w") as file:
        json.dump(report, file,indent=4)
