# AWS Resource Inventory

A generic, read-only inventory tool for AWS infrastructure.

## Requirements

- Python 3.9+
- AWS CLI v2
- An AWS IAM Identity Center (SSO) profile with read-only permissions

## Run

```bash
python3 scripts/discovery.py --lookback-days 30
```

Authenticate manually before running the script. The script never starts an SSO login. It uses the active AWS CLI profile (AWS_PROFILE or default) and verifies that STS credentials are available. Optional flags: --profile PROFILE and --expected-account-id ACCOUNT_ID.

## Coverage

- Secrets Manager: metadata and last-accessed date
- EFS: file systems, storage size and mount targets
- KMS: key metadata, aliases and tags
- Elastic Load Balancing: classic, application and network load balancers
- EC2: instance inventory
- RDS: instances and clusters
- Route 53: private hosted zones and VPC associations

The script scans enabled AWS regions, and Route 53 globally. Outputs are written locally to `reports/`: `inventory.json`, `inventory.csv`, `summary.json` and `errors.json`, plus `resource-report.csv` with one column per discovered tag key and explicit activity evidence.

## Safety

No resource mutations, secret value reads or deletion decisions. Reports may contain sensitive infrastructure metadata and must never be committed to a public repository. Review dependencies, Terraform ownership, usage metrics, costs and approvals independently before considering any cleanup.

API errors are captured in `errors.json`; a scan with errors is incomplete. The tool does not guarantee a complete dependency graph or estimate savings.

## Activity evidence

- Secrets Manager: last retrieval date from AWS metadata (not all secret operations).
- EC2: last daily positive CPUUtilization datapoint within the lookback window; CPU activity does not establish business use.
- RDS instances: last daily positive DatabaseConnections datapoint within the lookback window.
- EFS: last daily positive TotalIOBytes datapoint within the lookback window.
- Application Load Balancers: last daily positive RequestCount datapoint within the lookback window.
- KMS, Route 53, Classic/NLB, and RDS clusters: last activity is not available in this version; the report says so rather than inventing a date.

CloudWatch metrics are evidence proxies, not definitive last-used timestamps. Missing datapoints do not establish inactivity. CloudWatch lookback is configurable from 1 to 90 days. API failures are recorded in errors.json. No login, cleanup, or modification calls are made.
