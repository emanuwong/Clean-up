# AWS Resource Inventory

A generic, read-only inventory tool for AWS infrastructure.

## Requirements

- Python 3.9+
- AWS CLI v2
- An AWS IAM Identity Center (SSO) profile with read-only permissions

## Run

```bash
aws sso login --profile audit-readonly
aws --profile audit-readonly sts get-caller-identity
python3 scripts/discovery.py --profile audit-readonly --expected-account-id 123456789012
```

The account ID above is a placeholder. Replace it with the intended AWS account ID.

## Coverage

- Secrets Manager: metadata and last-accessed date
- EFS: file systems, storage size and mount targets
- KMS: key metadata, aliases and tags
- Elastic Load Balancing: classic, application and network load balancers
- EC2: instance inventory
- RDS: instances and clusters
- Route 53: private hosted zones and VPC associations

The script scans enabled AWS regions, and Route 53 globally. Outputs are written locally to `reports/`: `inventory.json`, `inventory.csv`, `summary.json` and `errors.json`.

## Safety

No resource mutations, secret value reads or deletion decisions. Reports may contain sensitive infrastructure metadata and must never be committed to a public repository. Review dependencies, Terraform ownership, usage metrics, costs and approvals independently before considering any cleanup.

API errors are captured in `errors.json`; a scan with errors is incomplete. The tool does not guarantee a complete dependency graph or estimate savings.
