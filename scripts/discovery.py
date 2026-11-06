#!/usr/bin/env python3
"""Generic read-only AWS metadata inventory. Requires AWS CLI v2."""
import argparse
import csv
import datetime as dt
import json
import re
import os
from pathlib import Path
import subprocess
import sys

def aws(profile, args, errors, region=None):
    cmd = ["aws", "--profile", profile, "--no-cli-pager"]
    if region:
        cmd += ["--region", region]
    cmd += args + ["--output", "json"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                                env={**os.environ, "AWS_PAGER": "", "AWS_CLI_AUTO_PROMPT": "off"})
        if result.returncode:
            errors.append({"region": region, "operation": " ".join(args[:2]),
                           "message": result.stderr.strip()[:350]})
            return None
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        errors.append({"region": region, "operation": " ".join(args[:2]), "message": str(exc)[:350]})
        return None

def add(rows, service, region, kind, ident, arn="", name="", state="", tags=None, details=None):
    rows.append({"service": service, "region": region, "type": kind, "id": ident,
                 "arn": arn or "", "name": name or "", "state": state or "",
                 "tags": tags or [], "details": details or {}, "last_activity": None, "activity_source": "Not available from inventory APIs", "activity_note": "Requires service-specific usage evidence"})

def scan(profile, region, rows, errors):
    d = aws(profile, ["secretsmanager", "list-secrets", "--include-planned-deletion"], errors, region)
    if d is not None:
        for x in d.get("SecretList", []):
            add(rows, "secretsmanager", region, "secret", x.get("Name"), x.get("ARN"),
                x.get("Name"), "pending-deletion" if x.get("DeletedDate") else "active",
                x.get("Tags"), {"last_accessed": x.get("LastAccessedDate"),
                                "created": x.get("CreatedDate")})

    d = aws(profile, ["efs", "describe-file-systems"], errors, region)
    if d is not None:
        for x in d.get("FileSystems", []):
            fid = x["FileSystemId"]
            mounts = aws(profile, ["efs", "describe-mount-targets", "--file-system-id", fid], errors, region)
            add(rows, "efs", region, "file_system", fid, x.get("FileSystemArn"),
                x.get("Name"), x.get("LifeCycleState"), x.get("Tags"),
                {"size_bytes": x.get("SizeInBytes", {}).get("Value"),
                 "encrypted": x.get("Encrypted"),
                 "mount_targets": [{"id": m.get("MountTargetId"), "vpc": m.get("VpcId"),
                                    "subnet": m.get("SubnetId")}
                                   for m in (mounts or {}).get("MountTargets", [])]})

    d = aws(profile, ["kms", "list-keys"], errors, region)
    if d is not None:
        for x in d.get("Keys", []):
            kid = x["KeyId"]
            info = aws(profile, ["kms", "describe-key", "--key-id", kid], errors, region)
            if info is None:
                continue
            k = info.get("KeyMetadata", {})
            aliases = aws(profile, ["kms", "list-aliases", "--key-id", kid], errors, region)
            tags = aws(profile, ["kms", "list-resource-tags", "--key-id", kid], errors, region)
            add(rows, "kms", region, "key", kid, k.get("Arn"),
                ",".join(a.get("AliasName", "") for a in (aliases or {}).get("Aliases", [])),
                k.get("KeyState"), (tags or {}).get("Tags"),
                {"manager": k.get("KeyManager"), "usage": k.get("KeyUsage"),
                 "deletion_date": k.get("DeletionDate")})

    for service in ("elbv2", "elb"):
        d = aws(profile, [service, "describe-load-balancers"], errors, region)
        if d is None:
            continue
        for x in d.get("LoadBalancers", []):
            name = x.get("LoadBalancerName")
            arn = x.get("LoadBalancerArn", "")
            flag = "--load-balancer-arns" if service == "elbv2" else "--load-balancer-names"
            tags = aws(profile, [service, "describe-tags", flag, arn or name], errors, region)
            descriptions = (tags or {}).get("TagDescriptions", [])
            add(rows, "load_balancer", region, x.get("Type", "classic"), name, arn,
                name, x.get("State", {}).get("Code", "") if service == "elbv2" else "",
                descriptions[0].get("Tags", []) if descriptions else [],
                {"scheme": x.get("Scheme"), "vpc": x.get("VpcId"), "dns": x.get("DNSName")})

    d = aws(profile, ["ec2", "describe-instances"], errors, region)
    if d is not None:
        for reservation in d.get("Reservations", []):
            for x in reservation.get("Instances", []):
                tags = x.get("Tags", [])
                name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), "")
                add(rows, "ec2", region, "instance", x.get("InstanceId"), name=name,
                    state=x.get("State", {}).get("Name"), tags=tags,
                    details={"instance_type": x.get("InstanceType"), "vpc": x.get("VpcId")})

    for operation, key, kind in (("describe-db-instances", "DBInstances", "instance"),
                                  ("describe-db-clusters", "DBClusters", "cluster")):
        d = aws(profile, ["rds", operation], errors, region)
        if d is None:
            continue
        for x in d.get(key, []):
            ident = x.get("DBInstanceIdentifier") or x.get("DBClusterIdentifier")
            arn = x.get("DBInstanceArn") or x.get("DBClusterArn")
            tags = aws(profile, ["rds", "list-tags-for-resource", "--resource-name", arn], errors, region) if arn else None
            add(rows, "rds", region, kind, ident, arn, ident,
                x.get("DBInstanceStatus") or x.get("Status"), (tags or {}).get("TagList"),
                {"engine": x.get("Engine"), "class": x.get("DBInstanceClass"),
                 "cluster": x.get("DBClusterIdentifier")})

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--output-dir", default="reports")
    args = parser.parse_args()
    rows, errors = [], []
    identity = aws(args.profile, ["sts", "get-caller-identity"], errors)
    if not identity or identity.get("Account") != args.expected_account_id:
        print("Account verification failed; discovery aborted.", file=sys.stderr)
        return 2
    data = aws(args.profile, ["ec2", "describe-regions", "--all-regions"], errors)
    if data is None:
        print("Unable to enumerate regions; discovery aborted.", file=sys.stderr)
        return 2
    regions = sorted(x["RegionName"] for x in data.get("Regions", [])
                     if x.get("OptInStatus") in ("opt-in-not-required", "opted-in"))
    if not regions:
        print("No enabled regions found.", file=sys.stderr)
        return 2
    for region in regions:
        print("Scanning", region, file=sys.stderr)
        scan(args.profile, region, rows, errors)
    zones = aws(args.profile, ["route53", "list-hosted-zones"], errors)
    if zones is not None:
        for zone in zones.get("HostedZones", []):
            if not zone.get("Config", {}).get("PrivateZone"):
                continue
            zid = zone["Id"].split("/")[-1]
            detail = aws(args.profile, ["route53", "get-hosted-zone", "--id", zid], errors)
            add(rows, "route53", "global", "private_hosted_zone", zid,
                name=zone.get("Name"), details={"record_count": zone.get("ResourceRecordSetCount"),
                "vpc_associations": (detail or {}).get("VPCs", [])})
    # Usage evidence is intentionally conservative: no fabricated "last used" dates.
    # Secrets Manager provides a last retrieval date (day granularity).
    # EC2/RDS/ELB/EFS CloudWatch metrics show activity within a window, not exact last use.
    # CloudTrail Event History is limited and does not cover all data-plane usage.
    for item in rows:
        if item["service"] == "secretsmanager":
            item["last_activity"] = item["details"].get("last_accessed")
            item["activity_source"] = "Secrets Manager LastAccessedDate (last retrieval, day granularity)"
            item["activity_note"] = "No date does not prove unused; rotation or other operations are not represented."
        elif item["service"] == "kms":
            item["activity_note"] = "KMS DescribeKey has no reliable last-used timestamp. Validate CloudTrail and dependent services."
        elif item["service"] == "route53":
            item["activity_note"] = "Hosted zone metadata has no last-query timestamp. Query logging must be configured separately."
        elif item["service"] in ("ec2", "rds", "load_balancer", "efs"):
            item["activity_note"] = "Last activity requires CloudWatch metric analysis and workload dependency review."
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out, 0o700)
    except OSError:
        pass
    for filename, value in (("inventory.json", rows), ("errors.json", errors),
                            ("summary.json", {"timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                             "regions": regions, "resource_count": len(rows),
                             "error_count": len(errors), "complete": not errors})):
        path = out / filename
        path.write_text(json.dumps(value, indent=2, default=str) + "\n")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    path = out / "inventory.csv"
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["service", "region", "type", "id",
                                                    "arn", "name", "state", "tags", "last_activity", "activity_source", "activity_note", "details"])
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, default=str) if isinstance(v, (dict, list)) else v
                             for k, v in row.items()})
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    # Flatten all observed tag keys into distinct CSV columns for filtering.
    def tagdict(tags):
        return {str(t.get("Key", "")): str(t.get("Value", "")) for t in tags if isinstance(t, dict) and t.get("Key")}
    tag_keys = sorted({key for item in rows for key in tagdict(item["tags"])})
    report_path = out / "resource-report.csv"
    columns = ["service", "region", "type", "id", "arn", "name", "state",
               "last_activity", "activity_source", "activity_note"] + ["tag:" + key for key in tag_keys]
    with report_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for item in rows:
            tags = tagdict(item["tags"])
            line = {key: item.get(key, "") for key in columns if not key.startswith("tag:")}
            line.update({"tag:" + key: tags.get(key, "") for key in tag_keys})
            writer.writerow(line)
    try:
        os.chmod(report_path, 0o600)
    except OSError:
        pass
    print("Resources:", len(rows), "API errors:", len(errors))
    print("Report:", report_path)
    return 1 if errors else 0

if __name__ == "__main__":
    sys.exit(main())
