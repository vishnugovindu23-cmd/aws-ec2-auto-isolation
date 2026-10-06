"""End-to-end demo against a mocked AWS account (no real AWS needed).

    python scripts/simulate.py            isolate, then show the SOC notification
    python scripts/simulate.py --release  isolate, then release after sign-off
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from isolation.finding import parse_event  # noqa: E402
from isolation.handler import lambda_handler, release_handler  # noqa: E402
from isolation.isolate import IsolationResult  # noqa: E402
from isolation.notify import build_message  # noqa: E402


def banner(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 60 - len(text)))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()

    with mock_aws():
        ec2 = boto3.client("ec2")
        sns = boto3.client("sns")
        topic = sns.create_topic(Name="soc-alerts")["TopicArn"]
        os.environ["SNS_TOPIC_ARN"] = topic

        vpc = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.20.1.0/24")["Subnet"]["SubnetId"]
        web_sg = ec2.create_security_group(GroupName="web-prod", Description="web", VpcId=vpc)["GroupId"]
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        iid = ec2.run_instances(
            ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[web_sg],
            TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web-prod-02"}]}],
        )["Instances"][0]["InstanceId"]

        banner("Environment")
        print(f"VPC {vpc}  instance {iid} (web-prod-02)  security group {web_sg}")

        event = json.loads((ROOT / "events" / "guardduty_finding.json").read_text())
        event = copy.deepcopy(event)
        event["detail"]["resource"]["instanceDetails"]["instanceId"] = iid

        banner("GuardDuty finding received")
        d = event["detail"]
        print(f"{d['type']}  severity {d['severity']}")
        print(d["title"])

        banner("Lambda: auto-isolation")
        result = lambda_handler(event, ec2=ec2, sns=sns)
        for step in result["actions"]:
            print(f"  [done] {step}")
        print(f"\nStatus: {result['status'].upper()}")
        print(f"Quarantine SG: {result['quarantine_sg']}   Evidence snapshots: {', '.join(result['snapshots'])}")

        banner("SOC notification (SNS)")
        finding = parse_event(event, 7)
        fields = {k: result[k] for k in ("instance_id", "status", "actions", "snapshots", "quarantine_sg", "original_sgs")}
        subject, body = build_message(finding, IsolationResult(**fields))
        print(f"Subject: {subject}\n")
        print(body)

        if args.release:
            banner("Investigation closed: release")
            released = release_handler({"instance_id": iid}, ec2=ec2)
            for step in released["actions"]:
                print(f"  [done] {step}")
            print(f"\nStatus: {released['status'].upper()}")


if __name__ == "__main__":
    main()
