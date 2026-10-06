import copy
import json
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

from isolation.finding import NotActionable, parse_event
from isolation.handler import lambda_handler, release_handler
from isolation.isolate import QUARANTINE_SG_NAME

REGION = "us-east-1"
SAMPLE = json.loads((Path(__file__).parent.parent / "events" / "guardduty_finding.json").read_text())


class RecordingEC2:
    """Proxy to the moto client that records SG swaps.

    moto appends groups on ModifyNetworkInterfaceAttribute, real AWS replaces the set,
    so tests assert on the exact API call rather than moto's resulting state.
    """

    def __init__(self, client):
        self._client = client
        self.sg_swaps: list[tuple[str, list[str]]] = []

    def modify_network_interface_attribute(self, **kwargs):
        self.sg_swaps.append((kwargs["NetworkInterfaceId"], kwargs["Groups"]))
        return self._client.modify_network_interface_attribute(**kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


@pytest.fixture
def aws(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.delenv("DRY_RUN", raising=False)
    with mock_aws():
        ec2 = RecordingEC2(boto3.client("ec2", region_name=REGION))
        sns = boto3.client("sns", region_name=REGION)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
        web_sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        yield {"ec2": ec2, "sns": sns, "vpc": vpc, "subnet": subnet, "web_sg": web_sg, "ami": ami}


def launch(aws, tags=None):
    resp = aws["ec2"].run_instances(
        ImageId=aws["ami"], MinCount=1, MaxCount=1, SubnetId=aws["subnet"],
        SecurityGroupIds=[aws["web_sg"]],
        TagSpecifications=[{"ResourceType": "instance", "Tags": tags or [{"Key": "Name", "Value": "web-prod-02"}]}],
    )
    return resp["Instances"][0]["InstanceId"]


def event_for(instance_id, severity=8):
    e = copy.deepcopy(SAMPLE)
    e["detail"]["resource"]["instanceDetails"]["instanceId"] = instance_id
    e["detail"]["severity"] = severity
    return e


def describe(aws, instance_id):
    return aws["ec2"].describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]


def tags_of(instance):
    return {t["Key"]: t["Value"] for t in instance.get("Tags", [])}


def test_high_severity_finding_isolates_instance(aws):
    iid = launch(aws)
    result = lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])

    assert result["status"] == "isolated"
    inst = describe(aws, iid)
    eni = inst["NetworkInterfaces"][0]["NetworkInterfaceId"]
    assert aws["ec2"].sg_swaps == [(eni, [result["quarantine_sg"]])]
    assert result["original_sgs"] == {eni: [aws["web_sg"]]}
    assert tags_of(inst)["SecurityStatus"] == "Quarantined"
    assert tags_of(inst)["IR-FindingType"] == "Backdoor:EC2/C&CActivity.B!DNS"

    protection = aws["ec2"].describe_instance_attribute(InstanceId=iid, Attribute="disableApiTermination")
    assert protection["DisableApiTermination"]["Value"] is True

    snaps = aws["ec2"].describe_snapshots(SnapshotIds=result["snapshots"])["Snapshots"]
    assert snaps and all({"Key": "IR-Evidence", "Value": "true"} in s["Tags"] for s in snaps)


def test_quarantine_group_blocks_all_traffic(aws):
    iid = launch(aws)
    result = lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    sg = aws["ec2"].describe_security_groups(GroupIds=[result["quarantine_sg"]])["SecurityGroups"][0]
    assert sg["GroupName"] == QUARANTINE_SG_NAME
    assert sg["IpPermissions"] == []
    assert sg["IpPermissionsEgress"] == []


def test_quarantine_group_is_reused(aws):
    a, b = launch(aws), launch(aws)
    r1 = lambda_handler(event_for(a), ec2=aws["ec2"], sns=aws["sns"])
    r2 = lambda_handler(event_for(b), ec2=aws["ec2"], sns=aws["sns"])
    assert r1["quarantine_sg"] == r2["quarantine_sg"]


def test_low_severity_is_ignored(aws):
    iid = launch(aws)
    result = lambda_handler(event_for(iid, severity=4), ec2=aws["ec2"], sns=aws["sns"])
    assert result["status"] == "ignored"
    assert "SecurityStatus" not in tags_of(describe(aws, iid))


def test_exempt_instance_is_not_touched(aws):
    iid = launch(aws, tags=[{"Key": "IsolationExempt", "Value": "true"}])
    result = lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    assert result["status"] == "skipped_exempt"
    assert aws["ec2"].sg_swaps == []


def test_second_finding_is_idempotent(aws):
    iid = launch(aws)
    lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    again = lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    assert again["status"] == "already_isolated"


def test_dry_run_changes_nothing(aws, monkeypatch):
    monkeypatch.setenv("DRY_RUN", "true")
    iid = launch(aws)
    result = lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    assert result["status"] == "dry_run"
    assert all(a.startswith("[DRY RUN]") for a in result["actions"])
    assert aws["ec2"].sg_swaps == []
    assert "SecurityStatus" not in tags_of(describe(aws, iid))


def test_sns_notification_sent(aws, monkeypatch):
    topic = aws["sns"].create_topic(Name="soc-alerts")["TopicArn"]
    monkeypatch.setenv("SNS_TOPIC_ARN", topic)
    iid = launch(aws)
    result = lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    assert result["notification_id"]


def test_release_restores_original_groups(aws):
    iid = launch(aws)
    lambda_handler(event_for(iid), ec2=aws["ec2"], sns=aws["sns"])
    released = release_handler({"instance_id": iid}, ec2=aws["ec2"])
    assert released["status"] == "released"
    inst = describe(aws, iid)
    eni = inst["NetworkInterfaces"][0]["NetworkInterfaceId"]
    assert aws["ec2"].sg_swaps[-1] == (eni, [aws["web_sg"]])
    assert tags_of(inst)["SecurityStatus"] == "Released"


def test_manual_and_securityhub_events_parse():
    manual = parse_event({"instance_id": "i-0abc", "ticket": "INC-4471"}, 7)
    assert manual.source == "manual" and manual.finding_id == "INC-4471"

    sh = {
        "source": "aws.securityhub",
        "detail": {"findings": [{
            "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/1",
            "Types": ["TTPs/Command and Control"],
            "Title": "C2 traffic",
            "Severity": {"Normalized": 90},
            "Resources": [{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0def"}],
        }]},
    }
    f = parse_event(sh, 7)
    assert f.instance_id == "i-0def" and f.severity == 9.0


def test_non_instance_finding_not_actionable():
    e = copy.deepcopy(SAMPLE)
    e["detail"]["resource"]["resourceType"] = "S3Bucket"
    with pytest.raises(NotActionable):
        parse_event(e, 7)
