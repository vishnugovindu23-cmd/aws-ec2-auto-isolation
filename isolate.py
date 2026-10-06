"""Containment actions for a compromised EC2 instance.

Order matters: evidence is preserved (termination protection, snapshots) before
network access is cut, so nothing is lost if a later step fails.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .finding import Finding

log = logging.getLogger(__name__)

QUARANTINE_SG_NAME = "ir-quarantine-no-traffic"
STATUS_TAG = "SecurityStatus"
ORIGINAL_SG_TAG = "IR-OriginalSecurityGroups"
EXEMPT_TAG = "IsolationExempt"


@dataclass
class IsolationResult:
    instance_id: str
    status: str
    actions: list[str] = field(default_factory=list)
    snapshots: list[str] = field(default_factory=list)
    quarantine_sg: str | None = None
    original_sgs: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class Isolator:
    def __init__(self, ec2_client, dry_run: bool = False):
        self.ec2 = ec2_client
        self.dry_run = dry_run

    def isolate(self, finding: Finding) -> IsolationResult:
        instance = self._describe(finding.instance_id)
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        result = IsolationResult(finding.instance_id, status="pending")

        if tags.get(EXEMPT_TAG, "").lower() == "true":
            result.status = "skipped_exempt"
            result.actions.append(f"Instance tagged {EXEMPT_TAG}=true, no action taken")
            return result
        if tags.get(STATUS_TAG) == "Quarantined":
            result.status = "already_isolated"
            result.actions.append("Instance already quarantined, no action taken")
            return result

        result.original_sgs = {
            eni["NetworkInterfaceId"]: [g["GroupId"] for g in eni["Groups"]]
            for eni in instance["NetworkInterfaces"]
        }

        self._step(result, "Enable termination protection", self._protect, finding.instance_id)
        result.snapshots = self._step(
            result, "Snapshot attached EBS volumes for forensics", self._snapshot, instance, finding
        ) or []
        result.quarantine_sg = self._step(
            result, "Get or create quarantine security group", self._quarantine_sg, instance["VpcId"]
        )
        for eni_id in result.original_sgs:
            self._step(
                result, f"Swap {eni_id} to quarantine SG", self._swap_sg, eni_id, result.quarantine_sg
            )
        self._step(result, "Tag instance with incident details", self._tag, finding, result)

        result.status = "dry_run" if self.dry_run else "isolated"
        return result

    def release(self, instance_id: str) -> IsolationResult:
        """Undo isolation after the investigation: restore original SGs and clear IR tags."""
        instance = self._describe(instance_id)
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        result = IsolationResult(instance_id, status="pending")
        if tags.get(STATUS_TAG) != "Quarantined":
            result.status = "not_isolated"
            return result
        original = _decode_sg_tag(tags.get(ORIGINAL_SG_TAG, ""))
        for eni_id, groups in original.items():
            self._step(result, f"Restore {eni_id} security groups", self._swap_sg, eni_id, *groups)
        self._step(result, "Mark instance as released", self._mark_released, instance_id)
        result.original_sgs = original
        result.status = "dry_run" if self.dry_run else "released"
        return result

    def _step(self, result: IsolationResult, label: str, fn, *args):
        if self.dry_run:
            result.actions.append(f"[DRY RUN] {label}")
            return None
        value = fn(*args)
        result.actions.append(label)
        log.info("%s: %s", result.instance_id, label)
        return value

    def _describe(self, instance_id: str) -> dict:
        resp = self.ec2.describe_instances(InstanceIds=[instance_id])
        return resp["Reservations"][0]["Instances"][0]

    def _protect(self, instance_id: str) -> None:
        self.ec2.modify_instance_attribute(InstanceId=instance_id, DisableApiTermination={"Value": True})

    def _snapshot(self, instance: dict, finding: Finding) -> list[str]:
        ids = []
        for mapping in instance.get("BlockDeviceMappings", []):
            volume_id = mapping["Ebs"]["VolumeId"]
            snap = self.ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"IR evidence {finding.finding_id} from {instance['InstanceId']} {mapping['DeviceName']}",
                TagSpecifications=[{
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "IR-FindingId", "Value": finding.finding_id},
                        {"Key": "IR-SourceInstance", "Value": instance["InstanceId"]},
                        {"Key": "IR-Evidence", "Value": "true"},
                    ],
                }],
            )
            ids.append(snap["SnapshotId"])
        return ids

    def _quarantine_sg(self, vpc_id: str) -> str:
        existing = self.ec2.describe_security_groups(
            Filters=[{"Name": "group-name", "Values": [QUARANTINE_SG_NAME]}, {"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        if existing:
            return existing[0]["GroupId"]
        sg_id = self.ec2.create_security_group(
            GroupName=QUARANTINE_SG_NAME,
            Description="Incident response quarantine: no inbound or outbound traffic",
            VpcId=vpc_id,
        )["GroupId"]
        self.ec2.revoke_security_group_egress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        return sg_id

    def _swap_sg(self, eni_id: str, *group_ids: str) -> None:
        self.ec2.modify_network_interface_attribute(NetworkInterfaceId=eni_id, Groups=list(group_ids))

    def _tag(self, finding: Finding, result: IsolationResult) -> None:
        self.ec2.create_tags(
            Resources=[finding.instance_id],
            Tags=[
                {"Key": STATUS_TAG, "Value": "Quarantined"},
                {"Key": "IR-IsolatedAt", "Value": datetime.now(timezone.utc).isoformat(timespec="seconds")},
                {"Key": "IR-FindingId", "Value": finding.finding_id[:255]},
                {"Key": "IR-FindingType", "Value": finding.finding_type[:255]},
                {"Key": ORIGINAL_SG_TAG, "Value": _encode_sg_tag(result.original_sgs)},
            ],
        )

    def _mark_released(self, instance_id: str) -> None:
        self.ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": STATUS_TAG, "Value": "Released"},
                {"Key": "IR-ReleasedAt", "Value": datetime.now(timezone.utc).isoformat(timespec="seconds")},
            ],
        )


def _encode_sg_tag(mapping: dict[str, list[str]]) -> str:
    return ";".join(f"{eni}={','.join(groups)}" for eni, groups in mapping.items())


def _decode_sg_tag(value: str) -> dict[str, list[str]]:
    out = {}
    for part in filter(None, value.split(";")):
        eni, groups = part.split("=", 1)
        out[eni] = groups.split(",")
    return out
