"""Normalise the events that can trigger isolation into one Finding object."""
from __future__ import annotations

from dataclasses import dataclass


class NotActionable(Exception):
    """The event is valid but should not trigger isolation (wrong resource, low severity)."""


@dataclass(frozen=True)
class Finding:
    instance_id: str
    finding_id: str
    finding_type: str
    severity: float
    source: str
    title: str = ""

    @property
    def severity_label(self) -> str:
        if self.severity >= 7:
            return "HIGH"
        if self.severity >= 4:
            return "MEDIUM"
        return "LOW"


def parse_event(event: dict, min_severity: float) -> Finding:
    """Accepts a GuardDuty finding from EventBridge, a Security Hub finding, or a manual request."""
    if event.get("source") == "aws.guardduty":
        return _from_guardduty(event["detail"], min_severity)
    if event.get("source") == "aws.securityhub":
        return _from_securityhub(event["detail"]["findings"][0], min_severity)
    if "instance_id" in event:
        return Finding(
            instance_id=event["instance_id"],
            finding_id=event.get("ticket", "manual"),
            finding_type="Manual:Analyst/IsolationRequest",
            severity=10.0,
            source="manual",
            title=event.get("reason", "Analyst requested isolation"),
        )
    raise ValueError("Unrecognised event: expected GuardDuty, Security Hub or {'instance_id': ...}")


def _from_guardduty(detail: dict, min_severity: float) -> Finding:
    resource = detail.get("resource", {})
    if resource.get("resourceType") != "Instance":
        raise NotActionable(f"resource type {resource.get('resourceType')} is not an EC2 instance")
    severity = float(detail.get("severity", 0))
    if severity < min_severity:
        raise NotActionable(f"severity {severity} below threshold {min_severity}")
    return Finding(
        instance_id=resource["instanceDetails"]["instanceId"],
        finding_id=detail["id"],
        finding_type=detail["type"],
        severity=severity,
        source="guardduty",
        title=detail.get("title", ""),
    )


def _from_securityhub(f: dict, min_severity: float) -> Finding:
    ec2 = [r for r in f.get("Resources", []) if r.get("Type") == "AwsEc2Instance"]
    if not ec2:
        raise NotActionable("Security Hub finding has no AwsEc2Instance resource")
    severity = float(f.get("Severity", {}).get("Normalized", 0)) / 10
    if severity < min_severity:
        raise NotActionable(f"severity {severity} below threshold {min_severity}")
    return Finding(
        instance_id=ec2[0]["Id"].rsplit("/", 1)[-1],
        finding_id=f["Id"],
        finding_type=(f.get("Types") or ["Unknown"])[0],
        severity=severity,
        source="securityhub",
        title=f.get("Title", ""),
    )
