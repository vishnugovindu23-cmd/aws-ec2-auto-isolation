"""SOC notification over SNS (email, Slack via Chatbot, PagerDuty, etc. subscribe to the topic)."""
from __future__ import annotations

import json

from .finding import Finding
from .isolate import IsolationResult


def build_message(finding: Finding, result: IsolationResult) -> tuple[str, str]:
    subject = f"[{finding.severity_label}] EC2 {finding.instance_id} {result.status.replace('_', ' ')}"
    lines = [
        f"Instance:      {finding.instance_id}",
        f"Status:        {result.status}",
        f"Finding:       {finding.finding_type} (severity {finding.severity})",
        f"Source:        {finding.source} / {finding.finding_id}",
        f"Summary:       {finding.title}",
        f"Quarantine SG: {result.quarantine_sg or '-'}",
        f"Snapshots:     {', '.join(result.snapshots) or '-'}",
        "",
        "Actions taken:",
        *[f"  - {a}" for a in result.actions],
        "",
        "Next steps: acquire memory if needed, review snapshots in the forensics account,",
        "then run release only after the incident owner signs off.",
    ]
    return subject[:100], "\n".join(lines)


def publish(sns_client, topic_arn: str | None, finding: Finding, result: IsolationResult) -> str | None:
    if not topic_arn:
        return None
    subject, body = build_message(finding, result)
    resp = sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject,
        Message=body,
        MessageAttributes={"status": {"DataType": "String", "StringValue": result.status}},
    )
    return resp["MessageId"]


def as_json(finding: Finding, result: IsolationResult) -> str:
    return json.dumps({"finding": finding.__dict__, "result": result.to_dict()}, indent=2, default=str)
