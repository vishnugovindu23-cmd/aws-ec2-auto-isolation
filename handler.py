"""Lambda entry points.

Environment variables:
  MIN_SEVERITY   GuardDuty severity needed to act (default 7 = HIGH)
  SNS_TOPIC_ARN  topic for SOC notifications (optional)
  DRY_RUN        "true" logs the plan without changing anything
"""
from __future__ import annotations

import json
import logging
import os

import boto3

from .finding import NotActionable, parse_event
from .isolate import Isolator
from .notify import publish

log = logging.getLogger()
log.setLevel(logging.INFO)


def _env_bool(name: str) -> bool:
    return os.getenv(name, "false").lower() in ("1", "true", "yes")


def lambda_handler(event, context=None, ec2=None, sns=None):
    min_severity = float(os.getenv("MIN_SEVERITY", "7"))
    try:
        finding = parse_event(event, min_severity)
    except NotActionable as exc:
        log.info("Ignoring event: %s", exc)
        return {"status": "ignored", "reason": str(exc)}

    ec2 = ec2 or boto3.client("ec2")
    sns = sns or boto3.client("sns")
    result = Isolator(ec2, dry_run=_env_bool("DRY_RUN")).isolate(finding)
    message_id = publish(sns, os.getenv("SNS_TOPIC_ARN"), finding, result)

    log.info(json.dumps({"finding": finding.__dict__, "result": result.to_dict()}, default=str))
    return {**result.to_dict(), "notification_id": message_id}


def release_handler(event, context=None, ec2=None):
    """Invoke with {"instance_id": "i-..."} once the investigation is closed."""
    ec2 = ec2 or boto3.client("ec2")
    result = Isolator(ec2, dry_run=_env_bool("DRY_RUN")).release(event["instance_id"])
    return result.to_dict()
