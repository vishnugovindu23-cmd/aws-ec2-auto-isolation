terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  package = "${path.module}/../build/lambda.zip"
}

# SOC notifications

resource "aws_sns_topic" "soc_alerts" {
  name = "${var.name_prefix}-soc-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.soc_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# IAM: only the actions the containment playbook needs

data "aws_iam_policy_document" "assume_lambda" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "isolation" {
  name               = "${var.name_prefix}-role"
  assume_role_policy = data.aws_iam_policy_document.assume_lambda.json
}

data "aws_iam_policy_document" "isolation" {
  statement {
    sid = "Describe"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeNetworkInterfaces",
    ]
    resources = ["*"]
  }

  statement {
    sid = "Contain"
    actions = [
      "ec2:CreateSecurityGroup",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:ModifyInstanceAttribute",
      "ec2:CreateSnapshot",
      "ec2:CreateTags",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.soc_alerts.arn]
  }

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:*:*:*"]
  }
}

resource "aws_iam_role_policy" "isolation" {
  name   = "${var.name_prefix}-policy"
  role   = aws_iam_role.isolation.id
  policy = data.aws_iam_policy_document.isolation.json
}

# Lambda functions (build the zip first: ./scripts/package.sh)

resource "aws_lambda_function" "isolate" {
  function_name    = "${var.name_prefix}-isolate"
  role             = aws_iam_role.isolation.arn
  runtime          = "python3.12"
  handler          = "isolation.handler.lambda_handler"
  filename         = local.package
  source_code_hash = filebase64sha256(local.package)
  timeout          = 60

  environment {
    variables = {
      MIN_SEVERITY  = tostring(var.min_severity)
      SNS_TOPIC_ARN = aws_sns_topic.soc_alerts.arn
      DRY_RUN       = tostring(var.dry_run)
    }
  }
}

resource "aws_lambda_function" "release" {
  function_name    = "${var.name_prefix}-release"
  role             = aws_iam_role.isolation.arn
  runtime          = "python3.12"
  handler          = "isolation.handler.release_handler"
  filename         = local.package
  source_code_hash = filebase64sha256(local.package)
  timeout          = 60

  environment {
    variables = {
      DRY_RUN = tostring(var.dry_run)
    }
  }
}

resource "aws_cloudwatch_log_group" "isolate" {
  name              = "/aws/lambda/${aws_lambda_function.isolate.function_name}"
  retention_in_days = 365
}

# Trigger: high-severity GuardDuty findings on EC2 instances

resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "${var.name_prefix}-guardduty-high"
  description = "GuardDuty EC2 findings at or above the isolation severity"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_severity] }]
      resource = { resourceType = ["Instance"] }
    }
  })
}

resource "aws_cloudwatch_event_target" "isolate" {
  rule = aws_cloudwatch_event_rule.guardduty_high.name
  arn  = aws_lambda_function.isolate.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.isolate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high.arn
}
