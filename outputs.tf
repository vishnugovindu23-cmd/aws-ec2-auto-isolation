output "isolation_function" {
  value = aws_lambda_function.isolate.function_name
}

output "release_function" {
  value = aws_lambda_function.release.function_name
}

output "sns_topic_arn" {
  value = aws_sns_topic.soc_alerts.arn
}

output "eventbridge_rule" {
  value = aws_cloudwatch_event_rule.guardduty_high.name
}
