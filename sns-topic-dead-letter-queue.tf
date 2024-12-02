resource "aws_sns_topic" "shared-sns-topic-dlq" {
  name              = "${var.ENVIRONMENT_NAME}-lambda-dlq"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_policy" "shared-sns-policy-dlq" {
  arn    = aws_sns_topic.shared-sns-topic-dlq.arn
  policy = data.aws_iam_policy_document.sns_topic_policy_dlq.json
}

data "aws_iam_policy_document" "sns_topic_policy_dlq" {
  policy_id = "__devsecops_alert_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current.account_id,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.shared-sns-topic-dlq.arn,
    ]

    sid = "__devsecops_alert_statement_ID"
  }
}

resource "aws_sns_topic_subscription" "sns_topic_email_subscription_dlq" {
  count     = length(local.sns_emails)
  topic_arn = aws_sns_topic.shared-sns-topic-dlq.arn
  protocol  = "email"
  endpoint  = local.sns_emails[count.index]
}