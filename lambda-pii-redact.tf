#
# ENABLE / DISABLE LAMBDA FUNCT
#

variable "yay_or_nay_pii_redact" {
  type = map(number)
  default = {
    dev     = 1
    test    = 0
    uat     = 0
    preprod = 0
    prod    = 0
  }
}

#
# IAM ROLE 4 LAMBDA
#
resource "aws_iam_role" "iam_role_for_lambda_pii_redact" {
  count = var.yay_or_nay_pii_redact[var.ENVIRONMENT_NAME]
  name  = "${var.PROJECT_NAME}-${var.ENVIRONMENT_NAME}-iam_role_for_lambda_pii_redact"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    watchdog = "true"
  }
}

#
# IAM POLICY 4 LAMBDA
#
resource "aws_iam_policy" "custom_iam_policy_for_lambda_pii_redact" {
  count = var.yay_or_nay_pii_redact[var.ENVIRONMENT_NAME]
  name  = "${var.PROJECT_NAME}-${var.ENVIRONMENT_NAME}-custom_iam_policy_for_lambda_pii_redact"
  #path        = "/"
  description = "S3 Put get Objects"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::*"
      },
      {
        Action = [
            "ecr:GetAuthorizationToken",
            "ecr:BatchGetImage",
            "ecr:InitiateLayerUpload",
            "ecr:UploadLayerPart",
            "ecr:CompleteLayerUpload",
            "ecr:BatchCheckLayerAvailability",
            "ecr:GetDownloadUrlForLayer",
            "ecr:PutImage"
            ]
        Effect   = "Allow"
        Resource = "arn:aws:ecr:*:*:*"
      },
      {
        "Action": [
            "comprehend:*",
            "s3:ListAllMyBuckets",
            "s3:ListBucket",
            "s3:GetBucketLocation",
            "iam:ListRoles",
            "iam:GetRole"
        ],
        "Effect": "Allow",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
            "textract:*"
        ],
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": [
            "sns:*"
        ],
        "Resource": "*"
      }
    ]
  })
}


#
# ATTACH IAM POLICIES 2 IAM ROLE
#
resource "aws_iam_role_policy_attachment" "custom_iam_policy_attachment_for_lambda_pii_redact" {
  count      = var.yay_or_nay_pii_redact[var.ENVIRONMENT_NAME]
  role       = aws_iam_role.iam_role_for_lambda_pii_redact[0].name
  policy_arn = aws_iam_policy.custom_iam_policy_for_lambda_pii_redact[0].arn
}

resource "aws_iam_role_policy_attachment" "basic_lambda_iam_policy_attachment_for_lambda_pii_redact" {
  count      = var.yay_or_nay_pii_redact[var.ENVIRONMENT_NAME]
  role       = aws_iam_role.iam_role_for_lambda_pii_redact[0].name
  policy_arn = data.aws_iam_policy.AWSLambdaBasicExecutionRole.arn
}

#resource "aws_iam_role_policy_attachment" "vpc_lambda_iam_policy_attachment_for_lambda_pii_redact" {
#  role       = aws_iam_role.iam_role_for_lambda_pii_redact.name
#  policy_arn = data.aws_iam_policy.AWSLambdaVPCAccessExecutionRole.arn
#}

#
# LAMBDA FUNCTION
#
resource "aws_lambda_function" "lambda_pii_redact" {
  count         = var.yay_or_nay_pii_redact[var.ENVIRONMENT_NAME]
  function_name = "${var.PROJECT_NAME}-${var.ENVIRONMENT_NAME}-pii-redact"
  role          = aws_iam_role.iam_role_for_lambda_pii_redact[0].arn

  image_uri = var.LAMBDA_PII_REDACT_IMAGE
  package_type = "Image"

  reserved_concurrent_executions = 10

  #vpc_config {
  #  subnet_ids = data.aws_subnets.environment.ids
  #  iam_user_ids = [aws_iam_user.sgs.id]
  #}

  #Timeout in seconds
  timeout = 300

  environment {
    variables = {
      env           = var.ENVIRONMENT_NAME
      PII_REDACT_DESTINATION_BUCKET = var.S3_PII_REDACT_BUCKET
      PII_REDACT_CONFIDENCE_SCORE = "0.8"
      SNS_TOPIC_ARN = aws_sns_topic.shared-sns-topic-dlq.arn
    }
  }

  ephemeral_storage {
    size = 10240 # Min 512 MB and the Max 10240 MB
  }

  dead_letter_config {
    target_arn = aws_sns_topic.shared-sns-topic-dlq.arn 
  }
}