# -----------------------------------------------------------
# Block GuardDuty Findings Source
# -----------------------------------------------------------
locals {
  event_name_guardduty_responder = "guardduty_responder"
}

data "aws_iam_policy_document" "guardduty_responder" {
  count = var.create_guardduty_responder ? 1 : 0

  statement {
    actions = [
      "EC2:*"
    ]
    resources = [
      "*"
    ]
  }
}

module "lambda_guardduty_responder" {

  source = "git::https://github.com/plus3it/terraform-aws-lambda.git?ref=v1.1.0"

  function_name = local.event_name_guardduty_responder
  description   = "GuardDuty Findings Processor - Block source"
  handler       = "${local.event_name_guardduty_responder}.lambda_handler"
  policy        = data.aws_iam_policy_document.guardduty_responder[0]
  runtime       = "python3.8"
  source_path   = "${path.module}/${local.event_name_guardduty_responder}.py"
  timeout       = 300
  tags          = var.tags

  environment = {
    variables = var.environment_variables
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_responder" {
  count = var.create_guardduty_responder ? 1 : 0

  name        = local.event_name_guardduty_responder
  description = "Block source of GuardDuty findings"

  event_pattern = <<-PATTERN
    {
    "detail-type": [
        "GuardDuty Finding"
    ],
    "source": [
        "aws.guardduty"
    ]
    }
  PATTERN
}

resource "aws_cloudwatch_event_target" "guardduty_responder" {
  count = var.create_guardduty_responder ? 1 : 0

  target_id = local.event_name_guardduty_responder
  arn       = module.lambda_guardduty_responder.function_arn
  rule      = aws_cloudwatch_event_rule.guardduty_responder[0].name
}

resource "aws_lambda_permission" "guardduty_responder" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda_guardduty_responder.function_arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_responder[0].arn
}