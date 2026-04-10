package main

deny[msg] {
  statement := input.resource.aws_iam_policy[_].policy.Statement[_]
  statement.Action == "*"
  msg := "Wildcard action '*' is not allowed in IAM policies!"
}

deny[msg] {
  statement := input.resource.aws_iam_policy[_].policy.Statement[_]
  statement.Resource == "*"
  msg := "Wildcard resource '*' is not allowed!"
}
