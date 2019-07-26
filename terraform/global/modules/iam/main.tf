resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_numbers                = true
  require_uppercase_characters   = true
  require_symbols                = true
  allow_users_to_change_password = true
}

resource "aws_iam_role" "DdevopsCrossAccountReadOnly" {
  name = "DdevopsCrossAccountReadOnly"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${var.child-account-id}:root"
    },
    "Action": "sts:AssumeRole"
  }
}
EOF
}

resource "aws_iam_policy_attachment" "DdevopsCrossAccountReadOnly" {
  name       = "DdevopsCrossAccountReadOnly"
  roles      = ["${aws_iam_role.DdevopsCrossAccountReadOnly.name}"]
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "DdevopsCrossAccountPowerUsers" {
  name = "DdevopsCrossAccountPowerUsers"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${var.child-account-id}:root"
    },
    "Action": "sts:AssumeRole"
  }
}
EOF
}

resource "aws_iam_policy_attachment" "DdevopsCrossAccountPowerUsers" {
  name       = "CrossAccountPowerUsers"
  roles      = ["${aws_iam_role.DdevopsCrossAccountPowerUsers.name}"]
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_role" "DdevopsCrossAccountAdministrators" {
  name = "CrossAccountAdministrators"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${var.child-account-id}:root"
    },
    "Action": "sts:AssumeRole"
  }
}
EOF
}

resource "aws_iam_policy_attachment" "DdevopsCrossAccountAdministrators" {
  name       = "CrossAccountAdministrators"
  roles      = ["${aws_iam_role.DdevopsCrossAccountAdministrators.name}"]
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}


resource "aws_iam_role" "DdevopsCrossAccountNetworkAdministrators" {
  name = "CrossAccountNetworkAdministrators"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${var.child-account-id}:root"
    },
    "Action": "sts:AssumeRole"
  }
}
EOF
}

resource "aws_iam_policy_attachment" "DdevopsCrossAccountNetworkAdministrators" {
  name       = "CrossNetworkAccountAdministrators"
  roles      = ["${aws_iam_role.DdevopsCrossAccountNetworkAdministrators.name}"]
  policy_arn = "arn:aws:iam::aws:policy/job-function/NetworkAdministrator"
}

resource "aws_iam_role" "DdevopsCrossAccountSupportUsers" {
  name = "CrossAccountSupportUsers"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${var.child-account-id}:root"
    },
    "Action": "sts:AssumeRole"
  }
}
EOF
}

resource "aws_iam_policy_attachment" "DdevopsCrossAccountSupportUsers" {
  name       = "CrossAccountSupportUsers"
  roles      = ["${aws_iam_role.DdevopsCrossAccountSupportUsers.name}"]
  policy_arn = "arn:aws:iam::aws:policy/job-function/SupportUser"
}

resource "aws_iam_role" "DdevopsCrossAccountSystemAdministrators" {
  name = "DdevopsCrossAccountSystemAdministrators"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::${var.child-account-id}:root"
    },
    "Action": "sts:AssumeRole"
  }
}
EOF
}

resource "aws_iam_policy_attachment" "DdevopsCrossAccountSystemAdministrators" {
  name       = "CrossAccountSystemAdministrators"
  roles      = ["${aws_iam_role.DdevopsCrossAccountSystemAdministrators.name}"]
  policy_arn = "arn:aws:iam::aws:policy/job-function/SystemAdministrator"
}
