locals {

  name   = "ecsdemo-echo-service"
  region = "eu-west-1"

  container_name = "ecsdemo-echo-service"

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/ecs-blueprints"
  }
}

data "aws_secretsmanager_secret" "github_token" {
  name = var.github_token_secret_name
}

data "aws_secretsmanager_secret_version" "github_token" {
  secret_id = data.aws_secretsmanager_secret.github_token.id
}

data "aws_vpc" "vpc" {
  filter {
    name   = "tag:Name"
    values = ["core-infra"]
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "tag:Name"
    values = ["core-infra-private-*"]
  }
}

data "aws_subnets" "public" {
  filter {
    name   = "tag:Name"
    values = ["core-infra-public-*"]
  }
}

data "aws_ecs_cluster" "core_infra" {
  cluster_name = "core-infra"
}

resource "aws_cognito_user_pool" "this" {
  name = "echo-user-pool"
  # Add any additional configuration options here
}

resource "aws_cognito_user_pool_client" "this" {
  name = "echo-user-pool-client"
  explicit_auth_flows = ["ADMIN_NO_SRP_AUTH"]
  user_pool_id = aws_cognito_user_pool.this.id
  # Add any additional configuration options here
}

resource "aws_lb" "this" {
  name               = "example-alb"
  internal           = false
  load_balancer_type = "application"
  subnets            = concat(data.aws_subnets.public.ids)
  
  security_groups    = [aws_security_group.this.id]
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

resource "aws_lb_target_group" "this" {
  name     = "echo-target-group"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.vpc.id
  target_type = "ip"

  health_check {
    path = "/healthcheck"
  }
}

resource "aws_security_group" "this" {
  name_prefix = "echo-sg"
  vpc_id      = data.aws_vpc.vpc.id


  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_ecs_task_definition" "this" {
  family                   = "echo-task-family"
  container_definitions    = jsonencode([{
    name      = "echo-service-task"
    image     = module.container_image_ecr.repository_url
    essential = true
    portMappings = [{
      containerPort = 3000
      hostPort      = 3000
    }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = "ecs_tasks_logs"
        "awslogs-region"        = local.region
        "awslogs-stream-prefix" = "echo-service"
      }
    },
    environment = [
      {
        name  = "COGNITO_USER_POOL_ID"
        value = aws_cognito_user_pool.this.id
      },
      {
        name  = "COGNITO_USER_POOL_CLIENT_ID"
        value = aws_cognito_user_pool_client.this.id
      },
    ]
  }])
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  task_role_arn = aws_iam_role.task.arn
  execution_role_arn       = one(data.aws_iam_roles.ecs_core_infra_exec_role.arns)
  tags = local.tags


}
resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.task.json

  tags = local.tags
}


resource "aws_ecs_service" "this" {
  name            = "echo-service"
  cluster         = data.aws_ecs_cluster.core_infra.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count                      = 2
  deployment_minimum_healthy_percent = 50
 
  scheduling_strategy                = "REPLICA"
  deployment_maximum_percent         = 200

  network_configuration {
    security_groups = [aws_security_group.this.id]
    subnets         =  concat(data.aws_subnets.public.ids)

    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "echo-service-task"
    container_port   = 3000
  }

  tags = local.tags
}


resource "aws_iam_role" "codebuild" {
  name = "ecsdemo-echo-service-codebuild"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = {
          Service = "codebuild.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "codebuild" {
  policy_arn = aws_iam_policy.codebuild.arn
  role       = aws_iam_role.codebuild.name
}

resource "aws_iam_policy" "codebuild" {
  name        = "ecsdemo-echo-service-codebuild"
  description = "Policy for CodeBuild to access ECR"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecs:RegisterTaskDefinition",
          "ecs:ListTaskDefinitions",
          "ecs:DescribeTaskDefinition",
          "ecr:ListImages",
          "ecr:DescribeImages",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetBucketAcl",
          "s3:PutObject",
          "ecr:CompleteLayerUpload",
          "ecr:GetAuthorizationToken",
          "ecr:UploadLayerPart",
          "ecr:InitiateLayerUpload",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "iam:PassRole"
        ]
        Resource = "*"
      }
    ]
  })
}


module "codebuild_ci" {
  source = "../../modules/codebuild"

  name           = "codebuild-${local.name}"
  service_role   = aws_iam_role.codebuild.arn
  buildspec_path = "./application-code/echo-service/templates/buildspec.yml"
  s3_bucket      = module.codepipeline_s3_bucket
  iam_role_name  = "echo-service-codebuild-${random_id.this.hex}"
  ecr_repository = module.container_image_ecr.repository_url

  environment = {
    privileged_mode = true
    environment_variables = [
      {
        name  = "REPO_URL"
        value = module.container_image_ecr.repository_url
      }, {
        name  = "TASK_DEFINITION_FAMILY"
        value = aws_ecs_task_definition.this.family
      }, {
        name  = "CONTAINER_NAME"
        value = local.container_name
      }, {
        name  = "FOLDER_PATH"
        value = "./application-code/echo-service/."
      }, {  
        name  = "COGNITO_USER_POOL_ID"
        value = aws_cognito_user_pool.this.id
      }, {
        name  = "COGNITO_USER_POOL_CLIENT_ID"
        value = aws_cognito_user_pool_client.this.id
      }
    ]
  }

  create_iam_role = false
  
}

module "container_image_ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.4"

  repository_name = local.container_name

  repository_force_delete           = true
  create_lifecycle_policy           = false
  repository_read_access_arns       = [one(data.aws_iam_roles.ecs_core_infra_exec_role.arns)]
  repository_read_write_access_arns = [module.codepipeline_ci_cd.codepipeline_role_arn]

  tags = local.tags
}

module "codepipeline_ci_cd" {
  source = "../../modules/codepipeline"

  name         = "pipeline-${local.name}"
  service_role = module.codepipeline_ci_cd.codepipeline_role_arn
  s3_bucket    = module.codepipeline_s3_bucket
  sns_topic    = aws_sns_topic.codestar_notification.arn

  stage = [{
    name = "GetSource"
    action = [{
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      output_artifacts = ["SourceArtifact"]
      configuration = {
        OAuthToken           = data.aws_secretsmanager_secret_version.github_token.secret_string
        Owner                = var.repository_owner
        Repo                 = var.repository_name
        Branch               = var.repository_branch
        PollForSourceChanges = true
      }
    }],
    }, {
    name = "Build"
    action = [{
      name             = "Build_app"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceArtifact"]
      output_artifacts = ["BuildArtifact_app"]
      configuration = {
        ProjectName = module.codebuild_ci.project_id
      }
    }],
    }, {
    name = "Deploy"
    action = [{
      name             = "Deploy_app"
      category         = "Deploy"
      owner            = "AWS"
      provider         = "ECS"
      version          = "1"
      input_artifacts  = ["BuildArtifact_app"]
      configuration = {
        ClusterName     = data.aws_ecs_cluster.core_infra.cluster_name
        ServiceName     = "echo-service"
        #TaskDefinitionName  = aws_ecs_task_definition.this.arn
        #ContainerName   = "echo-service"
        #ContainerPort   = 3000
      }
    }],
  }]

  create_iam_role = true
  iam_role_name   = "echo-service-pipeline-${random_id.this.hex}"

  tags = local.tags
}

module "codepipeline_s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = "codepipeline-${local.region}-${random_id.this.hex}"
  tags = local.tags
}

resource "aws_sns_topic" "codestar_notification" {
  name = local.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteAccess"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:${local.region}:${data.aws_caller_identity.current.account_id}:${local.name}"
        Principal = {
          Service = "codestar-notifications.amazonaws.com"
        }
      },
    ]
  })

  tags = local.tags
}

resource "random_id" "this" {
  byte_length = "2"
}

data "aws_iam_roles" "ecs_core_infra_exec_role" {
  name_regex = "core-infra-execution-*"
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "task" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "cognito_admin_auth" {
  name        = "CognitoAdminAuth"
  description = "Allows admin initiate auth action on Cognito"
  policy      = <<-EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "cognito-idp:AdminInitiateAuth",
      "Resource": "${aws_cognito_user_pool.this.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "task_cognito_admin_auth" {
  role       = aws_iam_role.task.name
  policy_arn = aws_iam_policy.cognito_admin_auth.arn
}





