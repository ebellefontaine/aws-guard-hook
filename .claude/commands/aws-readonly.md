# AWS Read-Only Mode

You are operating in **AWS read-only mode**. Your role is to inspect and understand AWS infrastructure, then express any desired changes through **Infrastructure as Code (IaC)** — never by running AWS CLI write/mutation commands directly.

## What you SHOULD do

Use read-only AWS CLI commands freely to inspect the current state of infrastructure:

```
aws <service> describe-*
aws <service> list-*
aws <service> get-*
aws <service> query
aws <service> search-*
aws <service> check-*
aws <service> validate-*
aws <service> scan            # DynamoDB table scan
aws <service> batch-get-*
aws <service> generate-presigned-*
aws <service> estimate-*
aws <service> preview-*
aws <service> export-*
aws <service> filter-*
aws <service> lookup-*
aws <service> calculate-*
aws <service> resolve-*
aws <service> summarize-*
aws sts get-caller-identity
aws configure list
aws s3 ls
aws logs tail
```

These commands are safe: they are read-only and have no side effects.

## What you must NOT do

Do **not** run AWS CLI commands that create, modify, delete, or otherwise mutate AWS resources. This includes (but is not limited to):

- `aws <service> create-*`
- `aws <service> put-*`
- `aws <service> update-*`
- `aws <service> delete-*`
- `aws <service> remove-*`
- `aws <service> attach-*` / `detach-*`
- `aws <service> enable-*` / `disable-*`
- `aws <service> start-*` / `stop-*`
- `aws <service> deploy` / `aws cloudformation deploy`
- `aws s3 cp` (upload direction: local → s3://)
- `aws s3 sync`, `aws s3 rm`, `aws s3 mv`

Do **not** write shell scripts or one-off automation that calls these commands to work around this restriction.

## How to make infrastructure changes

If your investigation reveals that a change is needed, **edit the IaC source code** rather than using the AWS CLI directly. Choose the appropriate tool already in use by this project:

| IaC Toolchain | Where to make changes |
|---|---|
| **Terraform** | Edit `.tf` files, then `terraform plan` / `terraform apply` |
| **AWS CDK** | Edit the CDK app source (TypeScript, Python, etc.), then `cdk deploy` |
| **CloudFormation** | Edit the `.yaml` / `.json` template, then deploy the stack |
| **Pulumi** | Edit the Pulumi program, then `pulumi up` |
| **SAM** | Edit `template.yaml`, then `sam deploy` |

### Workflow

1. **Inspect** — use read-only CLI commands to understand the current state.
2. **Plan** — decide what the desired state should be.
3. **Edit IaC** — express the desired state in the appropriate IaC files.
4. **Review** — show the diff and, if applicable, a dry-run (`terraform plan`, `cdk diff`, etc.).
5. **Apply** — let the human run the IaC deploy command (or do so only with explicit approval).

## Why this matters

Directly mutating AWS resources via the CLI:
- Creates **drift** between your IaC source of truth and the live environment.
- Leaves **no audit trail** in version control.
- Is **hard to reproduce** or roll back.
- Risks **accidental destruction** of production resources.

IaC changes are reviewed, version-controlled, and repeatable. Always prefer them.
