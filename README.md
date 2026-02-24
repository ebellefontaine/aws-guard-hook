# aws-guard-hook

A Claude Code `PreToolUse` hook that blocks AWS CLI write/mutation operations.
Only read-only commands are permitted. All infrastructure changes must go
through Infrastructure as Code (IaC).

## Why

When Claude Code runs inside an AWS environment, it can inadvertently execute
destructive CLI commands (`aws ec2 terminate-instances`, `aws s3 rm`, etc.).
This hook intercepts every `Bash` tool call before it runs and rejects any AWS
command that is not provably read-only, giving Claude the policy reason so it
can pivot to editing IaC instead.

## How it works

The hook implements an **allowlist** strategy:

1. If the shell command contains no `aws` invocation → allow.
2. Each `aws` invocation is extracted from compound commands (`&&`, `||`, `;`,
   `|`), command substitutions (`$(aws ...)`, `` `aws ...` ``), and env-var
   prefixed forms (`AWS_PROFILE=prod aws ...`).
3. The service and subcommand are parsed (skipping global flags like
   `--region`, `--profile`).
4. Always-allowed pairs pass immediately: all `aws sts *` commands,
   `aws configure get/list`, `aws s3 ls`, `aws s3 presign`,
   `aws s3 cp <s3://src> <local-dest>` (downloads only), `aws logs tail`.
5. For everything else the subcommand must start with a recognised read-only
   prefix: `get-`, `list-`, `describe-`, `query`, `search-`, `check-`,
   `validate-`, `scan`, `batch-get-`, `generate-presigned-`, `estimate-`,
   `preview-`, `export-`, `filter-`, `lookup-`, `calculate-`, `resolve-`,
   `summarize-`.
6. Anything that does not match is **hard-blocked** (exit 2). Claude receives
   the block message and is expected to identify the correct IaC change.

There is **no override**. The block is absolute.

IaC deploy commands (`terraform apply`, `cdk deploy`, `pulumi up`, etc.) are
**not** intercepted — they are intentional operations in an IaC workflow.

## Requirements

- Python 3.8+
- No third-party dependencies (stdlib only)

## Installation

### Option A — project-level (this repo already configured)

The `.claude/settings.json` in this repository already registers the hook.
Clone the repo and open it with Claude Code:

```bash
git clone <repo-url> my-project
cd my-project
claude  # hook is active immediately
```

### Option B — add to an existing project

1. Copy `hooks/aws_guard.py` into your project's `hooks/` directory.

2. Add the hook to your project's `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 hooks/aws_guard.py"
          }
        ]
      }
    ]
  }
}
```

3. Verify the hook format against the current
   [Claude Code hooks documentation](https://docs.anthropic.com/en/docs/claude-code/hooks)
   if the schema has changed since this was written.

## Block message example

When a write command is intercepted Claude sees:

```
[AWS Guard] Command blocked: this operation would perform a write/mutation on AWS infrastructure.

Policy: Only read-only AWS CLI operations are permitted. Allowed subcommand
prefixes: get-, list-, describe-, query-, search-, check-, validate-, scan,
batch-get-, generate-presigned- and similar read-only verbs. All
infrastructure changes must be made through Infrastructure as Code (IaC) and
applied using the appropriate IaC deployment workflow.

Blocked command: aws ec2 run-instances --image-id ami-12345678 --instance-type t3.micro
```

## Running the tests

```bash
python3 hooks/test_aws_guard.py
```

91 tests cover: read-only allows, write blocks, compound commands, pipelines,
command substitutions, `aws s3 cp` direction detection, and global-flag
parsing.

## Extending the hook

All configuration lives at the top of `hooks/aws_guard.py`:

| Symbol | Purpose |
|---|---|
| `READ_ONLY_PREFIXES` | Tuple of subcommand prefixes (or exact words) that are read-only |
| `ALWAYS_ALLOWED` | `(service, subcommand)` pairs that bypass prefix checking entirely |
| `AWS_GLOBAL_VALUE_FLAGS` | Global flags that consume the next token (used during parsing) |
| `BLOCK_MESSAGE_TEMPLATE` | The message Claude receives when a command is blocked |

To allow an additional subcommand pattern, add its prefix to
`READ_ONLY_PREFIXES`. To always allow a specific service (e.g. `cloudwatch`
reads via `aws cloudwatch get-metric-data`), that already works via the
`get-` prefix — no change needed.

## Specification

See [SPEC.md](SPEC.md) for the full design specification including decision
rationale from the requirements interview.
