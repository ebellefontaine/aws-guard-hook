# AWS Guard Hook — Specification

## 1. Purpose

Prevent Claude Code from executing AWS CLI commands that mutate cloud
infrastructure. Only read-only operations (queries, listings, descriptions)
are permitted through the CLI. All infrastructure changes must be expressed
in Infrastructure as Code (IaC) and applied through the IaC toolchain.

## 2. Scope

| In scope | Out of scope |
|---|---|
| Raw `aws` CLI invocations | `terraform apply`, `cdk deploy`, `sam deploy` (IaC deploys are intentional) |
| All AWS services | AWS SDK calls made from application code |
| Compound shell commands containing `aws` | Non-AWS system commands |
| Command substitutions `$(aws ...)` and backtick forms | |

## 3. Hook Type

**Claude Code `PreToolUse` hook** on the `Bash` tool.

The hook receives a JSON payload on stdin, inspects the `tool_input.command`
field, and either exits 0 (allow) or exits 2 (hard block) with a message on
stdout that Claude receives as the tool error.

There is **no override mechanism**. The block is absolute.

## 4. Detection Algorithm

### 4.1 Early exit

If the command string does not contain the word `aws` (whole-word match), the
hook exits 0 immediately without further inspection.

### 4.2 Extraction of AWS invocations

The command string is split on shell operators (`&&`, `||`, `;`, `|`). Each
segment is stripped of leading environment-variable assignments
(`KEY=VALUE aws ...`). Any segment that begins with `aws` is treated as an
AWS invocation to be evaluated.

Additionally, command substitutions of the form `$(aws ...)` and
`` `aws ...` `` are extracted and evaluated independently.

If `aws` appears in the command string but no invocations can be extracted,
the hook **blocks** conservatively.

### 4.3 Parsing service and subcommand

For each extracted invocation the hook tokenises the string using POSIX shell
quoting rules (Python `shlex.split`). It then iterates the tokens to find the
first two positional arguments (skipping known global flags and their values):

```
aws [global-flags] <service> [service-flags] <subcommand> [options]
```

If tokenisation fails (e.g. unclosed quote), the hook **blocks** conservatively.

### 4.4 Always-allowed combinations

The following are allowed unconditionally, regardless of subcommand prefix:

| Service | Subcommand(s) | Rationale |
|---|---|---|
| `sts` | any | Identity/session checks — purely interrogative |
| `configure` | `get`, `list`, `list-profiles` | Reads local config only |
| `s3` | `ls` | Listing — no mutation |
| `s3` | `presign` | Generates a URL — no mutation |
| `s3` | `cp` where source is `s3://` and destination is a local path | Download only |
| `logs` | `tail` | Streaming log reads |

### 4.5 Read-only prefix allowlist (general rule)

For all other service/subcommand combinations, the subcommand is checked
against the following prefix allowlist. A command is allowed if its subcommand
starts with any of these prefixes:

| Prefix | Example subcommands |
|---|---|
| `get-` | `get-object`, `get-function`, `get-role` |
| `list-` | `list-buckets`, `list-functions`, `list-roles` |
| `describe-` | `describe-instances`, `describe-stacks` |
| `query-` | `query` (DynamoDB) |
| `search-` | `search-resources` |
| `check-` | `check-dns-availability` |
| `validate-` | `validate-template` |
| `scan` | `scan` (DynamoDB — exact match, no trailing dash) |
| `batch-get-` | `batch-get-item` |
| `generate-presigned-` | `generate-presigned-url` |
| `estimate-` | `estimate-template-cost` |
| `preview-` | preview operations |
| `export-` | read-export operations |
| `filter-` | `filter-log-events` |
| `lookup-` | `lookup-events` |
| `calculate-` | `calculate-route` |
| `resolve-` | DNS resolution queries |
| `summarize-` | `summarize-findings` |

Anything not matched by the above is **blocked**.

### 4.6 Special case: `aws s3 cp` direction detection

For `aws s3 cp`, the hook inspects the first two positional arguments after
`cp` (skipping flags). The command is allowed only when:

- source starts with `s3://`  **AND**
- destination does **not** start with `s3://`

Uploads (`local → s3://`) and S3-to-S3 copies are blocked.

## 5. Block Message

When a command is blocked, the hook prints the following to stdout and exits 2:

```
[AWS Guard] Command blocked: this operation would perform a write/mutation on AWS infrastructure.

Policy: Only read-only AWS CLI operations are permitted. Allowed subcommand
prefixes: get-, list-, describe-, query-, search-, check-, validate-, scan,
batch-get-, generate-presigned- and similar read-only verbs. All
infrastructure changes must be made through Infrastructure as Code (IaC) and
applied using the appropriate IaC deployment workflow.

Blocked command: <the offending aws invocation>
```

Claude receives this message as the tool error and is expected to determine
the appropriate IaC action on its own.

## 6. IaC Toolchain

The hook is **IaC-tool-agnostic**. It does not reference any specific tool
(Terraform, CDK, CloudFormation, Pulumi, etc.). The guidance message uses the
generic term "Infrastructure as Code (IaC)" so users of any toolchain receive
correct guidance.

## 7. IaC Deploy Commands

Commands such as `terraform apply`, `cdk deploy`, `sam deploy`, and
`pulumi up` are **not intercepted**. These are intentional, expected
operations in an IaC workflow and fall outside the scope of this hook.

## 8. Non-Goals

- Blocking AWS SDK calls embedded in application source code.
- Inspecting the semantic impact of read-only calls (e.g. `describe-` that
  is expensive or rate-limited).
- Auditing or logging blocked commands to an external system.
- Any per-user or per-session override mechanism.

## 9. Configuration

The hook is configured via `.claude/settings.json` at project level:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 hooks/aws-guard.py"
          }
        ]
      }
    ]
  }
}
```

The script requires Python 3.8+ and no third-party dependencies.
