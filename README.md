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
2. Each `aws` invocation is extracted from:
   - Compound commands (`&&`, `||`, `;`, `|`)
   - Piped-to-aws patterns (`cat data.json | aws s3api put-object ...`)
   - Command substitutions (`$(aws ...)`, `` `aws ...` ``)
   - Env-var prefixed forms (`AWS_PROFILE=prod aws ...`)
   - Heredoc bodies passed to a shell interpreter (`bash <<EOF\naws ...\nEOF`)
   - Shell `-c` inline strings (`bash -c 'aws ...'`)
   - AWS commands with heredoc stdin (`aws sqs send-message ... <<EOF`)
3. Heredoc content written to files (not executed) is stripped before checking,
   preventing false positives when a script file happens to mention `aws`.
4. The service and subcommand are parsed (skipping global flags like
   `--region`, `--profile`).
5. Always-allowed pairs pass immediately: all `aws sts *` commands,
   `aws configure get/list`, `aws s3 ls`, `aws s3 presign`,
   `aws s3 cp <s3://src> <local-dest>` (downloads only), `aws logs tail`.
6. For everything else the subcommand must start with a recognised read-only
   prefix: `get-`, `list-`, `describe-`, `query`, `search-`, `check-`,
   `validate-`, `scan`, `batch-get-`, `generate-presigned-`, `estimate-`,
   `preview-`, `export-`, `filter-`, `lookup-`, `calculate-`, `resolve-`,
   `summarize-`.
7. Anything that does not match is **hard-blocked** (exit 2). Claude receives
   the block message and is expected to identify the correct IaC change.

There is **no override**. The block is absolute.

IaC deploy commands (`terraform apply`, `cdk deploy`, `pulumi up`, etc.) are
**not** intercepted — they are intentional operations in an IaC workflow.

## Requirements

- Python 3.8+ **or** [uv](https://docs.astral.sh/uv/) (preferred — zero-latency startup)
- No third-party dependencies (stdlib only)

The script has a `uv`-compatible PEP 723 shebang, so `uv run hooks/aws_guard.py`
works with no virtualenv setup.

## Installation

### Option A — Claude Code plugin (recommended)

This repo ships as a Claude Code plugin. Install it via the plugin system:

```shell
# Add a marketplace pointing at this repo (one-time setup)
/plugin marketplace add <repo-url>

# Install the plugin — hook is registered automatically
/plugin install aws-guard
```

The plugin manifest is at `.claude-plugin/plugin.json` and the hook
definition is at `hooks/hooks.json`.

### Option B — user-level install (all projects on this machine)

Run the included install script. It copies the hook to `~/.claude/hooks/`
and merges the configuration into `~/.claude/settings.json`:

```bash
./install.sh
```

The hook then applies to every Claude Code project you open, not just this
repo.  To uninstall, remove the corresponding entry from
`~/.claude/settings.json`.

### Option C — project-level (this repo already configured)

The `.claude/settings.json` in this repository already registers the hook.
Clone the repo and open it with Claude Code:

```bash
git clone <repo-url> my-project
cd my-project
claude  # hook is active immediately
```

### Option D — add to an existing project manually

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
            "command": "uv run hooks/aws_guard.py"
          }
        ]
      }
    ]
  }
}
```

Use `python3 hooks/aws_guard.py` if `uv` is not available.

3. Verify the hook format against the current
   [Claude Code hooks documentation](https://docs.anthropic.com/en/docs/claude-code/hooks)
   if the schema has changed since this was written.

## AWS Read-Only Skill (`/aws-readonly`)

This repo also ships a **Claude Code skill** that gives Claude proactive
guidance — before it ever tries a write command — rather than relying solely
on the hook to block it after the fact.

### What the skill does

Invoking `/aws-readonly` loads a system-level prompt that instructs Claude to:

- Use only read-only AWS CLI commands (`describe-*`, `list-*`, `get-*`, etc.)
  for inspection and discovery.
- Avoid write/mutation CLI commands entirely (`create-*`, `put-*`, `delete-*`,
  `update-*`, etc.).
- Express any desired infrastructure change by **editing IaC source files**
  (Terraform `.tf`, CDK app, CloudFormation template, Pulumi program, or SAM
  `template.yaml`) rather than running the AWS CLI directly or writing
  one-off shell scripts.
- Follow an inspect → plan → edit IaC → review (`terraform plan` / `cdk diff`)
  → apply workflow.

The skill explains **why** this matters (drift, audit trail, rollback safety)
so Claude can reason about it and explain the constraint to you if asked.

### How to use the skill

The skill file lives at `.claude/commands/aws-readonly.md`.  Load it at the
start of any session where you want Claude to operate in read-only/IaC mode:

```
/aws-readonly
```

Claude Code reads the markdown file and treats its contents as active
guidance for the rest of the session.

### Skill vs. hook — two complementary layers

| Layer | When it acts | What it does |
|---|---|---|
| **`/aws-readonly` skill** | Proactively, at session start | Guides Claude toward IaC; prevents write attempts before they happen |
| **`aws_guard.py` hook** | Reactively, before every Bash call | Hard-blocks any write command that slips through; no override |

Using both layers together gives you defence-in-depth: the skill shapes
Claude's intent; the hook enforces the policy as a hard safety net.

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

116 tests cover: read-only allows, write blocks, compound commands, pipelines,
piped-to-aws commands, command substitutions, heredoc body detection (both
executed and non-executed), `bash -c` inline detection, `aws s3 cp` direction
detection, and global-flag parsing.

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
