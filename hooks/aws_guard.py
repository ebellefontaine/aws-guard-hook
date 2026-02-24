#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# ///
"""
AWS Guard Hook for Claude Code

Blocks AWS CLI write/mutation operations so that all infrastructure changes
are made through Infrastructure as Code (IaC) rather than direct CLI calls.

Only read-only operations (get-, list-, describe-, query-, search-, etc.) are
permitted.  There is no override mechanism — the block is absolute.

Exit codes (Claude Code PreToolUse hook convention):
  0  — command is allowed, tool proceeds normally
  2  — command is blocked, stdout message is delivered to Claude as the error
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Subcommand prefixes that unambiguously indicate a read-only AWS operation.
#
# Entries WITHOUT a trailing dash are treated as prefix-or-exact matches, so
# "scan" matches both the bare "scan" subcommand (DynamoDB) and hypothetical
# "scan-*" variants.  Entries WITH a trailing dash require the subcommand to
# have additional characters after the dash.
READ_ONLY_PREFIXES: Tuple[str, ...] = (
    "get-",
    "list-",
    "describe-",
    "query",        # matches "query" (DynamoDB) and "query-*"
    "search-",
    "check-",
    "validate-",
    "scan",         # matches "scan" (DynamoDB) and "scan-*"
    "batch-get-",
    "generate-presigned-",
    "estimate-",
    "preview-",
    "export-",
    "filter-",
    "lookup-",
    "calculate-",
    "resolve-",
    "summarize-",
)

# (service, subcommand_or_None) pairs that are always allowed.
# None for the subcommand means every subcommand under that service is allowed.
ALWAYS_ALLOWED: Tuple[Tuple[str, Optional[str]], ...] = (
    ("sts", None),              # get-caller-identity, assume-role-with-web-identity, …
    ("configure", "get"),
    ("configure", "list"),
    ("configure", "list-profiles"),
    ("logs", "tail"),
)

# Global AWS CLI flags that each consume the *next* token as their value.
AWS_GLOBAL_VALUE_FLAGS = frozenset({
    "--endpoint-url",
    "--output",
    "--query",
    "--profile",
    "--region",
    "--color",
    "--ca-bundle",
    "--cli-read-timeout",
    "--cli-connect-timeout",
    "--cli-binary-format",
})

# Shell interpreter names whose heredoc bodies and -c arguments we inspect.
# The negative lookbehind (?<![.\w]) prevents matching file extensions like
# ".sh" in "deploy.sh" or words like "mybash".
_SHELL_RE = r"(?<![.\w])(?:bash|sh|zsh|dash|ksh)"

BLOCK_MESSAGE_TEMPLATE = """\
[AWS Guard] Command blocked: this operation would perform a write/mutation on AWS infrastructure.

Policy: Only read-only AWS CLI operations are permitted. Allowed subcommand \
prefixes: get-, list-, describe-, query-, search-, check-, validate-, scan, \
batch-get-, generate-presigned-, and similar read-only verbs. All \
infrastructure changes must be made through Infrastructure as Code (IaC) \
and applied using the appropriate IaC deployment workflow.

Blocked command: {cmd}"""


# ---------------------------------------------------------------------------
# Heredoc utilities
# ---------------------------------------------------------------------------

# Matches a heredoc block: <<[-]?[optional-quote]MARKER[optional-quote]\n BODY \nMARKER
# Group 1: opening (e.g. "<<"), Group 2: marker word, Group 3: rest of opening line + \n
# Group 4 (implicit via .*?): body, Group 5: closing \nMARKER line
_HEREDOC_RE = re.compile(
    r"(<<-?\s*['\"]?)(\w+)(['\"]?[^\n]*\n)"  # opening: <<[-]['"]?MARKER['"]?[rest-of-line]\n
    r".*?"                                     # body (non-greedy, DOTALL)
    r"(\n\2[ \t]*(?:\n|$))",                  # closing: \nMARKER (own line)
    re.DOTALL,
)


def strip_heredoc_bodies(command: str) -> str:
    """
    Replace heredoc body text with a placeholder, leaving the markers intact.

    Used to distinguish 'aws' that appears in non-executed heredoc text
    (e.g. writing a shell script) from 'aws' that is actually invoked.

    Example:
        cat > deploy.sh <<EOF        ← kept
        aws ec2 run-instances ...    ← replaced with <heredoc>
        EOF                          ← kept
    """
    return _HEREDOC_RE.sub(r"\1\2\3<heredoc>\4", command)


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def extract_aws_invocations(command: str) -> List[str]:
    """
    Return every distinct aws CLI invocation found inside *command*.

    Handles:
    - Simple commands:              aws ec2 describe-instances
    - Piped-to-aws:                 cat data.json | aws s3api put-object ...
    - Compound commands:            aws ec2 describe ... && aws ec2 run-instances ...
    - Env-var prefixes:             AWS_PROFILE=prod aws ec2 describe-instances
    - Shell redirections / heredoc: aws sqs send-message --body - <<EOF ...
    - Command substitutions:        $(aws sts get-caller-identity)
    - Backtick substitutions:       `aws sts get-caller-identity`
    """
    found: List[str] = []

    # 1. Split on shell operators and examine each segment.
    #    This naturally handles both "aws ... | cmd" and "cmd | aws ..."
    #    because we check every segment, not just the first.
    segments = re.split(r"\s*(?:&&|\|\||;|\|)\s*", command)
    for seg in segments:
        seg = seg.strip()
        # Strip leading VAR=value assignments (e.g. AWS_PROFILE=prod aws ...)
        stripped = re.sub(r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*", "", seg)
        if re.match(r"aws\s", stripped):
            found.append(stripped)

    # 2. Extract $(...) command substitutions.
    for m in re.finditer(r"\$\(\s*(aws\s[^)]+)\)", command):
        found.append(m.group(1).strip())

    # 3. Extract backtick substitutions.
    for m in re.finditer(r"`\s*(aws\s[^`]+)`", command):
        found.append(m.group(1).strip())

    return found


def extract_heredoc_shell_aws(command: str) -> List[str]:
    """
    Extract aws invocations from heredoc bodies passed to a shell interpreter.

    Catches patterns like:

        bash <<EOF
        aws ec2 run-instances --image-id ami-... --instance-type t3.micro
        EOF

        sh <<'SCRIPT'
        aws s3 rm s3://my-bucket/file.txt
        SCRIPT
    """
    found: List[str] = []
    pattern = re.compile(
        r"\b" + _SHELL_RE + r"\b"       # bash / sh / zsh / dash / ksh
        r"[^\n]*"                        # optional flags on same line
        r"<<-?\s*['\"]?(\w+)['\"]?"     # <<[-][']MARKER[']
        r"[^\n]*\n"                      # rest of opening line (e.g. redirects), then newline
        r"(.*?)"                         # body (captured)
        r"\n\1[ \t]*(?:\n|$)",          # closing MARKER on its own line
        re.DOTALL,
    )
    for m in pattern.finditer(command):
        body = m.group(2)
        found.extend(extract_aws_invocations(body))
    return found


def extract_bash_c_aws(command: str) -> List[str]:
    """
    Extract aws invocations from shell -c '...' / shell -c "..." inline strings.

    Catches patterns like:

        bash -c 'aws ec2 run-instances ...'
        sh -c "aws s3 rm s3://bucket/file"
        bash -x -e -c 'aws lambda invoke ...'
    """
    found: List[str] = []
    prefix = r"\b" + _SHELL_RE + r"\b\s+(?:-\w+\s+)*-c\s+"

    # Single-quoted: content cannot contain literal single quotes in POSIX shell
    for m in re.finditer(prefix + r"'([^']*)'", command):
        found.extend(extract_aws_invocations(m.group(1)))

    # Double-quoted: allow escaped characters inside
    for m in re.finditer(prefix + r'"((?:[^"\\]|\\.)*)"', command):
        found.extend(extract_aws_invocations(m.group(1)))

    return found


def parse_aws_positional(cmd_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Tokenise an 'aws ...' string and return (service, subcommand).

    Shell redirections (<<EOF, >, >>) are not POSIX metacharacters in the
    default shlex mode, so they tokenise as ordinary words and are safely
    ignored because parse_aws_positional stops after finding two positionals.

    Returns (None, None) when tokenisation fails or 'aws' is not the first
    token.
    """
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        return None, None

    if not tokens or tokens[0] != "aws":
        return None, None

    positional: List[str] = []
    i = 1
    while i < len(tokens) and len(positional) < 2:
        tok = tokens[i]
        if tok in AWS_GLOBAL_VALUE_FLAGS:
            i += 2  # skip flag + its value
        elif tok.startswith("-"):
            i += 1  # skip boolean flag
        else:
            positional.append(tok)
            i += 1

    service = positional[0] if len(positional) > 0 else None
    subcommand = positional[1] if len(positional) > 1 else None
    return service, subcommand


def is_s3_cp_download(cmd_str: str) -> bool:
    """
    Return True when 'aws s3 cp' copies *from* S3 *to* a local path.

    Uploads (local → s3://) and S3-to-S3 copies are not downloads.
    """
    try:
        tokens = shlex.split(cmd_str)
    except ValueError:
        return False

    # Find the index of 'cp' (must appear at position >= 2, after 'aws s3').
    cp_idx: Optional[int] = None
    for idx, tok in enumerate(tokens):
        if tok == "cp" and idx >= 2:
            cp_idx = idx
            break
    if cp_idx is None:
        return False

    # Collect the first two positional arguments after 'cp'.
    positional: List[str] = []
    i = cp_idx + 1
    while i < len(tokens) and len(positional) < 2:
        tok = tokens[i]
        if tok.startswith("-"):
            i += 2  # conservatively skip flag + presumed value
        else:
            positional.append(tok)
            i += 1

    if len(positional) < 2:
        return False  # can't determine direction — block conservatively

    source, dest = positional[0], positional[1]
    return source.startswith("s3://") and not dest.startswith("s3://")


# ---------------------------------------------------------------------------
# Decision logic
# ---------------------------------------------------------------------------

def is_invocation_allowed(aws_cmd: str) -> Tuple[bool, str]:
    """
    Evaluate a single aws CLI invocation string.

    Returns (allowed, reason_if_blocked).
    """
    service, subcommand = parse_aws_positional(aws_cmd)

    if service is None:
        return False, f"could not parse AWS command: {aws_cmd!r}"

    # --- Always-allowed service/subcommand pairs ---
    for svc, sub in ALWAYS_ALLOWED:
        if service == svc and (sub is None or subcommand == sub):
            return True, ""

    # --- Special handling for aws s3 ---
    if service == "s3":
        if subcommand == "ls":
            return True, ""
        if subcommand == "presign":
            return True, ""
        if subcommand == "cp":
            if is_s3_cp_download(aws_cmd):
                return True, ""
            return False, "aws s3 cp is only permitted for downloads (s3:// → local)"
        # mv, rm, sync, mb, rb, website, … are all writes
        return False, f"aws s3 {subcommand!r} is a write/mutation operation"

    # --- No subcommand parsed ---
    if subcommand is None:
        return False, f"no subcommand found for: {aws_cmd!r}"

    # --- General read-only prefix allowlist ---
    # Entries in READ_ONLY_PREFIXES without a trailing dash (e.g. "scan",
    # "query") match both the bare subcommand and any "word-*" extensions,
    # because startswith("scan") matches "scan" and "scan-something" equally.
    if any(subcommand.startswith(p) for p in READ_ONLY_PREFIXES):
        return True, ""

    return False, f"'aws {service} {subcommand}' is not a recognised read-only operation"


def evaluate_command(command: str) -> Tuple[bool, str]:
    """
    Evaluate a full shell command string.

    Returns (allowed, blocked_invocation_string).
    """
    # Fast path — no 'aws' in the command at all.
    if not re.search(r"\baws\b", command):
        return True, ""

    invocations: List[str] = []

    # 1. Direct invocations, pipelines (both directions), compound commands,
    #    command substitutions, and heredoc-redirected aws commands.
    invocations.extend(extract_aws_invocations(command))

    # 2. aws commands inside heredoc bodies passed to a shell interpreter
    #    (e.g. bash <<EOF\naws ec2 run-instances...\nEOF).
    invocations.extend(extract_heredoc_shell_aws(command))

    # 3. aws commands inside shell -c '...' inline strings
    #    (e.g. bash -c 'aws ec2 run-instances ...').
    invocations.extend(extract_bash_c_aws(command))

    if not invocations:
        # 'aws' is somewhere in the string but we could not identify an
        # executed invocation.  Before blocking conservatively, check whether
        # 'aws' appears ONLY inside non-executed heredoc bodies (e.g. a script
        # being written to disk with cat/tee and a heredoc).
        if not re.search(r"\baws\b", strip_heredoc_bodies(command)):
            return True, ""  # 'aws' only in heredoc text, not executed

        # 'aws' is present outside heredoc text but unextractable — block.
        return False, command.strip()

    for inv in invocations:
        allowed, _reason = is_invocation_allowed(inv)
        if not allowed:
            return False, inv

    return True, ""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Unparseable input — fail open so we don't break non-AWS tools.
        sys.exit(0)

    # This hook only targets the Bash tool.
    if payload.get("tool_name") != "Bash":
        sys.exit(0)

    command: str = payload.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    allowed, blocked_inv = evaluate_command(command)
    if allowed:
        sys.exit(0)

    print(BLOCK_MESSAGE_TEMPLATE.format(cmd=blocked_inv))
    sys.exit(2)


if __name__ == "__main__":
    main()
