#!/usr/bin/env python3
"""
PreToolUse hook to block reading of dotfiles and dangerous files.

Claude Code receives the denial reason and self-corrects.
"""

import json
import os
import re
import sys

# Patterns for dangerous files (regex)
DANGEROUS_PATTERNS = [
    (r'[/\\]\.env(\.[a-zA-Z0-9]+)?$', '.env file'),
    (r'[/\\]\.env$', '.env file'),
    (r'[/\\]\.ssh[/\\]', 'SSH directory'),
    (r'[/\\]\.aws[/\\]', 'AWS credentials directory'),
    (r'[/\\]\.git[/\\]', '.git directory'),
    (r'[/\\]id_rsa', 'SSH private key'),
    (r'[/\\]id_ed25519', 'SSH private key'),
    (r'[/\\]\.npmrc$', 'npm credentials'),
    (r'[/\\]\.yarnrc$', 'yarn credentials'),
    (r'[/\\]\.pgpass$', 'PostgreSQL credentials'),
    (r'[/\\]\.netrc$', 'netrc credentials'),
    (r'\.pem$', 'certificate file'),
    (r'\.key$', 'private key file'),
    (r'\.p12$', 'PKCS12 file'),
    (r'\.pfx$', 'PFX file'),
]

# Safe dotfiles that should NOT be blocked
SAFE_DOTFILES = {
    '.gitignore', '.gitattributes', '.gitmodules',
    '.editorconfig', '.prettierrc', '.prettierrc.json', '.prettierrc.js',
    '.eslintrc', '.eslintrc.json', '.eslintrc.js', '.eslintrc.yaml',
    '.clang-format', '.clang-tidy',
    '.flake8', '.pylintrc', '.mypy.ini',
    'package.json', 'package-lock.json', 'yarn.lock',
    'tsconfig.json', 'jsconfig.json',
    '.browserslistrc', '.nvmrc', '.node-version',
}

# Regex to detect dotfiles (file starting with . in path)
DOTFILE_REGEX = re.compile(r'[/\\]\.[^./][^/\\]*$')


def is_dangerous_file(file_path: str) -> tuple[bool, str]:
    """Check if file matches dangerous patterns."""
    normalized = file_path.replace('\\', '/')
    for pattern, description in DANGEROUS_PATTERNS:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True, description
    return False, ""


def is_dotfile(file_path: str) -> bool:
    """Check if file is a dotfile (not in SAFE_DOTFILES)."""
    normalized = file_path.replace('\\', '/')

    # Check if it's a dotfile
    if not DOTFILE_REGEX.search(normalized):
        return False

    # Extract just the filename for safe check
    filename = normalized.rsplit('/', 1)[-1]

    # It's safe if it's in our safe list
    if filename in SAFE_DOTFILES:
        return False

    # It's dangerous if it starts with . and is a hidden file
    return filename.startswith('.')


def block(reason: str, file_path: str):
    """Output JSON to deny the tool call with a reason."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"Blocked: {reason}\nFile: {file_path}\nClaude will use a different approach."
        }
    }
    print(json.dumps(output))
    sys.exit(0)


def main():
    input_data = json.loads(sys.stdin.read())
    tool_input = input_data.get("tool_input", {})
    file_path = tool_input.get("file_path", "")

    if not file_path:
        sys.exit(0)

    # Check dangerous patterns first
    is_dangerous, danger_desc = is_dangerous_file(file_path)
    if is_dangerous:
        block(danger_desc, file_path)

    # Check if it's a dotfile
    if is_dotfile(file_path):
        block("dotfile", file_path)

    sys.exit(0)


if __name__ == "__main__":
    main()
