# claude-gitignore-guard

Claude Code plugin to prevent reading of `.env`, `.ssh`, `.aws`, secrets and sensitive dotfiles.

## Problem

Claude Code sometimes reads `.env`, `.ssh`, and other sensitive files even when they're in `.gitignore`. This plugin blocks Read, Bash, Glob, and Grep tools from accessing them.

## Features

- Blocks 90+ sensitive file patterns
- Works with Read, Bash, Glob, and Grep tools
- Claude self-corrects when blocked — no config needed
- Node.js (no Python required)

## Keywords

claude-code-plugin security secrets-protection env-files dotfiles privacy file-access-control claude-code-security claude-code-privacy prevent-secrets-reading

## Installation

```
/plugin marketplace add https://github.com/saravananravi08/claude-gitignore-guard
/plugin install gitignore-guard@claude-gitignore-guard
/reload-plugins
```

## What It Blocks

| Category | Examples |
|----------|----------|
| Environment files | `.env`, `.env.local`, `.env.production` |
| Cloud credentials | `.aws/`, `.gcloud/`, `.azure/` |
| SSH keys | `.ssh/id_rsa`, `.ssh/config` |
| Git configs | `.git/`, `.gitconfig`, `.git-credentials` |
| Database credentials | `.pgpass`, `.my.cnf`, `.mongoshrc.js` |
| Private keys | `*.pem`, `*.key`, `*.crt`, `*.p12`, `*.pfx` |
| Shell history | `.bash_history`, `.zsh_history` |
| CI/CD configs | GitHub Actions, GitLab, Travis CI |
| IDE configs | VSCode SFTP, JetBrains workspace |
| Password managers | KeePass, Bitwarden, 1Password |

## Safe Dotfiles (Allowed)

`.gitignore`, `.gitattributes`, `.editorconfig`, `.prettierrc`, `.eslintrc`, `package.json`, `tsconfig.json`, etc.

## How It Works

Uses `PreToolUse` hooks on Read, Bash, Glob, and Grep tools. Returns `permissionDecision: "deny"` with a reason — Claude sees it was blocked and uses a different approach.

## Requirements

- [Node.js](https://nodejs.org/) (for hook scripts)

## Uninstall

```
/plugin uninstall gitignore-guard
/plugin marketplace remove claude-gitignore-guard
```

## Author

saravananravi08 — https://github.com/saravananravi08
