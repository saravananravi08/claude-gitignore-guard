# claude-gitignore-guard

A Claude Code plugin that prevents reading of `.gitignore`'d files and dangerous dotfiles (`.env`, `.ssh`, etc.).

## Requirements

- [Node.js](https://nodejs.org/) (for the hook script)

## Installation

```
/plugin marketplace add https://github.com/saravananravi08/claude-gitignore-guard
/plugin install gitignore-guard@claude-gitignore-guard
```

## What It Blocks

| Pattern | Examples |
|---------|----------|
| `.env` files | `.env`, `.env.local`, `.env.production` |
| SSH directory | `.ssh/id_rsa`, `.ssh/config` |
| AWS credentials | `.aws/credentials` |
| Git directory | `.git/config` |
| Private keys | `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| All dotfiles | `.*` files (except safe ones below) |

## Safe Dotfiles (Allowed)

These dotfiles are allowed through:

`.gitignore`, `.gitattributes`, `.gitmodules`, `.editorconfig`, `.prettierrc`, `.eslintrc`, `package.json`, `package-lock.json`, `tsconfig.json`, etc.

## Usage

After installing, the plugin automatically blocks attempts to read sensitive files. Claude Code will see the denial and use a different approach.

### Test it

```
/read .env
```
Should be blocked with: `Blocked: .env file`

```
/read src/index.js
```
Should work normally.

## How It Works

Uses a `PreToolUse` hook on the `Read` tool. When Claude Code tries to read a blocked file, the hook returns a denial with a reason, and Claude self-corrects.

## Uninstall

```
/plugin uninstall gitignore-guard
/plugin marketplace remove claude-gitignore-guard
```
