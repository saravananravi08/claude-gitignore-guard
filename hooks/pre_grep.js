#!/usr/bin/env node
/**
 * PreToolUse hook to block Grep from reading sensitive files.
 */

const DANGEROUS_PATTERNS = [
  /[/\\]\.env(\.[a-zA-Z0-9]+)?$/,
  /[/\\]\.envrc$/,
  /[/\\]\.ssh[/\\]/,
  /[/\\]\.aws[/\\]/,
  /[/\\]\.gcloud[/\\]/,
  /[/\\]\.azure[/\\]/,
  /[/\\]\.git[/\\]/,
  /[/\\]\.git-credentials$/,
  /[/\\]\.gitconfig$/,
  /[/\\]\.npmrc$/,
  /[/\\]\.yarnrc$/,
  /[/\\]\.pgpass$/,
  /[/\\]\.my\.cnf$/,
  /[/\\]\.netrc$/,
  /\.pem$/,
  /\.key$/,
  /\.crt$/,
  /\.p12$/,
  /\.pfx$/,
  /\.jks$/,
  /[/\\]\.bash_history$/,
  /[/\\]\.zsh_history$/,
  /[/\\]\.aws\/credentials$/,
  /[/\\]wp-config\.php$/,
];

function isSensitivePath(path) {
  if (!path) return false;
  const normalized = path.replace(/\\/g, '/');
  for (const p of DANGEROUS_PATTERNS) {
    if (p.test(normalized)) {
      return true;
    }
  }
  return false;
}

function block(pattern, path) {
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `Blocked: grep reading sensitive file\nPath: ${path}\nPattern: ${pattern}\nClaude will use a different approach.`,
    },
  };
  console.log(JSON.stringify(output));
  process.exit(0);
}

function main() {
  let input;
  try {
    input = JSON.parse(require('fs').readFileSync(0, 'utf-8'));
  } catch {
    process.exit(0);
  }

  const toolInput = input.tool_input || {};
  const path = toolInput.path || '';
  const grepPattern = toolInput.pattern || '';

  if (!path) {
    process.exit(0);
  }

  if (isSensitivePath(path)) {
    block(grepPattern, path);
  }

  process.exit(0);
}

main();
