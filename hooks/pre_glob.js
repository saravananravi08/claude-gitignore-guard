#!/usr/bin/env node
/**
 * PreToolUse hook to block Glob from revealing sensitive files.
 */

const DANGEROUS_PATTERNS = [
  /[/\\]\.env/,
  /[/\\]\.ssh/,
  /[/\\]\.aws/,
  /[/\\]\.gcloud/,
  /[/\\]\.azure/,
  /[/\\]\.git/,
  /[/\\]\.npmrc/,
  /[/\\]\.yarnrc/,
  /[/\\]\.pgpass/,
  /[/\\]\.netrc/,
  /\.pem$/,
  /\.key$/,
  /\.crt$/,
  /id_rsa/,
  /id_ed25519/,
];

function isDangerousGlob(pattern) {
  for (const p of DANGEROUS_PATTERNS) {
    if (p.test(pattern)) {
      return true;
    }
  }
  return false;
}

function block(pattern) {
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `Blocked: glob pattern reveals sensitive files\nPattern: ${pattern}\nClaude will use a different approach.`,
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
  const globPattern = toolInput.pattern || '';

  if (!globPattern) {
    process.exit(0);
  }

  if (isDangerousGlob(globPattern)) {
    block(globPattern);
  }

  process.exit(0);
}

main();
