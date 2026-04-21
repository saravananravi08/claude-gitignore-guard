#!/usr/bin/env node
/**
 * PreToolUse hook to block Bash commands that read sensitive files.
 */

const DANGEROUS_PATTERNS = [
  // Environment/secrets files
  /[/\\]\.env(\.[a-zA-Z0-9]+)?$/,
  /[/\\]\.envrc$/,
  // Cloud provider directories
  /[/\\]\.aws[/\\]/,
  /[/\\]\.gcloud[/\\]/,
  /[/\\]\.azure[/\\]/,
  /[/\\]\.do[/\\]/,
  /[/\\]\.oci[/\\]/,
  /[/\\]\.scaleway[/\\]/,
  // SSH keys
  /[/\\]\.ssh[/\\]/,
  /[/\\]id_rsa/,
  /[/\\]id_ed25519/,
  /[/\\]id_ecdsa/,
  // Git credentials
  /[/\\]\.git-credentials$/,
  /[/\\]\.gitconfig$/,
  /[/\\]\.git[/\\]/,
  // Package manager credentials
  /[/\\]\.npmrc$/,
  /[/\\]\.yarnrc$/,
  /[/\\]\.pypirc$/,
  /[/\\]\.gem\/credentials$/,
  // Database credentials
  /[/\\]\.pgpass$/,
  /[/\\]\.my\.cnf$/,
  /[/\\]\.mongoshrc\.js$/,
  /[/\\]\.odbc\.ini$/,
  /[/\\]\.pg_service\.conf$/,
  // Netrc
  /[/\\]\.netrc$/,
  // Private keys and certificates
  /\.pem$/,
  /\.crt$/,
  /\.key$/,
  /\.p12$/,
  /\.pfx$/,
  /\.jks$/,
  // Shell history
  /[/\\]\.bash_history$/,
  /[/\\]\.zsh_history$/,
  // Password managers
  /\.kdbx?$/,
  // AWS credentials
  /[/\\]\.aws\/credentials$/,
  /[/\\]\.aws\/config$/,
  // Misc secrets
  /[/\\]wp-config\.php$/,
  /[/\\]config\/database\.yml$/,
  /[/\\]config\/secrets\.yml$/,
  /[/\\]config\/credentials\.yml\.enc$/,
];

const READ_COMMANDS = [
  'cat', 'less', 'more', 'head', 'tail', 'grep', 'sed', 'awk',
  'echo', 'tee', 'wc', 'sort', 'uniq', 'strings', 'xxd', 'hexdump',
  'od', 'vim', 'vi', 'nano', 'emacs', 'nano', 'pico', 'jed',
  'type', 'fc', 'script',
];

function isDangerousPath(command) {
  const normalized = command.replace(/\\/g, '/');
  for (const pattern of DANGEROUS_PATTERNS) {
    if (pattern.test(normalized)) {
      return true;
    }
  }
  return false;
}

function block(reason, command) {
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `Blocked: ${reason}\nCommand: ${command}\nClaude will use a different approach.`,
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
  const command = toolInput.command || '';

  if (!command) {
    process.exit(0);
  }

  // Check if command reads files
  const parts = command.trim().split(/\s+/);
  const cmd = parts[0];

  if (!READ_COMMANDS.includes(cmd)) {
    process.exit(0);
  }

  // Get file paths from command
  const args = parts.slice(1).join(' ');
  const normalized = args.replace(/\\/g, '/');

  // Check for redirections and command substitution
  if (/<\s*[^\s]+/.test(args) || /\$[^\$]+\$/.test(args) || /`[^`]+`/.test(args)) {
    const matches = args.match(/<\s*([^\s]+)|\$[^\$]+\$|`[^`]+`/g);
    if (matches) {
      for (const match of matches) {
        const path = match.replace(/^<\s*/, '').replace(/\$/g, '').replace(/`/g, '');
        if (isDangerousPath(path)) {
          block('reading sensitive file via redirection/substitution', command);
        }
      }
    }
  }

  // Extract file path before checking (handles trailing redirections like 2>&1)
  const filePath = normalized.split(/[|\s<>&\`]/)[0];
  if (isDangerousPath(filePath)) {
    block('reading sensitive file', command);
  }

  process.exit(0);
}

main();
