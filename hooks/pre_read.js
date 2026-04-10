#!/usr/bin/env node
/**
 * PreToolUse hook to block reading of dotfiles and dangerous files.
 * Claude Code receives the denial reason and self-corrects.
 */

const DANGEROUS_PATTERNS = [
  { regex: /[/\\]\.env(\.[a-zA-Z0-9]+)?$/, desc: '.env file' },
  { regex: /[/\\]\.ssh[/\\]/, desc: 'SSH directory' },
  { regex: /[/\\]\.aws[/\\]/, desc: 'AWS credentials directory' },
  { regex: /[/\\]\.git[/\\]/, desc: '.git directory' },
  { regex: /[/\\]id_rsa/, desc: 'SSH private key' },
  { regex: /[/\\]id_ed25519/, desc: 'SSH private key' },
  { regex: /[/\\]\.npmrc$/, desc: 'npm credentials' },
  { regex: /[/\\]\.yarnrc$/, desc: 'yarn credentials' },
  { regex: /[/\\]\.pgpass$/, desc: 'PostgreSQL credentials' },
  { regex: /[/\\]\.netrc$/, desc: 'netrc credentials' },
  { regex: /\.pem$/, desc: 'certificate file' },
  { regex: /\.key$/, desc: 'private key file' },
  { regex: /\.p12$/, desc: 'PKCS12 file' },
  { regex: /\.pfx$/, desc: 'PFX file' },
];

const SAFE_DOTFILES = new Set([
  '.gitignore', '.gitattributes', '.gitmodules',
  '.editorconfig', '.prettierrc', '.prettierrc.json', '.prettierrc.js',
  '.eslintrc', '.eslintrc.json', '.eslintrc.js', '.eslintrc.yaml',
  '.clang-format', '.clang-tidy',
  '.flake8', '.pylintrc', '.mypy.ini',
  'package.json', 'package-lock.json', 'yarn.lock',
  'tsconfig.json', 'jsconfig.json',
  '.browserslistrc', '.nvmrc', '.node-version',
]);

const DOTFILE_REGEX = /[/\\]\.[^./][^/\\]*$/;

function isDangerousFile(filePath) {
  const normalized = filePath.replace(/\\/g, '/');
  for (const { regex, desc } of DANGEROUS_PATTERNS) {
    if (regex.test(normalized)) {
      return desc;
    }
  }
  return null;
}

function isDotfile(filePath) {
  const normalized = filePath.replace(/\\/g, '/');

  if (!DOTFILE_REGEX.test(normalized)) {
    return false;
  }

  const filename = normalized.split('/').pop();

  if (SAFE_DOTFILES.has(filename)) {
    return false;
  }

  return filename.startsWith('.');
}

function block(reason, filePath) {
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: `Blocked: ${reason}\nFile: ${filePath}\nClaude will use a different approach.`,
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
  const filePath = toolInput.file_path || '';

  if (!filePath) {
    process.exit(0);
  }

  const dangerDesc = isDangerousFile(filePath);
  if (dangerDesc) {
    block(dangerDesc, filePath);
  }

  if (isDotfile(filePath)) {
    block('dotfile', filePath);
  }

  process.exit(0);
}

main();
