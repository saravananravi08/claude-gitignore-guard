#!/usr/bin/env node
/**
 * PreToolUse hook to block reading of dotfiles and dangerous files.
 * Claude Code receives the denial reason and self-corrects.
 */

const DANGEROUS_PATTERNS = [
  // Environment/secrets files
  { regex: /[/\\]\.env(\.[a-zA-Z0-9]+)?$/, desc: '.env file' },
  { regex: /[/\\]\.envrc$/, desc: 'direnv file' },

  // Cloud provider directories
  { regex: /[/\\]\.aws[/\\]/, desc: 'AWS credentials directory' },
  { regex: /[/\\]\.gcloud[/\\]/, desc: 'Google Cloud credentials directory' },
  { regex: /[/\\]\.azure[/\\]/, desc: 'Azure credentials directory' },
  { regex: /[/\\]\.do[/\\]/, desc: 'DigitalOcean credentials directory' },
  { regex: /[/\\]\.oci[/\\]/, desc: 'Oracle Cloud credentials directory' },
  { regex: /[/\\]\.scaleway[/\\]/, desc: 'Scaleway credentials directory' },

  // SSH keys and config
  { regex: /[/\\]\.ssh[/\\]/, desc: 'SSH directory' },
  { regex: /[/\\]id_rsa/, desc: 'SSH private key' },
  { regex: /[/\\]id_ed25519/, desc: 'SSH private key' },
  { regex: /[/\\]id_ecdsa/, desc: 'SSH private key' },
  { regex: /[/\\]known_hosts$/, desc: 'SSH known hosts' },

  // Git credentials
  { regex: /[/\\]\.git-credentials$/, desc: 'git credentials file' },
  { regex: /[/\\]\.gitconfig$/, desc: 'gitconfig with potential tokens' },
  { regex: /[/\\]\.git[/\\]/, desc: '.git directory' },

  // Package manager credentials
  { regex: /[/\\]\.npmrc$/, desc: 'npm credentials' },
  { regex: /[/\\]\.yarnrc$/, desc: 'yarn credentials' },
  { regex: /[/\\]\.pypirc$/, desc: 'PyPI credentials' },
  { regex: /[/\\]\.pearrc$/, desc: 'PEAR credentials' },
  { regex: /[/\\]\.gem\/credentials$/, desc: 'RubyGems credentials' },

  // Database credentials
  { regex: /[/\\]\.pgpass$/, desc: 'PostgreSQL credentials' },
  { regex: /[/\\]\.my\.cnf$/, desc: 'MySQL credentials' },
  { regex: /[/\\]\.mongoshrc\.js$/, desc: 'MongoDB credentials' },
  { regex: /[/\\]\.odbc\.ini$/, desc: 'ODBC credentials' },
  { regex: /[/\\]\.pg_service\.conf$/, desc: 'PostgreSQL service credentials' },

  // Netrc and network credentials
  { regex: /[/\\]\.netrc$/, desc: 'netrc credentials file' },
  { regex: /[/\\]\.tugboat$/, desc: 'DigitalOcean/Droplet credentials' },
  { regex: /[/\\]\.transifex\.rc$/, desc: 'Transifex credentials' },
  { regex: /[/\\]\.cloudscale\.rc$/, desc: 'Cloudscale credentials' },
  { regex: /[/\\]\.oraclecloud\.rc$/, desc: 'Oracle Cloud credentials' },

  // Infrastructure/secrets management
  { regex: /[/\\]\.sops\.ya?ml$/, desc: 'AWS SOPS secrets file' },
  { regex: /ansible\/vault\.ya?ml$/, desc: 'Ansible vault file' },
  { regex: /[/\\]vault\.ya?ml$/, desc: 'HashiCorp Vault configuration' },
  { regex: /secrets\.ya?ml$/, desc: 'secrets file' },
  { regex: /credentials\.ya?ml$/, desc: 'credentials file' },
  { regex: /[/\\]\.tfsploit\.yml$/, desc: 'TensorFlow secrets' },

  // Docker/Container
  { regex: /[/\\]\.docker[/\\]/, desc: 'Docker configuration directory' },
  { regex: /[/\\]\.dockerignore$/, desc: 'dockerignore with secrets' },
  { regex: /[/\\]Dockerfile$/, desc: 'Dockerfile with secrets' },
  { regex: /docker-compose.+\.ya?ml$/, desc: 'docker-compose with secrets' },

  // Kubernetes
  { regex: /[/\\]\.kube[/\\]/, desc: 'Kubernetes config directory' },
  { regex: /[/\\]\.kubeconfig$/, desc: 'Kubernetes config file' },
  { regex: /[/\\]kubectl.cfg$/, desc: 'kubectl config' },

  // CI/CD secrets
  { regex: /[/\\]\.github[/\\]workflows[/\\]/, desc: 'GitHub Actions workflows directory' },
  { regex: /[/\\]\.gitlab-ci\.yml$/, desc: 'GitLab CI config with secrets' },
  { regex: /[/\\]\.travis\.yml$/, desc: 'Travis CI config with secrets' },
  { regex: /[/\\]\.circleci[/\\]/, desc: 'CircleCI config directory' },
  { regex: /[/\\]\.gitlab[/\\]/, desc: 'GitLab configuration directory' },

  // Private keys and certificates
  { regex: /\.pem$/, desc: 'PEM certificate/private key file' },
  { regex: /\.crt$/, desc: 'certificate file' },
  { regex: /\.key$/, desc: 'private key file' },
  { regex: /\.p12$/, desc: 'PKCS12 file' },
  { regex: /\.pfx$/, desc: 'PFX file' },
  { regex: /\.jks$/, desc: 'Java keystore file' },

  // Payment/Finance
  { regex: /[/\\]\.stripe\.php$/, desc: 'Stripe configuration' },
  { regex: /[/\\]stripe_key/, desc: 'Stripe API key file' },
  { regex: /[/\\]paypal\.yml$/, desc: 'PayPal credentials' },

  // Password managers and keychains
  { regex: /\.kdbx?$/, desc: 'KeePass database file' },
  { regex: /[/\\]\.bitwarden[/\\]/, desc: 'Bitwarden data directory' },
  { regex: /[/\\]1Password[/\\]/, desc: '1Password data directory' },
  { regex: /[/\\]\.keepassx[/\\]/, desc: 'KeePassX data directory' },

  // Application-specific secrets
  { regex: /[/\\]\.flask$/, desc: 'Flask secret key file' },
  { regex: /[/\\]\.streamlit\/secrets\.toml$/, desc: 'Streamlit secrets' },
  { regex: /[/\\]\.streamlit\/config\.toml$/, desc: 'Streamlit config with secrets' },
  { regex: /[/\\]\.sentrycli$/, desc: 'Sentry CLI token' },

  // VPN configs
  { regex: /\.ovpn$/, desc: 'OpenVPN configuration' },
  { regex: /\.vpnc$/, desc: 'VPNC configuration' },
  { regex: /[/\\]\.openconnect$/, desc: 'OpenConnect VPN credentials' },

  // Shell history (can contain exposed passwords)
  { regex: /[/\\]\.bash_history$/, desc: 'bash command history' },
  { regex: /[/\\]\.zsh_history$/, desc: 'zsh command history' },
  { regex: /[/\\]\.history\//, desc: 'shell history directory' },
  { regex: /[/\\]\.mysql_history$/, desc: 'MySQL command history' },
  { regex: /[/\\]\.psql_history$/, desc: 'PostgreSQL command history' },
  { regex: /[/\\]\.rediscli_history$/, desc: 'Redis command history' },

  // IDE/editor configs with deployment info
  { regex: /[/\\]\.vscode[/\\]sftp\.json$/, desc: 'VSCode SFTP config with deployment info' },
  { regex: /[/\\]\.vscode[/\\]ftp-sync\.json$/, desc: 'VSCode FTP sync config' },
  { regex: /[/\\]\.vscode[/\\]launch\.json$/, desc: 'VSCode launch config' },
  { regex: /[/\\]\.idea\/workspace\.xml$/, desc: 'JetBrains workspace with deployment info' },
  { regex: /[/\\]\.idea\/databases\.xml$/, desc: 'JetBrains database config with credentials' },
  { regex: /[/\\]\.idea\/settings\.json$/, desc: 'JetBrains settings with tokens' },

  // Database GUI configs
  { regex: /[/\\]\. Sequel Pro[/\\]/, desc: 'Sequel Pro database config' },
  { regex: /[/\\]\.dbeaver[/\\]/, desc: 'DBeaver database config' },
  { regex: /[/\\]\. Robo 3T[/\\]/, desc: 'Robo 3T MongoDB config' },
  { regex: /[/\\]\.mapeditor[/\\]/, desc: 'Tiled map editor config' },

  // Backup and temporary files (often accidentally committed)
  { regex: /\.bak$/, desc: 'backup file' },
  { regex: /\.backup$/, desc: 'backup file' },
  { regex: /\.old$/, desc: 'old file' },
  { regex: /\.orig$/, desc: 'original file' },
  { regex: /core\.\d+$/, desc: 'core dump file' },
  { regex: /\.stackdump$/, desc: 'stack dump file' },

  // Misc sensitive
  { regex: /[/\\]\.aws\/credentials$/, desc: 'AWS credentials file' },
  { regex: /[/\\]\.aws\/config$/, desc: 'AWS config file' },
  { regex: /[/\\]\.netlify\/context$/, desc: 'Netlify deploy context' },
  { regex: /[/\\]\.vercel\/context$/, desc: 'Vercel deploy context' },
  { regex: /[/\\]wp-config\.php$/, desc: 'WordPress config with database credentials' },
  { regex: /[/\\]config\/database\.yml$/, desc: 'Rails database config' },
  { regex: /[/\\]config\/secrets\.yml$/, desc: 'Rails secrets config' },
  { regex: /[/\\]config\/credentials\.yml\.enc$/, desc: 'Rails encrypted credentials' },
];

// Safe dotfiles that should NOT be blocked
const SAFE_DOTFILES = new Set([
  // Git configs (safe)
  '.gitignore', '.gitattributes', '.gitmodules',
  // Editor configs (safe - no secrets)
  '.editorconfig', '.prettierrc', '.prettierrc.json', '.prettierrc.js',
  '.prettierrc.yaml', '.prettierrc.toml',
  '.eslintrc', '.eslintrc.json', '.eslintrc.js', '.eslintrc.yaml', '.eslintrc.toml',
  '.eslintignore', '.babelrc', '.babelrc.js', '.babelrc.json',
  '.clang-format', '.clang-tidy', '.clang',
  '.stylelintrc', '.stylelintrc.json', '.stylelintrc.js', '.stylelintrc.yaml',
  '.htmlhintrc', '.htmlhintrc.json',
  '.cspell.json', '.cspell.yaml',
  '.lintstagedrc', '.lintstagedrc.json', '.lintstagedrc.js',
  // IDE/Editor safe configs
  '.editorconfig', '.vimrc', '.nvimrc', '.nanorc', '.htaccess', '.htgroups',
  // Package management (safe - dependency info only)
  'package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
  'composer.lock', 'Gemfile.lock', 'go.sum', 'Cargo.lock',
  'poetry.lock', 'pip.lock', 'requirements.txt',
  // Config files (safe)
  'tsconfig.json', 'jsconfig.json', 'workspace.json', 'launch.json',
  '.browserslistrc', '.browserslist', '.nvmrc', '.node-version',
  '.ruby-version', '.python-version', '.tool-versions',
  '.env.example', '.env.example.local', '.env.template', '.env.dist',
  // Misc safe
  '.DS_Store', '.localized', '.CFUserTextEncoding',
  '.flaskignore', '.gitkeep', '.dockerignore',
  '.dockerfile', '.devcontainer',
  '.github', '.gitignore', '.gitattributes',
]);

// Regex to detect dotfiles (file starting with . in path)
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
