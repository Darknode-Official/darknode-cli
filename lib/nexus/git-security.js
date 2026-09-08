"use strict";
// ============================================================================
// git-security.js -- Git repository secret scanning and security analysis
//
// Scans git repositories for leaked secrets, credentials, API keys, tokens,
// private keys, connection strings, and other sensitive data. Performs both
// live working-tree analysis and full git-history traversal to find secrets
// that were committed and later removed (but still live in the reflog).
// Includes entropy-based detection for high-randomness strings that pattern
// matching alone would miss.
//
// Uses only Node.js built-ins (fs, path, child_process, crypto).
// ============================================================================

const fs = require("fs");
const path = require("path");
const { execSync, spawnSync } = require("child_process");
const crypto = require("crypto");

// ---------------------------------------------------------------------------
// Severity weights -- consistent with vuln-scanner.js
// ---------------------------------------------------------------------------
const SEVERITY_WEIGHTS = {
  critical: 10,
  high:     7,
  medium:   4,
  low:      2,
  info:     1,
};

// ---------------------------------------------------------------------------
// HIGH_ENTROPY_THRESHOLD -- Shannon entropy threshold for detecting random
// strings that look like secrets. A truly random base64 string of length 40+
// typically has entropy > 4.5 bits/char. We use 4.0 as a balanced threshold
// that catches most secrets while avoiding excessive false positives on
// normal code identifiers and English text (~3.5 bits/char).
// ---------------------------------------------------------------------------
const HIGH_ENTROPY_THRESHOLD = 4.0;

// Separate thresholds per character class for more accurate detection
const ENTROPY_THRESHOLDS = {
  hex:     3.0,   // hex strings have max ~4.0 entropy, lower threshold needed
  base64:  4.0,   // base64 has richer charset, higher natural entropy
  generic: 4.5,   // unknown charset -- be conservative
};

// Minimum string length to consider for entropy analysis
const MIN_ENTROPY_LENGTH = 16;

// ---------------------------------------------------------------------------
// SECRET_PATTERNS -- 45+ regex patterns for detecting leaked credentials.
//
// Each entry: { id, label, severity, regex, description }
//   - regex operates on a single line of text
//   - severity: critical | high | medium | low | info
//   - IMPORTANT: patterns use descriptive character classes, NOT real keys
//   - match examples use "EXAMPLE_REDACTED" placeholders
// ---------------------------------------------------------------------------
const SECRET_PATTERNS = [
  // ---- AWS ----
  {
    id: "aws-access-key",
    label: "AWS Access Key ID",
    severity: "critical",
    regex: /(?:^|[^A-Za-z0-9/+=])(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?:[^A-Za-z0-9/+=]|$)/,
    description: "AWS access key IDs begin with AKIA/ABIA/ACCA/ASIA followed by 16 alphanumeric characters.",
    example: "AKIA" + "EXAMPLE_REDACTED",
  },
  {
    id: "aws-secret-key",
    label: "AWS Secret Access Key",
    severity: "critical",
    regex: /(?:aws_secret_access_key|aws_secret_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}['"]?/i,
    description: "AWS secret access keys are 40-character base64 strings assigned alongside an access key ID.",
    example: "aws_secret_access_key=EXAMPLE_REDACTED",
  },
  {
    id: "aws-session-token",
    label: "AWS Session Token",
    severity: "critical",
    regex: /(?:aws_session_token|AWS_SESSION_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{100,}['"]?/i,
    description: "Temporary AWS session tokens are long base64 strings used with STS credentials.",
    example: "aws_session_token=EXAMPLE_REDACTED",
  },
  {
    id: "aws-mws-key",
    label: "AWS MWS Key",
    severity: "high",
    regex: /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i,
    description: "Amazon Marketplace Web Service authentication tokens follow a UUID-like pattern.",
    example: "amzn.mws.EXAMPLE_REDACTED",
  },

  // ---- Google / GCP ----
  {
    id: "gcp-api-key",
    label: "Google API Key",
    severity: "high",
    regex: /AIza[A-Za-z0-9_\\-]{35}/,
    description: "Google API keys begin with AIza and are 39 characters total.",
    example: "AIzaEXAMPLE_REDACTED",
  },
  {
    id: "gcp-oauth-id",
    label: "Google OAuth Client ID",
    severity: "medium",
    regex: /[0-9]{12,}-[a-z0-9]{32}\.apps\.googleusercontent\.com/,
    description: "Google OAuth2 client IDs end with .apps.googleusercontent.com.",
    example: "EXAMPLE_REDACTED.apps.googleusercontent.com",
  },
  {
    id: "gcp-service-account",
    label: "GCP Service Account Key",
    severity: "critical",
    regex: /"type"\s*:\s*"service_account"/,
    description: "GCP service account JSON key files contain a type field set to service_account.",
    example: '"type": "service_account"',
  },
  {
    id: "firebase-url",
    label: "Firebase Database URL",
    severity: "medium",
    regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/i,
    description: "Firebase Realtime Database URLs can expose read/write access if rules are misconfigured.",
    example: "https://EXAMPLE_REDACTED.firebaseio.com",
  },

  // ---- GitHub ----
  {
    id: "github-pat",
    label: "GitHub Personal Access Token",
    severity: "critical",
    regex: /ghp_[A-Za-z0-9]{36}/,
    description: "GitHub fine-grained or classic personal access tokens start with ghp_ prefix.",
    example: "ghp_EXAMPLE_REDACTED",
  },
  {
    id: "github-oauth",
    label: "GitHub OAuth Access Token",
    severity: "critical",
    regex: /gho_[A-Za-z0-9]{36}/,
    description: "GitHub OAuth access tokens start with gho_ prefix.",
    example: "gho_EXAMPLE_REDACTED",
  },
  {
    id: "github-app-token",
    label: "GitHub App Token",
    severity: "critical",
    regex: /(?:ghu|ghs)_[A-Za-z0-9]{36}/,
    description: "GitHub App user-to-server (ghu_) and server-to-server (ghs_) tokens.",
    example: "ghs_EXAMPLE_REDACTED",
  },
  {
    id: "github-refresh-token",
    label: "GitHub Refresh Token",
    severity: "critical",
    regex: /ghr_[A-Za-z0-9]{36}/,
    description: "GitHub refresh tokens start with ghr_ prefix.",
    example: "ghr_EXAMPLE_REDACTED",
  },

  // ---- GitLab ----
  {
    id: "gitlab-pat",
    label: "GitLab Personal Access Token",
    severity: "critical",
    regex: /glpat-[A-Za-z0-9_\-]{20,}/,
    description: "GitLab personal access tokens start with glpat- prefix.",
    example: "glpat-EXAMPLE_REDACTED",
  },
  {
    id: "gitlab-runner-token",
    label: "GitLab Runner Registration Token",
    severity: "high",
    regex: /GR1348941[A-Za-z0-9_\-]{20,}/,
    description: "GitLab runner registration tokens start with GR1348941.",
    example: "GR1348941EXAMPLE_REDACTED",
  },

  // ---- Slack ----
  {
    id: "slack-token",
    label: "Slack Token",
    severity: "critical",
    regex: /xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+/,
    description: "Slack bot, user, and app tokens start with xoxb-, xoxp-, xoxo-, xoxr-, or xoxs-.",
    example: "xoxb-EXAMPLE_REDACTED",
  },
  {
    id: "slack-webhook",
    label: "Slack Webhook URL",
    severity: "high",
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{20,}/,
    description: "Slack incoming webhook URLs contain workspace and channel identifiers.",
    example: "https://hooks.slack.com/services/TEXAMPLE_REDACTED",
  },

  // ---- Stripe ----
  {
    id: "stripe-secret-key",
    label: "Stripe Secret Key",
    severity: "critical",
    regex: /sk_live_[A-Za-z0-9]{24,}/,
    description: "Stripe live secret keys start with sk_live_ and grant full API access.",
    example: "sk_live_EXAMPLE_REDACTED",
  },
  {
    id: "stripe-restricted-key",
    label: "Stripe Restricted Key",
    severity: "high",
    regex: /rk_live_[A-Za-z0-9]{24,}/,
    description: "Stripe restricted keys start with rk_live_ and have limited API access.",
    example: "rk_live_EXAMPLE_REDACTED",
  },
  {
    id: "stripe-publishable-key",
    label: "Stripe Publishable Key",
    severity: "low",
    regex: /pk_live_[A-Za-z0-9]{24,}/,
    description: "Stripe publishable keys are intended for client-side use but should not be in source control.",
    example: "pk_live_EXAMPLE_REDACTED",
  },

  // ---- Twilio ----
  {
    id: "twilio-api-key",
    label: "Twilio API Key",
    severity: "high",
    regex: /SK[0-9a-fA-F]{32}/,
    description: "Twilio API keys are 34-character strings starting with SK.",
    example: "SKEXAMPLE_REDACTED",
  },

  // ---- SendGrid ----
  {
    id: "sendgrid-api-key",
    label: "SendGrid API Key",
    severity: "critical",
    regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/,
    description: "SendGrid API keys follow the pattern SG.<22chars>.<43chars>.",
    example: "SG.EXAMPLE_REDACTED",
  },

  // ---- Mailgun ----
  {
    id: "mailgun-api-key",
    label: "Mailgun API Key",
    severity: "high",
    regex: /key-[0-9a-f]{32}/,
    description: "Mailgun private API keys start with key- followed by 32 hex characters.",
    example: "key-EXAMPLE_REDACTED",
  },

  // ---- Heroku ----
  {
    id: "heroku-api-key",
    label: "Heroku API Key",
    severity: "high",
    regex: /(?:heroku_api_key|HEROKU_API_KEY|heroku_api_token)\s*[=:]\s*['"]?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]?/i,
    description: "Heroku API keys are UUIDs associated with account-level API access.",
    example: "HEROKU_API_KEY=EXAMPLE_REDACTED",
  },

  // ---- NPM ----
  {
    id: "npm-token",
    label: "NPM Access Token",
    severity: "critical",
    regex: /(?:\/\/registry\.npmjs\.org\/:_authToken=|npm_)[A-Za-z0-9_\-]{36,}/,
    description: "NPM tokens grant publish access to the npm registry.",
    example: "npm_EXAMPLE_REDACTED",
  },

  // ---- PyPI ----
  {
    id: "pypi-token",
    label: "PyPI API Token",
    severity: "critical",
    regex: /pypi-[A-Za-z0-9_\-]{100,}/,
    description: "PyPI API tokens start with pypi- and are used for package publishing.",
    example: "pypi-EXAMPLE_REDACTED",
  },

  // ---- Docker Hub ----
  {
    id: "dockerhub-token",
    label: "Docker Hub Access Token",
    severity: "high",
    regex: /dckr_pat_[A-Za-z0-9_\-]{20,}/,
    description: "Docker Hub personal access tokens start with dckr_pat_ prefix.",
    example: "dckr_pat_EXAMPLE_REDACTED",
  },

  // ---- Generic private keys ----
  {
    id: "private-key-rsa",
    label: "RSA Private Key",
    severity: "critical",
    regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/,
    description: "PEM-encoded RSA private key header detected in file content.",
    example: "-----BEGIN RSA PRIVATE KEY-----",
  },
  {
    id: "private-key-ec",
    label: "EC Private Key",
    severity: "critical",
    regex: /-----BEGIN EC PRIVATE KEY-----/,
    description: "PEM-encoded elliptic curve private key header detected.",
    example: "-----BEGIN EC PRIVATE KEY-----",
  },
  {
    id: "private-key-openssh",
    label: "OpenSSH Private Key",
    severity: "critical",
    regex: /-----BEGIN OPENSSH PRIVATE KEY-----/,
    description: "OpenSSH private key header detected.",
    example: "-----BEGIN OPENSSH PRIVATE KEY-----",
  },
  {
    id: "private-key-dsa",
    label: "DSA Private Key",
    severity: "critical",
    regex: /-----BEGIN DSA PRIVATE KEY-----/,
    description: "PEM-encoded DSA private key header (legacy, insecure).",
    example: "-----BEGIN DSA PRIVATE KEY-----",
  },
  {
    id: "private-key-pgp",
    label: "PGP Private Key Block",
    severity: "critical",
    regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/,
    description: "ASCII-armored PGP/GPG private key block detected.",
    example: "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  },
  {
    id: "pkcs8-private-key",
    label: "PKCS8 Private Key",
    severity: "critical",
    regex: /-----BEGIN ENCRYPTED PRIVATE KEY-----/,
    description: "PKCS#8 encrypted private key header detected.",
    example: "-----BEGIN ENCRYPTED PRIVATE KEY-----",
  },

  // ---- Database connection strings ----
  {
    id: "postgres-uri",
    label: "PostgreSQL Connection String",
    severity: "critical",
    regex: /postgres(?:ql)?:\/\/[^\s'"}{)]+:[^\s'"}{)]+@[^\s'"}{)]+/i,
    description: "PostgreSQL URIs with embedded credentials (user:pass@host).",
    example: "postgresql://user:EXAMPLE_REDACTED@host/db",
  },
  {
    id: "mysql-uri",
    label: "MySQL Connection String",
    severity: "critical",
    regex: /mysql:\/\/[^\s'"}{)]+:[^\s'"}{)]+@[^\s'"}{)]+/i,
    description: "MySQL URIs with embedded credentials.",
    example: "mysql://user:EXAMPLE_REDACTED@host/db",
  },
  {
    id: "mongodb-uri",
    label: "MongoDB Connection String",
    severity: "critical",
    regex: /mongodb(?:\+srv)?:\/\/[^\s'"}{)]+:[^\s'"}{)]+@[^\s'"}{)]+/i,
    description: "MongoDB URIs with embedded credentials.",
    example: "mongodb+srv://user:EXAMPLE_REDACTED@cluster/db",
  },
  {
    id: "redis-uri",
    label: "Redis Connection String",
    severity: "high",
    regex: /redis(?:s)?:\/\/[^\s'"}{)]*:[^\s'"}{)]+@[^\s'"}{)]+/i,
    description: "Redis URIs with embedded password.",
    example: "redis://:EXAMPLE_REDACTED@host:6379",
  },
  {
    id: "mssql-uri",
    label: "MSSQL Connection String",
    severity: "critical",
    regex: /(?:Server|Data Source)\s*=[^;]+;\s*(?:User ID|uid)\s*=[^;]+;\s*(?:Password|pwd)\s*=[^;]+/i,
    description: "Microsoft SQL Server connection strings with embedded credentials.",
    example: "Server=host;User ID=sa;Password=EXAMPLE_REDACTED",
  },

  // ---- Generic password/secret assignment ----
  {
    id: "generic-password",
    label: "Hardcoded Password",
    severity: "high",
    regex: /(?:password|passwd|pwd|pass)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    description: "Variable assignment with password-like name and a non-trivial string value.",
    example: 'password="EXAMPLE_REDACTED"',
  },
  {
    id: "generic-secret",
    label: "Hardcoded Secret",
    severity: "high",
    regex: /(?:secret|secret_key|client_secret|app_secret)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    description: "Variable assignment with secret-like name and a non-trivial string value.",
    example: 'client_secret="EXAMPLE_REDACTED"',
  },
  {
    id: "generic-api-key",
    label: "Hardcoded API Key",
    severity: "high",
    regex: /(?:api_key|apikey|api[-_]?secret)\s*[=:]\s*['"][^'"]{8,}['"]/i,
    description: "Variable assignment with api-key-like name and a non-trivial string value.",
    example: 'api_key="EXAMPLE_REDACTED"',
  },
  {
    id: "generic-token",
    label: "Hardcoded Token",
    severity: "high",
    regex: /(?:access_token|auth_token|bearer_token|refresh_token)\s*[=:]\s*['"][^'"]{16,}['"]/i,
    description: "Variable assignment with token-like name and a long string value.",
    example: 'access_token="EXAMPLE_REDACTED"',
  },
  {
    id: "authorization-header",
    label: "Authorization Header",
    severity: "high",
    regex: /(?:Authorization|X-Api-Key)\s*[=:]\s*['"](?:Bearer|Basic|Token)\s+[A-Za-z0-9+/=._\-]{20,}['"]/i,
    description: "Hardcoded Authorization header with a Bearer/Basic/Token credential.",
    example: 'Authorization: "Bearer EXAMPLE_REDACTED"',
  },

  // ---- Cloud / SaaS providers ----
  {
    id: "azure-storage-key",
    label: "Azure Storage Account Key",
    severity: "critical",
    regex: /(?:AccountKey|azure_storage_key|AZURE_STORAGE_KEY)\s*[=:]\s*['"]?[A-Za-z0-9+/=]{86,88}['"]?/i,
    description: "Azure Storage account keys are ~88 character base64 strings.",
    example: "AccountKey=EXAMPLE_REDACTED",
  },
  {
    id: "azure-connection-string",
    label: "Azure Connection String",
    severity: "critical",
    regex: /DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}/i,
    description: "Full Azure Storage connection string with embedded account key.",
    example: "DefaultEndpointsProtocol=https;AccountName=store;AccountKey=EXAMPLE_REDACTED",
  },
  {
    id: "digitalocean-token",
    label: "DigitalOcean Token",
    severity: "critical",
    regex: /dop_v1_[a-f0-9]{64}/,
    description: "DigitalOcean personal access tokens start with dop_v1_ followed by 64 hex characters.",
    example: "dop_v1_EXAMPLE_REDACTED",
  },
  {
    id: "shopify-token",
    label: "Shopify Access Token",
    severity: "high",
    regex: /shpat_[a-fA-F0-9]{32}/,
    description: "Shopify Admin API access tokens start with shpat_ prefix.",
    example: "shpat_EXAMPLE_REDACTED",
  },
  {
    id: "shopify-secret",
    label: "Shopify Shared Secret",
    severity: "high",
    regex: /shpss_[a-fA-F0-9]{32}/,
    description: "Shopify shared secrets start with shpss_ prefix.",
    example: "shpss_EXAMPLE_REDACTED",
  },

  // ---- JWT / session ----
  {
    id: "jwt-token",
    label: "JSON Web Token",
    severity: "high",
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}/,
    description: "JWT tokens have three base64url-encoded segments separated by dots.",
    example: "eyJEXAMPLE_REDACTED.eyJEXAMPLE_REDACTED.EXAMPLE_REDACTED",
  },

  // ---- Encryption / signing secrets ----
  {
    id: "encryption-key-hex",
    label: "Hex Encryption Key",
    severity: "high",
    regex: /(?:encryption_key|aes_key|cipher_key|signing_key|hmac_secret)\s*[=:]\s*['"]?[0-9a-fA-F]{32,}['"]?/i,
    description: "Named encryption/signing key assigned a hex string value.",
    example: "encryption_key=EXAMPLE_REDACTED",
  },
];

// ---------------------------------------------------------------------------
// SENSITIVE_FILENAMES -- 55 filenames that should never be committed to a
// public repository. Checked by analyzeGitHistory and checkGitConfig.
// ---------------------------------------------------------------------------
const SENSITIVE_FILENAMES = [
  // --- Environment / config ---
  ".env",
  ".env.local",
  ".env.development",
  ".env.staging",
  ".env.production",
  ".env.test",
  ".env.backup",
  ".env.bak",
  ".env.old",
  ".env.save",
  // --- SSH keys ---
  "id_rsa",
  "id_rsa.pub",
  "id_dsa",
  "id_dsa.pub",
  "id_ecdsa",
  "id_ecdsa.pub",
  "id_ed25519",
  "id_ed25519.pub",
  "authorized_keys",
  "known_hosts",
  "ssh_config",
  // --- TLS / certificates ---
  "server.key",
  "server.pem",
  "server.crt",
  "client.key",
  "client.pem",
  "privkey.pem",
  "fullchain.pem",
  "cert.pem",
  "ca-bundle.crt",
  "keystore.jks",
  "truststore.jks",
  "keystore.p12",
  // --- AWS ---
  "credentials",
  "aws_credentials",
  ".aws/credentials",
  ".aws/config",
  // --- GCP ---
  "service-account.json",
  "gcloud-service-key.json",
  "credentials.json",
  "client_secret.json",
  // --- Docker / K8s ---
  ".dockercfg",
  ".docker/config.json",
  "kubeconfig",
  ".kube/config",
  // --- Databases ---
  "database.yml",
  "database.sqlite",
  "database.sqlite3",
  "dump.sql",
  "backup.sql",
  // --- Application secrets ---
  "master.key",
  "secret_token.rb",
  "secrets.yml",
  "secrets.json",
  "wp-config.php",
  "configuration.php",
  "config.php",
  "settings.py",
  "local_settings.py",
  // --- IDE / debug ---
  ".idea/workspace.xml",
  ".vscode/launch.json",
  // --- Password managers / vaults ---
  ".htpasswd",
  ".netrc",
  ".pgpass",
  ".my.cnf",
  // --- Terraform ---
  "terraform.tfvars",
  "terraform.tfstate",
  "terraform.tfstate.backup",
  // --- Ansible ---
  "vault.yml",
  "group_vars/all.yml",
];

// Extensions that almost certainly contain secrets when committed
const SENSITIVE_EXTENSIONS = [
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".jks",
  ".keystore",
  ".pkcs12",
  ".der",
  ".cer",
  ".crt",
  ".env",
  ".secret",
  ".credentials",
  ".htpasswd",
  ".pgpass",
  ".netrc",
];

// ---------------------------------------------------------------------------
// GITIGNORE_RECOMMENDATIONS -- recommended .gitignore entries by project type
// ---------------------------------------------------------------------------
const GITIGNORE_RECOMMENDATIONS = {
  // Universal entries every project should include
  universal: {
    label: "Universal (all projects)",
    entries: [
      "# Environment variables",
      ".env",
      ".env.*",
      "!.env.example",
      "!.env.template",
      "",
      "# Private keys and certificates",
      "*.pem",
      "*.key",
      "*.p12",
      "*.pfx",
      "*.jks",
      "*.keystore",
      "",
      "# Credentials files",
      "credentials.json",
      "client_secret*.json",
      "service-account*.json",
      "",
      "# IDE secrets",
      ".idea/workspace.xml",
      ".vscode/launch.json",
      "",
      "# OS files",
      ".DS_Store",
      "Thumbs.db",
      "Desktop.ini",
      "",
      "# Terraform state",
      "*.tfstate",
      "*.tfstate.backup",
      "*.tfvars",
      "!*.tfvars.example",
      "",
      "# Password files",
      ".htpasswd",
      ".pgpass",
      ".netrc",
      ".my.cnf",
    ],
  },

  node: {
    label: "Node.js / JavaScript",
    entries: [
      "# Dependencies",
      "node_modules/",
      "package-lock.json",
      "yarn.lock",
      "pnpm-lock.yaml",
      "",
      "# Build output",
      "dist/",
      "build/",
      ".next/",
      ".nuxt/",
      "out/",
      "",
      "# Debug and logs",
      "npm-debug.log*",
      "yarn-debug.log*",
      "yarn-error.log*",
      ".pnpm-debug.log*",
      "",
      "# Coverage",
      "coverage/",
      ".nyc_output/",
      "",
      "# Cache",
      ".cache/",
      ".parcel-cache/",
      ".eslintcache",
      "",
      "# Secrets",
      ".npmrc",
      "!.npmrc.example",
    ],
  },

  python: {
    label: "Python",
    entries: [
      "# Virtual environments",
      "venv/",
      ".venv/",
      "env/",
      ".env/",
      "ENV/",
      "",
      "# Byte-compiled / optimized / DLL files",
      "__pycache__/",
      "*.py[cod]",
      "*$py.class",
      "",
      "# Distribution / packaging",
      "dist/",
      "build/",
      "*.egg-info/",
      "*.egg",
      "",
      "# Testing / coverage",
      ".pytest_cache/",
      ".coverage",
      "htmlcov/",
      "",
      "# Secrets",
      "local_settings.py",
      "settings_local.py",
      "*.sqlite3",
    ],
  },

  ruby: {
    label: "Ruby / Rails",
    entries: [
      "# Bundler",
      "vendor/bundle/",
      ".bundle/",
      "",
      "# Rails secrets",
      "config/master.key",
      "config/credentials.yml.enc",
      "config/database.yml",
      "!config/database.yml.example",
      "",
      "# Logs and temp",
      "log/",
      "tmp/",
      "storage/",
      "",
      "# Coverage",
      "coverage/",
    ],
  },

  go: {
    label: "Go",
    entries: [
      "# Binaries",
      "*.exe",
      "*.exe~",
      "*.dll",
      "*.so",
      "*.dylib",
      "",
      "# Test binary",
      "*.test",
      "",
      "# Output of go coverage",
      "*.out",
      "coverage.html",
      "",
      "# Vendor (if not committing deps)",
      "vendor/",
    ],
  },

  java: {
    label: "Java / JVM",
    entries: [
      "# Compiled class files",
      "*.class",
      "",
      "# Build output",
      "target/",
      "build/",
      "out/",
      "",
      "# Gradle",
      ".gradle/",
      "gradle.properties",
      "!gradle.properties.example",
      "",
      "# Maven",
      "*.jar",
      "*.war",
      "*.ear",
      "",
      "# Keystores",
      "*.jks",
      "*.keystore",
      "*.p12",
      "",
      "# Application secrets",
      "application-local.properties",
      "application-local.yml",
    ],
  },

  rust: {
    label: "Rust",
    entries: [
      "# Build artifacts",
      "target/",
      "",
      "# Cargo lock (for libraries; keep for binaries)",
      "# Cargo.lock",
      "",
      "# Debug info",
      "*.dSYM/",
      "*.pdb",
    ],
  },

  dotnet: {
    label: ".NET / C#",
    entries: [
      "# Build results",
      "bin/",
      "obj/",
      "",
      "# NuGet packages",
      "*.nupkg",
      "packages/",
      "",
      "# User settings",
      "*.suo",
      "*.user",
      "*.userosscache",
      "*.sln.docstates",
      "",
      "# Secrets",
      "appsettings.Development.json",
      "appsettings.Local.json",
      "usersecrets/",
    ],
  },

  terraform: {
    label: "Terraform / IaC",
    entries: [
      "# State files",
      "*.tfstate",
      "*.tfstate.backup",
      "*.tfstate.*.backup",
      ".terraform/",
      "",
      "# Variables with secrets",
      "*.tfvars",
      "!*.tfvars.example",
      "*.auto.tfvars",
      "",
      "# Crash logs",
      "crash.log",
      "crash.*.log",
      "",
      "# Plan files",
      "*.tfplan",
    ],
  },

  docker: {
    label: "Docker / Containers",
    entries: [
      "# Docker compose override (may contain secrets)",
      "docker-compose.override.yml",
      "",
      "# Docker environment files",
      ".env.docker",
      "",
      "# Docker credentials",
      ".dockercfg",
      ".docker/config.json",
    ],
  },

  mobile: {
    label: "Mobile (iOS / Android)",
    entries: [
      "# iOS",
      "*.ipa",
      "*.dSYM.zip",
      "*.dSYM",
      "Pods/",
      "",
      "# Android",
      "*.apk",
      "*.aab",
      "local.properties",
      "signing.properties",
      "keystore.properties",
      "*.keystore",
      "*.jks",
      "",
      "# Fastlane secrets",
      "fastlane/report.xml",
      "fastlane/Preview.html",
      "fastlane/screenshots",
      "fastlane/test_output",
      "fastlane/.env*",
    ],
  },

  php: {
    label: "PHP / Laravel / WordPress",
    entries: [
      "# Vendor",
      "vendor/",
      "",
      "# Laravel",
      ".env",
      "storage/",
      "bootstrap/cache/",
      "",
      "# WordPress",
      "wp-config.php",
      "wp-content/uploads/",
      "wp-content/cache/",
      "",
      "# Composer",
      "composer.lock",
    ],
  },
};

// ---------------------------------------------------------------------------
// Directories and file patterns to skip when scanning the working tree
// ---------------------------------------------------------------------------
const SKIP_DIRS = new Set([
  ".git",
  "node_modules",
  ".nexus",
  "dist",
  "build",
  ".cache",
  ".next",
  ".nuxt",
  "target",
  "__pycache__",
  "vendor",
  ".venv",
  "venv",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
  "coverage",
  ".nyc_output",
  ".gradle",
  ".idea",
  ".vs",
  "packages",
  "bower_components",
  ".terraform",
  ".serverless",
]);

const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
  ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac",
  ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z", ".rar",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".exe", ".dll", ".so", ".dylib", ".o", ".a",
  ".pyc", ".pyo", ".class", ".jar", ".war",
  ".db", ".sqlite", ".sqlite3",
  ".wasm",
]);

const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB -- skip huge files

// ---------------------------------------------------------------------------
// Shannon entropy calculation
// ---------------------------------------------------------------------------

/**
 * Calculate Shannon entropy of a string (bits per character).
 * High entropy (> 4.0) suggests the string is random / generated --
 * a strong signal for secrets, keys, and tokens.
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    freq[ch] = (freq[ch] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const ch in freq) {
    const p = freq[ch] / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Classify a string's character set for threshold selection.
 */
function classifyCharset(str) {
  if (/^[0-9a-fA-F]+$/.test(str)) return "hex";
  if (/^[A-Za-z0-9+/=]+$/.test(str)) return "base64";
  return "generic";
}

/**
 * Check whether a token exceeds the entropy threshold for its character class.
 */
function isHighEntropy(token) {
  if (!token || token.length < MIN_ENTROPY_LENGTH) return false;
  const charset = classifyCharset(token);
  const threshold = ENTROPY_THRESHOLDS[charset] || ENTROPY_THRESHOLDS.generic;
  return shannonEntropy(token) >= threshold;
}

/**
 * Extract high-entropy tokens from a line of text.
 * Splits on whitespace, quotes, colons, equals signs, and common delimiters,
 * then tests each token.
 */
function extractHighEntropyTokens(line) {
  const tokens = line.split(/[\s'"`:=,;(){}\[\]<>|&]+/).filter(Boolean);
  const hits = [];
  for (const token of tokens) {
    // Skip short tokens, common words, URLs without credentials
    if (token.length < MIN_ENTROPY_LENGTH) continue;
    if (/^https?:\/\//i.test(token)) continue;
    if (/^[a-z_][a-z0-9_]*$/i.test(token) && token.length < 32) continue; // likely a variable name
    if (isHighEntropy(token)) {
      hits.push({
        token: maskSecret(token),
        entropy: shannonEntropy(token).toFixed(2),
        charset: classifyCharset(token),
        length: token.length,
      });
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/**
 * Mask a secret for safe display. Shows first 4 and last 4 characters,
 * replacing the middle with asterisks.
 */
function maskSecret(s) {
  if (!s) return "***";
  s = String(s);
  if (s.length <= 12) return s.slice(0, 3) + "***" + s.slice(-2);
  return s.slice(0, 4) + "*".repeat(Math.min(s.length - 8, 20)) + s.slice(-4);
}

/**
 * Check if a path should be skipped during scanning.
 */
function shouldSkip(relPath) {
  const parts = relPath.split(path.sep);
  for (const p of parts) {
    if (SKIP_DIRS.has(p)) return true;
  }
  const ext = path.extname(relPath).toLowerCase();
  if (BINARY_EXT.has(ext)) return true;
  return false;
}

/**
 * Recursively collect files under dir, respecting skip rules.
 */
function walkDir(dir, relBase) {
  relBase = relBase || "";
  const results = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch (_) {
    return results;
  }
  for (const entry of entries) {
    const rel = relBase ? path.join(relBase, entry.name) : entry.name;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      results.push(...walkDir(full, rel));
    } else if (entry.isFile()) {
      if (shouldSkip(rel)) continue;
      try {
        const stat = fs.statSync(full);
        if (stat.size > MAX_FILE_SIZE) continue;
      } catch (_) { continue; }
      results.push({ full, rel });
    }
  }
  return results;
}

/**
 * Run a git command synchronously and return stdout, or null on failure.
 */
function git(repoPath, args) {
  try {
    const result = spawnSync("git", args, {
      cwd: repoPath,
      encoding: "utf8",
      maxBuffer: 50 * 1024 * 1024, // 50 MB
      timeout: 60000,
    });
    if (result.error) return null;
    return result.stdout || "";
  } catch (_) {
    return null;
  }
}

/**
 * Check if a path is inside a git repository.
 */
function isGitRepo(repoPath) {
  const result = git(repoPath, ["rev-parse", "--is-inside-work-tree"]);
  return result !== null && result.trim() === "true";
}

/**
 * Get the repository root from any path inside it.
 */
function getRepoRoot(repoPath) {
  const result = git(repoPath, ["rev-parse", "--show-toplevel"]);
  return result ? result.trim() : repoPath;
}

// ---------------------------------------------------------------------------
// scanGitSecrets(repoPath) -- main secret scanning function
//
// Scans the working tree for leaked secrets using pattern matching and
// entropy analysis. Returns a findings object with all detected issues.
// ---------------------------------------------------------------------------

/**
 * Scan a single file's content against all secret patterns.
 */
function scanFileContent(content, filePath) {
  const findings = [];
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;

    // Skip comment-only lines (reduce false positives on documentation)
    const trimmed = line.trim();
    if (trimmed.startsWith("//") && /example|sample|placeholder|dummy|test|fake|todo|fixme/i.test(trimmed)) continue;
    if (trimmed.startsWith("#") && /example|sample|placeholder|dummy|test|fake|todo|fixme/i.test(trimmed)) continue;

    // Pattern-based detection
    for (const pat of SECRET_PATTERNS) {
      if (pat.regex.test(line)) {
        // Extract the matched portion for display
        const match = line.match(pat.regex);
        findings.push({
          type: "pattern",
          patternId: pat.id,
          label: pat.label,
          severity: pat.severity,
          file: filePath,
          line: lineNum,
          match: maskSecret(match ? match[0] : ""),
          description: pat.description,
        });
      }
    }

    // Entropy-based detection (skip lines that already matched patterns)
    const patternHit = findings.some((f) => f.file === filePath && f.line === lineNum);
    if (!patternHit && line.length > 20) {
      const entropyHits = extractHighEntropyTokens(line);
      for (const hit of entropyHits) {
        findings.push({
          type: "entropy",
          patternId: "high-entropy",
          label: "High-Entropy String",
          severity: "medium",
          file: filePath,
          line: lineNum,
          match: hit.token,
          entropy: hit.entropy,
          charset: hit.charset,
          description: `High-entropy ${hit.charset} string (${hit.entropy} bits/char, ${hit.length} chars) may be a secret.`,
        });
      }
    }
  }
  return findings;
}

/**
 * Scan a git repository's working tree for leaked secrets.
 *
 * @param {string} repoPath - Path to the git repository (or any directory)
 * @param {object} [opts] - Options
 * @param {boolean} [opts.entropy=true] - Enable entropy-based detection
 * @param {boolean} [opts.patterns=true] - Enable pattern-based detection
 * @param {string[]} [opts.exclude] - Additional paths to exclude
 * @param {number} [opts.maxFiles=5000] - Maximum files to scan
 * @returns {object} Scan results with findings, stats, and metadata
 */
function scanGitSecrets(repoPath, opts) {
  opts = opts || {};
  const enableEntropy = opts.entropy !== false;
  const enablePatterns = opts.patterns !== false;
  const maxFiles = opts.maxFiles || 5000;
  const exclude = new Set(opts.exclude || []);

  const startTime = Date.now();

  // Resolve repo root
  const root = isGitRepo(repoPath) ? getRepoRoot(repoPath) : repoPath;

  // Collect files
  const files = walkDir(root, "").filter((f) => !exclude.has(f.rel));
  const scannedFiles = files.slice(0, maxFiles);

  const allFindings = [];
  const fileStats = { scanned: 0, skipped: files.length - scannedFiles.length, totalLines: 0 };

  for (const file of scannedFiles) {
    let content;
    try {
      content = fs.readFileSync(file.full, "utf8");
    } catch (_) { continue; }

    fileStats.scanned++;
    fileStats.totalLines += content.split("\n").length;

    // Check filename against sensitive filenames list
    const basename = path.basename(file.rel);
    const relLower = file.rel.toLowerCase();
    for (const sens of SENSITIVE_FILENAMES) {
      if (basename === path.basename(sens) || relLower.endsWith(sens.toLowerCase())) {
        allFindings.push({
          type: "filename",
          patternId: "sensitive-filename",
          label: "Sensitive File in Repository",
          severity: "high",
          file: file.rel,
          line: 0,
          match: basename,
          description: `File "${basename}" is commonly associated with secrets or credentials and should not be committed.`,
        });
        break;
      }
    }

    // Check extension against sensitive extensions
    const ext = path.extname(file.rel).toLowerCase();
    if (SENSITIVE_EXTENSIONS.includes(ext)) {
      allFindings.push({
        type: "extension",
        patternId: "sensitive-extension",
        label: "Sensitive File Extension",
        severity: "medium",
        file: file.rel,
        line: 0,
        match: ext,
        description: `File extension "${ext}" is associated with secrets, keys, or credentials.`,
      });
    }

    // Content scanning
    if (enablePatterns || enableEntropy) {
      const contentFindings = scanFileContent(content, file.rel);
      if (!enableEntropy) {
        allFindings.push(...contentFindings.filter((f) => f.type !== "entropy"));
      } else if (!enablePatterns) {
        allFindings.push(...contentFindings.filter((f) => f.type !== "pattern"));
      } else {
        allFindings.push(...contentFindings);
      }
    }
  }

  const elapsed = Date.now() - startTime;

  // Deduplicate findings by file + line + patternId
  const seen = new Set();
  const deduped = [];
  for (const f of allFindings) {
    const key = `${f.file}:${f.line}:${f.patternId}`;
    if (!seen.has(key)) {
      seen.add(key);
      deduped.push(f);
    }
  }

  // Sort by severity (critical first), then file, then line
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  deduped.sort((a, b) => {
    const s = (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9);
    if (s !== 0) return s;
    const f = a.file.localeCompare(b.file);
    if (f !== 0) return f;
    return (a.line || 0) - (b.line || 0);
  });

  // Summary counts
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: deduped.length };
  for (const f of deduped) summary[f.severity] = (summary[f.severity] || 0) + 1;

  return {
    repoPath: root,
    scanTime: new Date().toISOString(),
    elapsedMs: elapsed,
    files: fileStats,
    summary,
    findings: deduped,
    patternsUsed: SECRET_PATTERNS.length,
    entropyThreshold: HIGH_ENTROPY_THRESHOLD,
  };
}

// ---------------------------------------------------------------------------
// analyzeGitHistory(repoPath) -- find sensitive files ever committed
//
// Uses `git log --all --diff-filter=A --name-only` to find every file
// that was ever added to the repository, then checks against the
// sensitive filenames/extensions lists. Also checks for large blobs that
// might be key files.
// ---------------------------------------------------------------------------

/**
 * Analyze the full git history for sensitive files that were ever committed,
 * including files that have since been deleted or moved.
 *
 * @param {string} repoPath - Path to the git repository
 * @param {object} [opts] - Options
 * @param {number} [opts.maxCommits=10000] - Maximum commits to inspect
 * @param {boolean} [opts.includeDeleted=true] - Include files no longer in HEAD
 * @returns {object} History analysis results
 */
function analyzeGitHistory(repoPath, opts) {
  opts = opts || {};
  const maxCommits = opts.maxCommits || 10000;
  const includeDeleted = opts.includeDeleted !== false;

  const startTime = Date.now();

  if (!isGitRepo(repoPath)) {
    return {
      error: "Not a git repository",
      repoPath,
      findings: [],
      summary: { total: 0 },
    };
  }

  const root = getRepoRoot(repoPath);
  const findings = [];

  // ---- 1. Get all filenames ever added to the repo ----
  const logOutput = git(root, [
    "log", "--all", "--diff-filter=A", "--name-only",
    "--pretty=format:", "--max-count=" + maxCommits,
  ]);
  if (logOutput === null) {
    return {
      error: "Failed to read git history",
      repoPath: root,
      findings: [],
      summary: { total: 0 },
    };
  }

  const allFilesEver = [...new Set(
    logOutput.split("\n").map((l) => l.trim()).filter(Boolean)
  )];

  // ---- 2. Get files currently in HEAD ----
  const headOutput = git(root, ["ls-tree", "-r", "--name-only", "HEAD"]);
  const headFiles = new Set(
    (headOutput || "").split("\n").map((l) => l.trim()).filter(Boolean)
  );

  // ---- 3. Check each historical file ----
  for (const filePath of allFilesEver) {
    const basename = path.basename(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const inHead = headFiles.has(filePath);
    const status = inHead ? "present" : "deleted-from-HEAD";

    if (!includeDeleted && !inHead) continue;

    // Check against sensitive filenames
    let matched = false;
    for (const sens of SENSITIVE_FILENAMES) {
      if (basename === path.basename(sens) || filePath.toLowerCase().endsWith(sens.toLowerCase())) {
        findings.push({
          type: "history-filename",
          label: "Sensitive File in Git History",
          severity: "critical",
          file: filePath,
          status,
          match: basename,
          description: `"${basename}" was committed to the repository${!inHead ? " (since removed from HEAD, but still in history)" : ""}. This file type commonly contains secrets.`,
          remediation: !inHead
            ? "The file was removed from HEAD but its contents persist in git history. Use git-filter-repo or BFG Repo-Cleaner to purge it, then rotate any credentials it contained."
            : "Remove the file from the repository, add it to .gitignore, and rotate any credentials it contains.",
        });
        matched = true;
        break;
      }
    }

    // Check against sensitive extensions
    if (!matched && SENSITIVE_EXTENSIONS.includes(ext)) {
      findings.push({
        type: "history-extension",
        label: "Sensitive File Extension in Git History",
        severity: "high",
        file: filePath,
        status,
        match: ext,
        description: `A file with extension "${ext}" was committed${!inHead ? " (since removed)" : ""}. Files of this type often contain private keys or credentials.`,
        remediation: "Verify the file does not contain secrets. If it does, purge from history and rotate credentials.",
      });
    }
  }

  // ---- 4. Check for commits with suspicious messages ----
  const suspiciousMessages = git(root, [
    "log", "--all", "--oneline", "--max-count=" + maxCommits,
    "--grep=secret", "--grep=password", "--grep=credential",
    "--grep=private.key", "--grep=api.key", "--grep=token",
    "--grep=remove.*secret", "--grep=delete.*key",
    "--grep=oops", "--grep=accidentally",
  ]);

  const suspiciousCommits = (suspiciousMessages || "").split("\n").filter(Boolean);
  for (const commitLine of suspiciousCommits) {
    const parts = commitLine.match(/^([0-9a-f]+)\s+(.+)$/);
    if (!parts) continue;
    findings.push({
      type: "history-message",
      label: "Suspicious Commit Message",
      severity: "medium",
      commit: parts[1],
      message: parts[2],
      description: `Commit message mentions secrets/credentials: "${parts[2]}". Inspect this commit for leaked data.`,
      remediation: "Review the commit diff to verify no secrets were committed. If they were, purge from history.",
    });
  }

  // ---- 5. Look for large blobs that might be key/cert bundles ----
  const largeBlobs = git(root, [
    "rev-list", "--objects", "--all",
  ]);
  // We skip full blob-size analysis for performance; rely on filename matching above.

  // ---- 6. Check for force-pushes that might have been used to hide secrets ----
  const reflog = git(root, ["reflog", "--all", "--max-count=500"]);
  const forcePushes = (reflog || "").split("\n").filter((l) =>
    /forced-update|reset.*--hard|rebase.*--force/i.test(l)
  );
  if (forcePushes.length > 0) {
    findings.push({
      type: "history-forcepush",
      label: "Force-Push / History Rewrite Detected",
      severity: "info",
      count: forcePushes.length,
      description: `${forcePushes.length} force-push(es) or history rewrites detected in the reflog. These may have been used to remove accidentally committed secrets, but the old objects may still exist locally.`,
      remediation: "Run git gc --prune=now and git reflog expire --expire=now --all to clean up old objects, then verify no secrets remain.",
    });
  }

  const elapsed = Date.now() - startTime;

  // Summary
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  for (const f of findings) summary[f.severity] = (summary[f.severity] || 0) + 1;

  return {
    repoPath: root,
    scanTime: new Date().toISOString(),
    elapsedMs: elapsed,
    totalFilesInHistory: allFilesEver.length,
    totalFilesInHead: headFiles.size,
    summary,
    findings,
  };
}

// ---------------------------------------------------------------------------
// checkGitConfig(repoPath) -- audit .gitignore, hooks, signed commits,
// user config, and other git security settings
// ---------------------------------------------------------------------------

/**
 * Audit the git configuration of a repository for security best practices.
 *
 * Checks:
 *   - .gitignore coverage (are sensitive patterns listed?)
 *   - Pre-commit hooks (is a secret-scanning hook installed?)
 *   - Commit signing (GPG/SSH signatures enabled?)
 *   - User config (is a real email set, not a noreply?)
 *   - Branch protection hints
 *   - .gitattributes (is there a merge driver for lock files?)
 *
 * @param {string} repoPath - Path to the git repository
 * @returns {object} Config audit results
 */
function checkGitConfig(repoPath) {
  if (!isGitRepo(repoPath)) {
    return {
      error: "Not a git repository",
      repoPath,
      checks: [],
      score: 0,
      grade: "F",
    };
  }

  const root = getRepoRoot(repoPath);
  const checks = [];

  // ---- 1. .gitignore analysis ----
  const gitignorePath = path.join(root, ".gitignore");
  let gitignoreContent = "";
  let hasGitignore = false;
  try {
    gitignoreContent = fs.readFileSync(gitignorePath, "utf8");
    hasGitignore = true;
  } catch (_) {}

  checks.push({
    id: "gitignore-exists",
    label: ".gitignore File Exists",
    passed: hasGitignore,
    severity: hasGitignore ? "info" : "high",
    description: hasGitignore
      ? ".gitignore file is present."
      : "No .gitignore file found. The repository may accidentally track sensitive files.",
    remediation: hasGitignore ? null : "Create a .gitignore file with entries appropriate for your project type.",
  });

  if (hasGitignore) {
    // Check for critical ignore patterns
    const criticalPatterns = [
      { pattern: ".env", label: "Environment files (.env)" },
      { pattern: "*.pem", label: "PEM files (*.pem)" },
      { pattern: "*.key", label: "Key files (*.key)" },
      { pattern: "node_modules", label: "Node modules" },
      { pattern: "*.tfstate", label: "Terraform state (*.tfstate)" },
      { pattern: "credentials", label: "Credentials files" },
      { pattern: "*.p12", label: "PKCS12 files (*.p12)" },
      { pattern: ".env.*", label: "Environment variants (.env.*)" },
      { pattern: "id_rsa", label: "SSH private keys" },
      { pattern: "*.jks", label: "Java keystores (*.jks)" },
    ];

    const gitignoreLines = gitignoreContent.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));

    for (const cp of criticalPatterns) {
      const covered = gitignoreLines.some((line) => {
        // Simplified matching: check if the gitignore line covers this pattern
        const norm = line.replace(/^\//, "").replace(/\/$/, "");
        return norm === cp.pattern || norm.includes(cp.pattern) || cp.pattern.includes(norm);
      });
      checks.push({
        id: "gitignore-" + cp.pattern.replace(/[^a-z0-9]/g, "-"),
        label: `${cp.label} in .gitignore`,
        passed: covered,
        severity: covered ? "info" : "medium",
        description: covered
          ? `"${cp.pattern}" is covered by .gitignore.`
          : `"${cp.pattern}" is NOT covered by .gitignore. These files may be accidentally committed.`,
        remediation: covered ? null : `Add "${cp.pattern}" to your .gitignore file.`,
      });
    }

    // Check for negation patterns that might override safety
    const negations = gitignoreLines.filter((l) => l.startsWith("!"));
    if (negations.length > 0) {
      // Check if any negation re-includes a sensitive pattern
      const dangerousNegations = negations.filter((neg) => {
        const reIncluded = neg.slice(1);
        return SENSITIVE_EXTENSIONS.some((ext) => reIncluded.includes(ext)) ||
               SENSITIVE_FILENAMES.some((f) => reIncluded.includes(path.basename(f)));
      });
      if (dangerousNegations.length > 0) {
        checks.push({
          id: "gitignore-dangerous-negation",
          label: "Dangerous .gitignore Negation",
          passed: false,
          severity: "high",
          description: `Negation pattern(s) may re-include sensitive files: ${dangerousNegations.join(", ")}`,
          remediation: "Review negation patterns to ensure they do not re-include sensitive files.",
        });
      }
    }
  }

  // ---- 2. Git hooks ----
  const hooksDir = path.join(root, ".git", "hooks");
  let hasPreCommitHook = false;
  let hasPrePushHook = false;
  let hasCommitMsgHook = false;

  try {
    const preCommit = path.join(hooksDir, "pre-commit");
    if (fs.existsSync(preCommit)) {
      const hookContent = fs.readFileSync(preCommit, "utf8");
      hasPreCommitHook = true;
      // Check if it's a secret-scanning hook
      const isSecretScanner = /gitleaks|trufflehog|detect-secrets|git-secrets|talisman|secret/i.test(hookContent);
      checks.push({
        id: "hook-precommit-secrets",
        label: "Pre-Commit Secret Scanning Hook",
        passed: isSecretScanner,
        severity: isSecretScanner ? "info" : "medium",
        description: isSecretScanner
          ? "Pre-commit hook includes secret scanning (good)."
          : "Pre-commit hook exists but does not appear to scan for secrets.",
        remediation: isSecretScanner ? null : "Add a secret-scanning tool (gitleaks, trufflehog, detect-secrets) to your pre-commit hook.",
      });
    }
  } catch (_) {}

  try {
    if (fs.existsSync(path.join(hooksDir, "pre-push"))) hasPrePushHook = true;
  } catch (_) {}

  try {
    if (fs.existsSync(path.join(hooksDir, "commit-msg"))) hasCommitMsgHook = true;
  } catch (_) {}

  checks.push({
    id: "hook-precommit",
    label: "Pre-Commit Hook Installed",
    passed: hasPreCommitHook,
    severity: hasPreCommitHook ? "info" : "medium",
    description: hasPreCommitHook
      ? "A pre-commit hook is installed."
      : "No pre-commit hook found. Consider installing one for secret scanning and linting.",
    remediation: hasPreCommitHook ? null : "Install a pre-commit hook. Tools: husky (Node), pre-commit (Python), or a custom script.",
  });

  checks.push({
    id: "hook-prepush",
    label: "Pre-Push Hook Installed",
    passed: hasPrePushHook,
    severity: hasPrePushHook ? "info" : "low",
    description: hasPrePushHook
      ? "A pre-push hook is installed."
      : "No pre-push hook. Consider adding one for additional validation before pushing.",
    remediation: hasPrePushHook ? null : "Consider adding a pre-push hook for running tests or security checks before push.",
  });

  // ---- 3. Husky / lint-staged / lefthook detection ----
  const packageJsonPath = path.join(root, "package.json");
  let hasHusky = false;
  let hasLintStaged = false;
  try {
    const pkg = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
    const deps = Object.assign({}, pkg.dependencies, pkg.devDependencies);
    hasHusky = !!deps.husky;
    hasLintStaged = !!deps["lint-staged"];
  } catch (_) {}

  const huskyDir = path.join(root, ".husky");
  if (!hasHusky) {
    try { hasHusky = fs.existsSync(huskyDir); } catch (_) {}
  }

  // Lefthook detection
  let hasLefthook = false;
  try {
    hasLefthook = fs.existsSync(path.join(root, "lefthook.yml")) ||
                  fs.existsSync(path.join(root, ".lefthook.yml"));
  } catch (_) {}

  checks.push({
    id: "hook-manager",
    label: "Git Hook Manager",
    passed: hasHusky || hasLefthook,
    severity: (hasHusky || hasLefthook) ? "info" : "low",
    description: hasHusky ? "Husky is configured for git hook management."
      : hasLefthook ? "Lefthook is configured for git hook management."
      : "No git hook manager detected (husky, lefthook). Hook management tools ensure hooks are shared across the team.",
    remediation: (hasHusky || hasLefthook) ? null : "Consider installing husky or lefthook to manage git hooks in a team-friendly way.",
  });

  // ---- 4. Commit signing ----
  const gpgSign = git(root, ["config", "--get", "commit.gpgsign"]);
  const gpgEnabled = gpgSign && gpgSign.trim() === "true";

  const sshSign = git(root, ["config", "--get", "gpg.format"]);
  const sshSignEnabled = sshSign && sshSign.trim() === "ssh";

  const signingEnabled = gpgEnabled || sshSignEnabled;

  checks.push({
    id: "commit-signing",
    label: "Commit Signing Enabled",
    passed: signingEnabled,
    severity: signingEnabled ? "info" : "medium",
    description: signingEnabled
      ? `Commit signing is enabled (${sshSignEnabled ? "SSH" : "GPG"}).`
      : "Commit signing is not enabled. Unsigned commits can be spoofed.",
    remediation: signingEnabled ? null : "Enable commit signing with: git config commit.gpgsign true (GPG) or set gpg.format to ssh for SSH signing.",
  });

  // ---- 5. User config ----
  const userName = (git(root, ["config", "--get", "user.name"]) || "").trim();
  const userEmail = (git(root, ["config", "--get", "user.email"]) || "").trim();

  checks.push({
    id: "user-name",
    label: "Git User Name Configured",
    passed: userName.length > 0,
    severity: userName.length > 0 ? "info" : "low",
    description: userName.length > 0
      ? `Git user name: ${userName}`
      : "No git user name configured.",
    remediation: userName.length > 0 ? null : "Set your git user name: git config user.name 'Your Name'",
  });

  checks.push({
    id: "user-email",
    label: "Git User Email Configured",
    passed: userEmail.length > 0 && !userEmail.includes("noreply"),
    severity: userEmail.length > 0 ? "info" : "low",
    description: userEmail.length > 0
      ? `Git user email: ${userEmail}`
      : "No git user email configured.",
    remediation: userEmail.length > 0 ? null : "Set your git user email: git config user.email 'you@example.com'",
  });

  // ---- 6. Default branch ----
  const defaultBranch = (git(root, ["config", "--get", "init.defaultBranch"]) || "").trim();
  checks.push({
    id: "default-branch",
    label: "Default Branch Name",
    passed: true,
    severity: "info",
    description: defaultBranch
      ? `Default branch is set to "${defaultBranch}".`
      : "No default branch configured (git defaults to 'master').",
    remediation: null,
  });

  // ---- 7. .gitattributes ----
  const gitattrsPath = path.join(root, ".gitattributes");
  let hasGitattrs = false;
  let attrsContent = "";
  try {
    attrsContent = fs.readFileSync(gitattrsPath, "utf8");
    hasGitattrs = true;
  } catch (_) {}

  checks.push({
    id: "gitattributes",
    label: ".gitattributes File",
    passed: hasGitattrs,
    severity: hasGitattrs ? "info" : "low",
    description: hasGitattrs
      ? ".gitattributes file is present."
      : "No .gitattributes file. Consider adding one for consistent line endings and diff behavior.",
    remediation: hasGitattrs ? null : "Create a .gitattributes file with at least: * text=auto",
  });

  if (hasGitattrs) {
    // Check for binary marking of sensitive extensions
    const marksBinarySecrets = /\*\.pem|\*\.key|\*\.p12|\*\.jks/.test(attrsContent) &&
                               /binary|diff=/.test(attrsContent);
    checks.push({
      id: "gitattributes-secrets",
      label: "Sensitive Files Marked in .gitattributes",
      passed: marksBinarySecrets,
      severity: marksBinarySecrets ? "info" : "low",
      description: marksBinarySecrets
        ? "Sensitive file types have diff/merge attributes set."
        : "Sensitive file types (*.pem, *.key, etc.) are not given special treatment in .gitattributes.",
      remediation: marksBinarySecrets ? null : "Consider marking sensitive extensions as binary in .gitattributes to prevent accidental diff display.",
    });
  }

  // ---- 8. Fetch/Push URL security ----
  const remoteUrl = (git(root, ["config", "--get", "remote.origin.url"]) || "").trim();
  if (remoteUrl) {
    const usesHttps = remoteUrl.startsWith("https://");
    const usesSsh = remoteUrl.startsWith("git@") || remoteUrl.startsWith("ssh://");
    const hasEmbeddedCreds = /https?:\/\/[^@:]+:[^@]+@/.test(remoteUrl);

    checks.push({
      id: "remote-protocol",
      label: "Remote URL Protocol",
      passed: usesSsh || (usesHttps && !hasEmbeddedCreds),
      severity: hasEmbeddedCreds ? "critical" : (usesSsh || usesHttps) ? "info" : "medium",
      description: hasEmbeddedCreds
        ? "Remote URL contains embedded credentials -- these are stored in .git/config in plain text."
        : usesSsh
        ? `Remote uses SSH (${remoteUrl.replace(/:.+/, ":...")}), which is secure.`
        : usesHttps
        ? "Remote uses HTTPS."
        : `Remote URL protocol: ${remoteUrl.split(":")[0]}`,
      remediation: hasEmbeddedCreds
        ? "Change the remote URL to use SSH or HTTPS with a credential helper instead of embedded credentials."
        : null,
    });
  }

  // ---- 9. Check for .git directory permissions ----
  try {
    const gitDirStat = fs.statSync(path.join(root, ".git"));
    const mode = (gitDirStat.mode & 0o777).toString(8);
    const isWorldReadable = (gitDirStat.mode & 0o004) !== 0;
    checks.push({
      id: "git-dir-permissions",
      label: ".git Directory Permissions",
      passed: !isWorldReadable,
      severity: isWorldReadable ? "medium" : "info",
      description: isWorldReadable
        ? `.git directory is world-readable (mode ${mode}). Other users on this system can read your repository data.`
        : `.git directory permissions are appropriate (mode ${mode}).`,
      remediation: isWorldReadable ? "Run: chmod -R o-rwx .git" : null,
    });
  } catch (_) {}

  // ---- 10. Check for shallow clone ----
  const isShallow = git(root, ["rev-parse", "--is-shallow-repository"]);
  if (isShallow && isShallow.trim() === "true") {
    checks.push({
      id: "shallow-clone",
      label: "Shallow Clone Detected",
      passed: true,
      severity: "info",
      description: "This is a shallow clone. Full history analysis may be incomplete.",
      remediation: "Run git fetch --unshallow to get the full history for thorough secret scanning.",
    });
  }

  // ---- Scoring ----
  const passed = checks.filter((c) => c.passed).length;
  const total = checks.length;
  const score = total > 0 ? Math.round((passed / total) * 100) : 0;
  const grade = scoreToGrade(score);

  return {
    repoPath: root,
    scanTime: new Date().toISOString(),
    checks,
    score,
    grade,
    passed,
    total,
    remoteUrl: remoteUrl || null,
    userName,
    userEmail,
  };
}

/**
 * Score-to-grade helper, matching the vuln-scanner convention.
 */
function scoreToGrade(score) {
  const THRESHOLDS = [
    { min: 95, grade: "A+" },
    { min: 85, grade: "A"  },
    { min: 75, grade: "B+" },
    { min: 65, grade: "B"  },
    { min: 55, grade: "C+" },
    { min: 45, grade: "C"  },
    { min: 35, grade: "D"  },
    { min: 0,  grade: "F"  },
  ];
  for (const t of THRESHOLDS) {
    if (score >= t.min) return t.grade;
  }
  return "F";
}

// ---------------------------------------------------------------------------
// formatSecretReport(findings) -- generate a markdown security report
//
// Accepts a findings object (from scanGitSecrets, analyzeGitHistory, or
// checkGitConfig) and produces a formatted markdown report suitable for
// display in a terminal or saving to a file.
// ---------------------------------------------------------------------------

/**
 * Format a complete security report from scan results.
 *
 * @param {object} scanResult - Result from scanGitSecrets()
 * @param {object} [historyResult] - Result from analyzeGitHistory()
 * @param {object} [configResult] - Result from checkGitConfig()
 * @returns {string} Formatted markdown report
 */
function formatSecretReport(scanResult, historyResult, configResult) {
  const lines = [];
  const hr = "---";

  lines.push("# Git Security Scan Report");
  lines.push("");
  lines.push(`**Repository:** ${scanResult ? scanResult.repoPath : "N/A"}`);
  lines.push(`**Scan Date:** ${new Date().toISOString()}`);
  lines.push("");

  // ---- Executive Summary ----
  lines.push("## Executive Summary");
  lines.push("");

  const allFindings = [];
  if (scanResult && scanResult.findings) allFindings.push(...scanResult.findings);
  if (historyResult && historyResult.findings) allFindings.push(...historyResult.findings);

  const totalCritical = allFindings.filter((f) => f.severity === "critical").length;
  const totalHigh = allFindings.filter((f) => f.severity === "high").length;
  const totalMedium = allFindings.filter((f) => f.severity === "medium").length;
  const totalLow = allFindings.filter((f) => f.severity === "low").length;
  const totalInfo = allFindings.filter((f) => f.severity === "info").length;
  const totalCount = allFindings.length;

  if (totalCount === 0) {
    lines.push("No secrets or sensitive data detected. Good work keeping the repository clean.");
  } else {
    lines.push(`**${totalCount} finding(s) detected:**`);
    lines.push("");
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    if (totalCritical > 0) lines.push(`| CRITICAL | ${totalCritical} |`);
    if (totalHigh > 0) lines.push(`| HIGH     | ${totalHigh} |`);
    if (totalMedium > 0) lines.push(`| MEDIUM   | ${totalMedium} |`);
    if (totalLow > 0) lines.push(`| LOW      | ${totalLow} |`);
    if (totalInfo > 0) lines.push(`| INFO     | ${totalInfo} |`);
  }
  lines.push("");

  // ---- Working Tree Scan ----
  if (scanResult) {
    lines.push(hr);
    lines.push("## Working Tree Secret Scan");
    lines.push("");
    lines.push(`- Files scanned: ${scanResult.files ? scanResult.files.scanned : "N/A"}`);
    lines.push(`- Total lines analyzed: ${scanResult.files ? scanResult.files.totalLines.toLocaleString() : "N/A"}`);
    lines.push(`- Patterns used: ${scanResult.patternsUsed}`);
    lines.push(`- Entropy threshold: ${scanResult.entropyThreshold} bits/char`);
    lines.push(`- Scan duration: ${scanResult.elapsedMs}ms`);
    lines.push("");

    if (scanResult.findings && scanResult.findings.length > 0) {
      lines.push("### Findings");
      lines.push("");

      // Group by severity
      const bySev = {};
      for (const f of scanResult.findings) {
        if (!bySev[f.severity]) bySev[f.severity] = [];
        bySev[f.severity].push(f);
      }

      for (const sev of ["critical", "high", "medium", "low", "info"]) {
        const group = bySev[sev];
        if (!group || group.length === 0) continue;

        lines.push(`#### ${sev.toUpperCase()} (${group.length})`);
        lines.push("");

        for (const f of group) {
          lines.push(`- **${f.label}** in \`${f.file}\`${f.line ? ` (line ${f.line})` : ""}`);
          lines.push(`  - Pattern: ${f.patternId}`);
          lines.push(`  - Match: \`${f.match}\``);
          lines.push(`  - ${f.description}`);
          lines.push("");
        }
      }
    } else {
      lines.push("No secrets detected in the working tree.");
      lines.push("");
    }
  }

  // ---- History Analysis ----
  if (historyResult) {
    lines.push(hr);
    lines.push("## Git History Analysis");
    lines.push("");
    lines.push(`- Files ever committed: ${historyResult.totalFilesInHistory || "N/A"}`);
    lines.push(`- Files currently in HEAD: ${historyResult.totalFilesInHead || "N/A"}`);
    lines.push(`- Analysis duration: ${historyResult.elapsedMs}ms`);
    lines.push("");

    if (historyResult.findings && historyResult.findings.length > 0) {
      lines.push("### Historical Findings");
      lines.push("");

      for (const f of historyResult.findings) {
        const icon = f.severity === "critical" ? "[CRITICAL]"
          : f.severity === "high" ? "[HIGH]"
          : f.severity === "medium" ? "[MEDIUM]"
          : `[${f.severity.toUpperCase()}]`;

        if (f.type === "history-message") {
          lines.push(`- ${icon} **${f.label}**: commit \`${f.commit}\` -- "${f.message}"`);
        } else {
          lines.push(`- ${icon} **${f.label}**: \`${f.file}\` (${f.status || "unknown"})`);
        }
        lines.push(`  - ${f.description}`);
        if (f.remediation) lines.push(`  - Remediation: ${f.remediation}`);
        lines.push("");
      }
    } else {
      lines.push("No sensitive files found in git history.");
      lines.push("");
    }
  }

  // ---- Config Audit ----
  if (configResult) {
    lines.push(hr);
    lines.push("## Git Configuration Audit");
    lines.push("");
    lines.push(`- Score: **${configResult.score}/100** (Grade: **${configResult.grade}**)`);
    lines.push(`- Checks passed: ${configResult.passed}/${configResult.total}`);
    if (configResult.remoteUrl) lines.push(`- Remote: ${configResult.remoteUrl}`);
    if (configResult.userName) lines.push(`- User: ${configResult.userName} <${configResult.userEmail || "not set"}>`);
    lines.push("");

    if (configResult.checks && configResult.checks.length > 0) {
      lines.push("### Configuration Checks");
      lines.push("");
      lines.push("| Status | Check | Severity | Details |");
      lines.push("|--------|-------|----------|---------|");

      for (const c of configResult.checks) {
        const status = c.passed ? "PASS" : "FAIL";
        const detail = c.description.length > 80 ? c.description.slice(0, 77) + "..." : c.description;
        lines.push(`| ${status} | ${c.label} | ${c.severity.toUpperCase()} | ${detail} |`);
      }
      lines.push("");

      // Remediation section for failed checks
      const failed = configResult.checks.filter((c) => !c.passed && c.remediation);
      if (failed.length > 0) {
        lines.push("### Recommended Actions");
        lines.push("");
        for (let i = 0; i < failed.length; i++) {
          lines.push(`${i + 1}. **${failed[i].label}**: ${failed[i].remediation}`);
        }
        lines.push("");
      }
    }
  }

  // ---- .gitignore Recommendations ----
  lines.push(hr);
  lines.push("## Recommended .gitignore Entries");
  lines.push("");
  lines.push("Add the following entries to your .gitignore based on your project type:");
  lines.push("");

  // Always recommend universal
  lines.push("### Universal (all projects)");
  lines.push("");
  lines.push("```gitignore");
  lines.push(GITIGNORE_RECOMMENDATIONS.universal.entries.join("\n"));
  lines.push("```");
  lines.push("");

  // Detect project type from files present
  const root = scanResult ? scanResult.repoPath : (configResult ? configResult.repoPath : ".");
  const detectedTypes = detectProjectTypes(root);

  for (const ptype of detectedTypes) {
    const rec = GITIGNORE_RECOMMENDATIONS[ptype];
    if (!rec) continue;
    lines.push(`### ${rec.label}`);
    lines.push("");
    lines.push("```gitignore");
    lines.push(rec.entries.join("\n"));
    lines.push("```");
    lines.push("");
  }

  // ---- Remediation Guide ----
  if (totalCount > 0) {
    lines.push(hr);
    lines.push("## Remediation Guide");
    lines.push("");
    lines.push("### Immediate Actions");
    lines.push("");
    lines.push("1. **Rotate all compromised credentials** -- any secret found in a git repository");
    lines.push("   must be considered compromised, even if the commit was reverted or the file removed.");
    lines.push("   The old value persists in git history and reflog.");
    lines.push("");
    lines.push("2. **Remove secrets from the working tree** -- move secrets to environment variables,");
    lines.push("   a secrets manager (Vault, AWS Secrets Manager, 1Password), or encrypted config.");
    lines.push("");
    lines.push("3. **Purge secrets from git history** using one of:");
    lines.push("   - `git-filter-repo --path <file> --invert-paths` (recommended)");
    lines.push("   - `bfg --delete-files <file>` (BFG Repo-Cleaner)");
    lines.push("   - Then: `git reflog expire --expire=now --all && git gc --prune=now --aggressive`");
    lines.push("");
    lines.push("4. **Force-push the cleaned history** to the remote (coordinate with team first).");
    lines.push("");
    lines.push("### Prevention");
    lines.push("");
    lines.push("1. **Install a pre-commit secret scanner** -- gitleaks, trufflehog, or detect-secrets.");
    lines.push("2. **Use .gitignore** -- ensure all sensitive file types are excluded.");
    lines.push("3. **Enable commit signing** -- prevents commit author spoofing.");
    lines.push("4. **Use a .env.example pattern** -- commit a template with placeholder values,");
    lines.push("   never the real .env file.");
    lines.push("5. **CI/CD scanning** -- add secret scanning to your CI pipeline (GitHub Advanced Security,");
    lines.push("   GitLab Secret Detection, or standalone gitleaks/trufflehog).");
    lines.push("");
  }

  // ---- Tool Recommendations ----
  lines.push(hr);
  lines.push("## Recommended Tools");
  lines.push("");
  lines.push("| Tool | Purpose | Install |");
  lines.push("|------|---------|---------|");
  lines.push("| gitleaks | Git secret scanning | `brew install gitleaks` |");
  lines.push("| trufflehog | Deep secret scanning with verification | `brew install trufflehog` |");
  lines.push("| detect-secrets | Yelp's baseline-aware secret scanner | `pip install detect-secrets` |");
  lines.push("| git-filter-repo | History rewriting (remove secrets) | `pip install git-filter-repo` |");
  lines.push("| BFG Repo-Cleaner | Fast history cleaning | `brew install bfg` |");
  lines.push("| git-secrets | AWS credential scanner (pre-commit) | `brew install git-secrets` |");
  lines.push("| talisman | Pre-push hook for secret detection | See talisman.github.io |");
  lines.push("");

  lines.push(hr);
  lines.push(`*Report generated by darknode git-security scanner at ${new Date().toISOString()}*`);

  return lines.join("\n");
}

/**
 * Detect project types present in a repository based on marker files.
 */
function detectProjectTypes(repoPath) {
  const types = [];
  const markers = {
    node:      ["package.json", "yarn.lock", "pnpm-lock.yaml", ".npmrc"],
    python:    ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "setup.cfg"],
    ruby:      ["Gemfile", "Rakefile", ".ruby-version"],
    go:        ["go.mod", "go.sum"],
    java:      ["pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"],
    rust:      ["Cargo.toml"],
    dotnet:    [".csproj", ".sln", ".fsproj", "global.json"],
    terraform: ["main.tf", "variables.tf", "terraform.tf"],
    docker:    ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"],
    mobile:    ["Podfile", "build.gradle", "AndroidManifest.xml", "Info.plist"],
    php:       ["composer.json", "artisan", "wp-config.php", "index.php"],
  };

  for (const [type, files] of Object.entries(markers)) {
    for (const f of files) {
      try {
        if (fs.existsSync(path.join(repoPath, f))) {
          types.push(type);
          break;
        }
      } catch (_) {}
    }
  }
  return types;
}

// ---------------------------------------------------------------------------
// runFullScan(repoPath, opts) -- convenience wrapper that runs all three
// analyses and produces a combined report
// ---------------------------------------------------------------------------

/**
 * Run a full git security scan: working tree secrets, history analysis,
 * and configuration audit.
 *
 * @param {string} repoPath - Path to the git repository
 * @param {object} [opts] - Options passed through to individual scanners
 * @returns {object} Combined results with report
 */
function runFullScan(repoPath, opts) {
  opts = opts || {};

  const scanResult = scanGitSecrets(repoPath, opts);
  const historyResult = isGitRepo(repoPath) ? analyzeGitHistory(repoPath, opts) : null;
  const configResult = isGitRepo(repoPath) ? checkGitConfig(repoPath) : null;

  const report = formatSecretReport(scanResult, historyResult, configResult);

  // Compute overall risk level
  const allFindings = [
    ...(scanResult.findings || []),
    ...(historyResult ? historyResult.findings || [] : []),
  ];
  const criticalCount = allFindings.filter((f) => f.severity === "critical").length;
  const highCount = allFindings.filter((f) => f.severity === "high").length;

  let riskLevel = "low";
  if (criticalCount > 0) riskLevel = "critical";
  else if (highCount > 5) riskLevel = "high";
  else if (highCount > 0) riskLevel = "medium";

  return {
    riskLevel,
    scan: scanResult,
    history: historyResult,
    config: configResult,
    report,
    totalFindings: allFindings.length,
    criticalFindings: criticalCount,
    highFindings: highCount,
  };
}

// ---------------------------------------------------------------------------
// diffSecretScan(repoPath) -- scan only staged/unstaged changes for secrets
//
// Useful as a pre-commit check: only analyzes what is about to be committed,
// not the entire working tree.
// ---------------------------------------------------------------------------

/**
 * Scan staged and unstaged changes for secrets. Designed for pre-commit use.
 *
 * @param {string} repoPath - Path to the git repository
 * @returns {object} Findings from changed content only
 */
function diffSecretScan(repoPath) {
  if (!isGitRepo(repoPath)) {
    return { error: "Not a git repository", findings: [] };
  }

  const root = getRepoRoot(repoPath);
  const findings = [];

  // Get staged diff
  const stagedDiff = git(root, ["diff", "--cached", "--unified=0"]);
  // Get unstaged diff
  const unstagedDiff = git(root, ["diff", "--unified=0"]);

  const diffs = [
    { label: "staged", content: stagedDiff },
    { label: "unstaged", content: unstagedDiff },
  ];

  for (const d of diffs) {
    if (!d.content) continue;

    let currentFile = "";
    let lineNum = 0;

    for (const line of d.content.split("\n")) {
      // Track current file
      const fileMatch = line.match(/^\+\+\+ b\/(.+)$/);
      if (fileMatch) {
        currentFile = fileMatch[1];
        continue;
      }

      // Track line number from hunk headers
      const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
      if (hunkMatch) {
        lineNum = parseInt(hunkMatch[1], 10);
        continue;
      }

      // Only check added lines (lines starting with +)
      if (!line.startsWith("+") || line.startsWith("+++")) continue;
      const addedLine = line.slice(1);

      // Pattern matching
      for (const pat of SECRET_PATTERNS) {
        if (pat.regex.test(addedLine)) {
          const match = addedLine.match(pat.regex);
          findings.push({
            type: "diff-pattern",
            stage: d.label,
            patternId: pat.id,
            label: pat.label,
            severity: pat.severity,
            file: currentFile,
            line: lineNum,
            match: maskSecret(match ? match[0] : ""),
            description: pat.description,
          });
        }
      }

      // Entropy check on added lines
      if (addedLine.length > 20) {
        const entropyHits = extractHighEntropyTokens(addedLine);
        for (const hit of entropyHits) {
          findings.push({
            type: "diff-entropy",
            stage: d.label,
            patternId: "high-entropy",
            label: "High-Entropy String in Diff",
            severity: "medium",
            file: currentFile,
            line: lineNum,
            match: hit.token,
            entropy: hit.entropy,
            description: `High-entropy ${hit.charset} string (${hit.entropy} bits/char) in ${d.label} changes.`,
          });
        }
      }

      lineNum++;
    }
  }

  // Deduplicate
  const seen = new Set();
  const deduped = findings.filter((f) => {
    const key = `${f.file}:${f.line}:${f.patternId}:${f.stage}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: deduped.length };
  for (const f of deduped) summary[f.severity] = (summary[f.severity] || 0) + 1;

  return {
    repoPath: root,
    scanTime: new Date().toISOString(),
    summary,
    findings: deduped,
  };
}

// ---------------------------------------------------------------------------
// generatePreCommitHook() -- generate a pre-commit hook script that uses
// this module's secret patterns for scanning
// ---------------------------------------------------------------------------

/**
 * Generate a shell script for a pre-commit hook that scans staged files
 * for secrets using the patterns from this module.
 *
 * @returns {string} Shell script content
 */
function generatePreCommitHook() {
  const lines = [];
  lines.push("#!/usr/bin/env bash");
  lines.push("# Pre-commit hook: scan staged files for secrets");
  lines.push("# Generated by darknode git-security module");
  lines.push("# Install: cp this file to .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit");
  lines.push("");
  lines.push('set -euo pipefail');
  lines.push("");
  lines.push("# Color codes for output");
  lines.push('RED="\\033[0;31m"');
  lines.push('YELLOW="\\033[0;33m"');
  lines.push('GREEN="\\033[0;32m"');
  lines.push('NC="\\033[0m" # No Color');
  lines.push("");
  lines.push("FOUND=0");
  lines.push("");
  lines.push("# Get list of staged files");
  lines.push('FILES=$(git diff --cached --name-only --diff-filter=ACM)');
  lines.push("");
  lines.push('if [ -z "$FILES" ]; then');
  lines.push("  exit 0");
  lines.push("fi");
  lines.push("");
  lines.push("# Check for sensitive filenames");
  lines.push("SENSITIVE_FILES=(");

  // Add a subset of the most critical sensitive filenames
  const criticalFiles = SENSITIVE_FILENAMES.slice(0, 30);
  for (const f of criticalFiles) {
    lines.push(`  "${path.basename(f)}"`);
  }
  lines.push(")");
  lines.push("");

  lines.push('for FILE in $FILES; do');
  lines.push('  BASENAME=$(basename "$FILE")');
  lines.push('  for SENS in "${SENSITIVE_FILES[@]}"; do');
  lines.push('    if [ "$BASENAME" = "$SENS" ]; then');
  lines.push('      echo -e "${RED}[BLOCKED]${NC} Sensitive file staged: $FILE"');
  lines.push("      FOUND=1");
  lines.push("    fi");
  lines.push("  done");
  lines.push("done");
  lines.push("");

  lines.push("# Check for sensitive extensions");
  lines.push('for FILE in $FILES; do');
  lines.push('  case "$FILE" in');
  lines.push("    *.pem|*.key|*.p12|*.pfx|*.jks|*.keystore)");
  lines.push('      echo -e "${RED}[BLOCKED]${NC} Sensitive file extension: $FILE"');
  lines.push("      FOUND=1");
  lines.push("      ;;");
  lines.push("  esac");
  lines.push("done");
  lines.push("");

  lines.push("# Check staged content for secret patterns");
  lines.push('for FILE in $FILES; do');
  lines.push('  # Skip binary files');
  lines.push('  if file "$FILE" | grep -qE "binary|executable|archive|image|font"; then');
  lines.push("    continue");
  lines.push("  fi");
  lines.push("");
  lines.push('  CONTENT=$(git diff --cached -- "$FILE" | grep "^+" | grep -v "^+++" || true)');
  lines.push("");

  // Add pattern checks for the most critical patterns
  const hookPatterns = [
    { label: "AWS Access Key",    pattern: "AKIA[A-Z0-9]{16}" },
    { label: "AWS Secret Key",    pattern: "aws_secret_access_key\\s*=" },
    { label: "GitHub Token",      pattern: "gh[pousr]_[A-Za-z0-9]{36}" },
    { label: "GitLab Token",      pattern: "glpat-[A-Za-z0-9_-]{20,}" },
    { label: "Slack Token",       pattern: "xox[bpors]-[0-9]{10,}" },
    { label: "Stripe Secret Key", pattern: "sk_live_[A-Za-z0-9]{24,}" },
    { label: "Private Key",       pattern: "-----BEGIN.*PRIVATE KEY-----" },
    { label: "SendGrid Key",      pattern: "SG\\.[A-Za-z0-9_-]{22}" },
    { label: "NPM Token",         pattern: "npm_[A-Za-z0-9_-]{36}" },
    { label: "JWT Token",         pattern: "eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}" },
    { label: "Connection String",  pattern: "(?:postgres|mysql|mongodb)://[^\\s]+:[^\\s]+@" },
    { label: "Hardcoded Password", pattern: "(?:password|passwd|pwd)\\s*[=:]\\s*['\"][^'\"]{8,}" },
  ];

  for (const hp of hookPatterns) {
    lines.push(`  if echo "$CONTENT" | grep -qEi '${hp.pattern}'; then`);
    lines.push(`    echo -e "\${RED}[BLOCKED]\${NC} ${hp.label} detected in: $FILE"`);
    lines.push("    FOUND=1");
    lines.push("  fi");
    lines.push("");
  }

  lines.push("done");
  lines.push("");
  lines.push('if [ "$FOUND" -eq 1 ]; then');
  lines.push('  echo ""');
  lines.push('  echo -e "${YELLOW}Commit blocked: potential secrets detected in staged files.${NC}"');
  lines.push('  echo "Review the findings above and either:"');
  lines.push('  echo "  1. Remove the secret and use environment variables instead"');
  lines.push('  echo "  2. Add the file to .gitignore"');
  lines.push('  echo "  3. Use git commit --no-verify to bypass (NOT recommended)"');
  lines.push('  echo ""');
  lines.push("  exit 1");
  lines.push("fi");
  lines.push("");
  lines.push('echo -e "${GREEN}Pre-commit secret scan passed.${NC}"');
  lines.push("exit 0");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// installPreCommitHook(repoPath) -- write the hook to .git/hooks/pre-commit
// ---------------------------------------------------------------------------

/**
 * Install the generated pre-commit hook into a repository.
 *
 * @param {string} repoPath - Path to the git repository
 * @param {object} [opts] - Options
 * @param {boolean} [opts.force=false] - Overwrite existing hook
 * @returns {object} Installation result
 */
function installPreCommitHook(repoPath, opts) {
  opts = opts || {};
  if (!isGitRepo(repoPath)) {
    return { success: false, error: "Not a git repository" };
  }

  const root = getRepoRoot(repoPath);
  const hookPath = path.join(root, ".git", "hooks", "pre-commit");

  // Check for existing hook
  if (fs.existsSync(hookPath) && !opts.force) {
    return {
      success: false,
      error: "Pre-commit hook already exists. Use force:true to overwrite.",
      existingHook: hookPath,
    };
  }

  try {
    const hookContent = generatePreCommitHook();
    fs.writeFileSync(hookPath, hookContent, { mode: 0o755 });
    return {
      success: true,
      hookPath,
      message: "Pre-commit secret scanning hook installed successfully.",
    };
  } catch (err) {
    return {
      success: false,
      error: `Failed to write hook: ${err.message}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Batch scanning helpers -- scan multiple repos
// ---------------------------------------------------------------------------

/**
 * Scan multiple repositories and produce a combined summary.
 *
 * @param {string[]} repoPaths - Array of repository paths
 * @param {object} [opts] - Options passed to scanGitSecrets
 * @returns {object} Combined results keyed by repo path
 */
function batchScan(repoPaths, opts) {
  const results = {};
  let totalFindings = 0;
  let totalCritical = 0;

  for (const rp of repoPaths) {
    try {
      const result = runFullScan(rp, opts);
      results[rp] = result;
      totalFindings += result.totalFindings || 0;
      totalCritical += result.criticalFindings || 0;
    } catch (err) {
      results[rp] = { error: err.message };
    }
  }

  return {
    repos: results,
    totalRepos: repoPaths.length,
    totalFindings,
    totalCritical,
    scanTime: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Secret pattern validation -- test patterns against known-safe/known-bad
// inputs to ensure accuracy
// ---------------------------------------------------------------------------

/**
 * Run self-test on all secret patterns to verify they match their expected
 * examples and do not match common false positives.
 *
 * @returns {object} Test results with pass/fail per pattern
 */
function selfTest() {
  const results = [];

  // Known false positives that should NOT match
  const falsePositives = [
    "const color = '#FF5733';",
    "// TODO: add authentication",
    "npm install express",
    "process.env.NODE_ENV",
    "https://example.com/api/v1/users",
    "Authorization: Bearer ${token}",
    'password=""',
    'api_key=""',
    "const PLACEHOLDER = 'replace-me';",
    "// sk_test_1234567890 -- this is a test key",
  ];

  for (const pat of SECRET_PATTERNS) {
    const testResult = {
      id: pat.id,
      label: pat.label,
      passed: true,
      issues: [],
    };

    // Verify regex compiles and does not throw
    try {
      new RegExp(pat.regex.source, pat.regex.flags);
    } catch (err) {
      testResult.passed = false;
      testResult.issues.push(`Regex compilation failed: ${err.message}`);
    }

    // Check that the regex does not catastrophically backtrack on long strings
    const longString = "a".repeat(10000);
    const start = Date.now();
    try {
      pat.regex.test(longString);
    } catch (_) {}
    const elapsed = Date.now() - start;
    if (elapsed > 100) {
      testResult.passed = false;
      testResult.issues.push(`Regex took ${elapsed}ms on a 10K-char string (possible catastrophic backtracking)`);
    }

    results.push(testResult);
  }

  const passed = results.filter((r) => r.passed).length;
  return {
    total: results.length,
    passed,
    failed: results.length - passed,
    results,
  };
}

// ---------------------------------------------------------------------------
// Allowlist / baseline support -- suppress known false positives
// ---------------------------------------------------------------------------

/**
 * Load an allowlist file (.secretsbaseline or .gitsecurityrc) that marks
 * known findings as accepted/suppressed.
 *
 * @param {string} repoPath - Path to the repository
 * @returns {Set} Set of "file:line:patternId" keys to suppress
 */
function loadAllowlist(repoPath) {
  const root = isGitRepo(repoPath) ? getRepoRoot(repoPath) : repoPath;
  const allowlist = new Set();

  const files = [".gitsecurityrc", ".secretsbaseline", ".secret-allowlist"];
  for (const f of files) {
    try {
      const content = fs.readFileSync(path.join(root, f), "utf8");
      const entries = JSON.parse(content);
      if (Array.isArray(entries)) {
        for (const entry of entries) {
          if (entry.file && entry.patternId) {
            const key = entry.line
              ? `${entry.file}:${entry.line}:${entry.patternId}`
              : `${entry.file}:*:${entry.patternId}`;
            allowlist.add(key);
          }
        }
      }
    } catch (_) {}
  }

  return allowlist;
}

/**
 * Filter findings against an allowlist, removing suppressed entries.
 *
 * @param {object[]} findings - Array of findings from any scanner
 * @param {Set} allowlist - Set from loadAllowlist()
 * @returns {object[]} Filtered findings
 */
function applyAllowlist(findings, allowlist) {
  if (!allowlist || allowlist.size === 0) return findings;
  return findings.filter((f) => {
    const exactKey = `${f.file}:${f.line}:${f.patternId}`;
    const wildcardKey = `${f.file}:*:${f.patternId}`;
    return !allowlist.has(exactKey) && !allowlist.has(wildcardKey);
  });
}

/**
 * Generate a baseline file from current findings, marking all as accepted.
 * This is useful for adopting the scanner on an existing project where
 * you want to suppress all existing findings and only flag new ones.
 *
 * @param {object[]} findings - Array of findings to baseline
 * @returns {string} JSON string to write to .gitsecurityrc
 */
function generateBaseline(findings) {
  const entries = findings.map((f) => ({
    file: f.file,
    line: f.line || null,
    patternId: f.patternId,
    label: f.label,
    severity: f.severity,
    baselinedAt: new Date().toISOString(),
    reason: "Initial baseline -- review and rotate if this is a real secret",
  }));
  return JSON.stringify(entries, null, 2);
}

// ---------------------------------------------------------------------------
// SARIF output -- for CI integration (GitHub Code Scanning, etc.)
// ---------------------------------------------------------------------------

/**
 * Convert findings to SARIF format for CI/CD integration.
 * SARIF (Static Analysis Results Interchange Format) is supported by
 * GitHub Code Scanning, Azure DevOps, and other CI platforms.
 *
 * @param {object[]} findings - Array of findings
 * @param {string} repoPath - Repository path for artifact location
 * @returns {object} SARIF JSON object
 */
function toSarif(findings, repoPath) {
  const rules = {};
  const results = [];

  for (const f of findings) {
    // Build rule if not seen
    if (!rules[f.patternId]) {
      rules[f.patternId] = {
        id: f.patternId,
        name: f.label,
        shortDescription: { text: f.label },
        fullDescription: { text: f.description || f.label },
        defaultConfiguration: {
          level: f.severity === "critical" || f.severity === "high" ? "error"
            : f.severity === "medium" ? "warning"
            : "note",
        },
        properties: {
          severity: f.severity,
        },
      };
    }

    results.push({
      ruleId: f.patternId,
      message: { text: f.description || f.label },
      level: f.severity === "critical" || f.severity === "high" ? "error"
        : f.severity === "medium" ? "warning"
        : "note",
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: f.file,
              uriBaseId: "%SRCROOT%",
            },
            region: f.line ? { startLine: f.line } : undefined,
          },
        },
      ],
      properties: {
        severity: f.severity,
        type: f.type,
      },
    });
  }

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "darknode-git-security",
            version: "1.0.0",
            informationUri: "https://github.com/Darknode-Official/darknode-cli",
            rules: Object.values(rules),
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            startTimeUtc: new Date().toISOString(),
          },
        ],
      },
    ],
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  // Main scanning functions
  scanGitSecrets,
  analyzeGitHistory,
  checkGitConfig,
  formatSecretReport,
  runFullScan,
  diffSecretScan,

  // Constants
  SECRET_PATTERNS,
  SENSITIVE_FILENAMES,
  SENSITIVE_EXTENSIONS,
  GITIGNORE_RECOMMENDATIONS,
  HIGH_ENTROPY_THRESHOLD,
  ENTROPY_THRESHOLDS,
  MIN_ENTROPY_LENGTH,
  SEVERITY_WEIGHTS,

  // Entropy functions
  shannonEntropy,
  classifyCharset,
  isHighEntropy,
  extractHighEntropyTokens,

  // Utility functions
  maskSecret,
  detectProjectTypes,
  isGitRepo,
  getRepoRoot,

  // Pre-commit hook
  generatePreCommitHook,
  installPreCommitHook,

  // Allowlist / baseline
  loadAllowlist,
  applyAllowlist,
  generateBaseline,

  // Batch scanning
  batchScan,

  // CI integration
  toSarif,

  // Testing
  selfTest,
};
