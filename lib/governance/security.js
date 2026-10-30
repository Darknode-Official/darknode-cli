"use strict";
// Security utilities — pure, dependency-free, unit-tested (test/run.js).
//  - scanSecrets:    detect credentials in text (block/flag before writing)
//  - maskSecrets:    redact them before text is sent to a cloud engine
//  - classifyDanger: Darknode preflight — rate a shell command's destructive intent
//  - compactOutput:  head+tail trim of long tool output to save tokens

// scheme://user:password@host - a real password, not a doc placeholder (password, changeme, ${VAR}, <pw>, ***)
const CONN_PW = /\b([a-z][a-z0-9+.-]{1,20}:\/\/[^\s:@/'"]*:)(?!(?:password|pass|passwd|pwd|secret|changeme|example|xxx+|\*+|<[^>]*>|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|%[^@]*)@)([^\s@/'"]{3,})@/i;
// Unquoted YAML / INI / header secret (password: x, api_key = x, X-Api-Key: x). Code reads like this
// too (token = req.headers.token), so the value must hold a digit or symbol and must not be a call,
// a $VAR, a dotted identifier path, a keyword or a plain number; a key naming a URL/path/file
// (TOKEN_URL, private_key_path) holds a location, not a secret. Same rule as redact.js kv-secret.
const KV_SECRET = /^(\s*-?\s*[A-Za-z0-9_.-]*?(?:password|passwd|client[_-]?secret|secret(?:[_-]?key)?|token|api[_-]?key|access[_-]?key|private[_-]?key)[A-Za-z0-9_-]*(?<![_.-](?:url|uri|path|file|dir|endpoint))\s*[:=]\s*)(?![A-Za-z_$][\w$]*(?:\.[\w$]+)+\s*$)(?!(?:true|false|null|none|nil|yes|no|\d+)\s*$)(?=[^\s]*[0-9!@%^&*+=~?\/-])[^\s'"#$(){}\[\]<>,;`][^\s'"#(){}\[\]<>,;`]{5,}\s*$/im;
function scanSecrets(text) {
  const s = String(text || ""), pats = [
    [/\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/, "AWS access key id"],
    [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----/, "private key"], // any label (ENCRYPTED, PGP … BLOCK), as maskSecrets
    [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/, "GitHub token"],
    [/\bgithub_pat_[A-Za-z0-9_]{22,}\b/, "GitHub fine-grained PAT"],
    [/\bxox[baprse]-[A-Za-z0-9-]{10,}\b|\bxapp-\d-[A-Za-z0-9-]{10,}\b/, "Slack token"],
    [/\bAuthorization:\s*Basic\s+[A-Za-z0-9+\/]{8,}={0,2}/i, "Basic auth credentials"],
    [/\bsk-[A-Za-z0-9_-]{20,}/, "OpenAI-style API key"], // allow -/_ so sk-proj-… and sk-ant-api03-… (the current formats) are caught, not just the legacy sk-… body
    [/\bAIza[0-9A-Za-z_-]{35}\b/, "Google API key"],
    [/\b[rs]k_live_[0-9A-Za-z]{20,}\b/, "Stripe live key"],
    [/\bglpat-[0-9A-Za-z_-]{20,}\b/, "GitLab token"],
    [/\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b/, "SendGrid API key"],
    [/\bnpm_[A-Za-z0-9]{36}\b/, "npm token"],
    [/\b_authToken\s*=\s*(?!\$\{)[^\s'"]{20,}/, "npm token"], // .npmrc: legacy (UUID) tokens have no npm_ prefix
    [/\bhf_[A-Za-z0-9]{30,}\b/, "Hugging Face token"],
    [/\bsk_test_[0-9A-Za-z]{20,}\b/, "Stripe test key"],
    [/\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{30,}/, "PyPI token"],
    [/\bdo[opr]_v1_[a-f0-9]{64}\b/, "DigitalOcean token"],
    [/\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/, "Shopify token"],
    [/\bGOCSPX-[A-Za-z0-9_-]{20,}/, "Google OAuth client secret"],
    [/\bya29\.[0-9A-Za-z_-]{20,}/, "Google OAuth token"],
    [/\bgl(?:sa|c)_[A-Za-z0-9_=+\/-]{32,}/, "Grafana token"],
    [/\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_\/-]{20,}/, "Slack webhook URL"],
    [/\bAccountKey=[A-Za-z0-9+\/]{40,}={0,2}/, "Azure storage key"],
    [CONN_PW, "password in a connection string"],
    [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/, "JWT"],
    [/(?:password|passwd|client[_-]?secret|secret(?:[_-]?access)?(?:[_-]?key)?|api[_-]?key|(?:access|session|refresh|auth)[_-]?token)['"]?\s*[:=]\s*(['"])(?!\[redacted|\$\{[^'"\n]*\}\1)(?:(?!\1)[^\n]){6,}?\1/i, "hardcoded credential"], // not maskSecrets' own placeholder, nor a "${VAR}" reference
    [KV_SECRET, "hardcoded credential"],
  ];
  const hits = []; for (const [re, name] of pats) if (re.test(s)) hits.push(name);
  return [...new Set(hits)];
}
// Mask secrets before text is sent to a cloud engine (privacy layer).
function maskSecrets(text) {
  return String(text)
    // END marker optional / anchored to EOF: scanSecrets flags a key on its
    // BEGIN line alone, and read_file output is hard-capped, so a key can arrive
    // with its body but no END line — mask it anyway rather than leak it.
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|$)/g, "[redacted:private-key]")
    .replace(/\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g, "[redacted:aws-key]")
    .replace(/\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, "[redacted:github-token]")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{22,}\b/g, "[redacted:github-token]")
    .replace(/\bxox[baprse]-[A-Za-z0-9-]{10,}\b|\bxapp-\d-[A-Za-z0-9-]{10,}\b/g, "[redacted:slack-token]")
    .replace(/(\bAuthorization:\s*Basic\s+)[A-Za-z0-9+\/]{8,}={0,2}/gi, "$1[redacted:basic-auth]")
    .replace(/\bsk-[A-Za-z0-9_-]{20,}/g, "[redacted:api-key]")
    .replace(/\bAIza[0-9A-Za-z_-]{35}\b/g, "[redacted:google-key]")
    .replace(/\b[rs]k_live_[0-9A-Za-z]{20,}\b/g, "[redacted:stripe-key]")
    .replace(/\bglpat-[0-9A-Za-z_-]{20,}\b/g, "[redacted:gitlab-token]")
    .replace(/\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}\b/g, "[redacted:sendgrid-key]")
    .replace(/\bnpm_[A-Za-z0-9]{36}\b/g, "[redacted:npm-token]")
    .replace(/(\b_authToken\s*=\s*)(?!\$\{|\[redacted)[^\s'"]{20,}/g, "$1[redacted:npm-token]")
    .replace(new RegExp(CONN_PW.source, "g"), (m, pre, pw) => pre + "[redacted:userinfo]@")
    .replace(/\bhf_[A-Za-z0-9]{30,}\b/g, "[redacted:hf-token]")
    .replace(/\b[rs]k_test_[0-9A-Za-z]{20,}\b/g, "[redacted:stripe-key]")
    .replace(/\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{30,}/g, "[redacted:pypi-token]")
    .replace(/\bdo[opr]_v1_[a-f0-9]{64}\b/g, "[redacted:digitalocean-token]")
    .replace(/\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g, "[redacted:shopify-token]")
    .replace(/\bGOCSPX-[A-Za-z0-9_-]{20,}/g, "[redacted:google-oauth]")
    .replace(/\bya29\.[0-9A-Za-z_-]{20,}/g, "[redacted:google-oauth]")
    .replace(/\bgl(?:sa|c)_[A-Za-z0-9_=+\/-]{32,}/g, "[redacted:grafana-token]")
    .replace(/\bhttps:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9_\/-]{20,}/g, "[redacted:slack-webhook]")
    .replace(/(\bBearer\s+)[A-Za-z0-9._~+\/-]{20,}=*/gi, "$1[redacted:bearer]")
    .replace(/(\bAccountKey=)[A-Za-z0-9+\/]{40,}={0,2}/g, "$1[redacted:azure-key]")
    .replace(/^(\s*(?:export\s+)?[A-Za-z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)[A-Za-z0-9_]*=)[^\s'"#$][^\s'"#]{5,}/gim, "$1[redacted:env-secret]")
    .replace(/^(\s*aws_(?:secret_access_key|session_token)\s*=\s*)\S{16,}/gim, "$1[redacted:aws-credentials]") // ~/.aws/credentials
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\b/g, "[redacted:jwt]")
    // Generic hardcoded credential (password:/secret:/api_key=…"value"): redact the
    // quoted value so a secret scanSecrets would flag can't reach a cloud engine.
    // The placeholder contains a space so it is not itself matched as a credential.
    .replace(/((?:password|passwd|client[_-]?secret|secret(?:[_-]?access)?(?:[_-]?key)?|api[_-]?key|(?:access|session|refresh|auth)[_-]?token)['"]?\s*[:=]\s*)(['"])(?!\[redacted)(?:(?!\2)[^\n]){6,}?\2/ig, "$1$2[redacted credential]$2") // a quoted value may hold spaces
    .replace(new RegExp(KV_SECRET.source, "gim"), "$1[redacted credential]");
}
// Darknode preflight — classify a shell command's destructive intent.
function classifyDanger(cmd) {
  // A backslash-newline is a line continuation (the shell joins the lines), and git's global
  // options (-C dir, -c k=v, --no-pager) sit between "git" and the subcommand the rules match.
  const c0 = String(cmd || "").replace(/\\\r?\n/g, " ").replace(/\bgit((?:\s+(?:-[Cc]\s+\S+|--[\w-]+(?:=\S+)?|-[pP]))+)(?=\s)/g, "git");
  // The shell strips quotes around a word before running it, so "rm" -rf ~ and r""m -rf ~ run
  // rm -rf ~. Classify that unquoted form too: quotes around (or inside) a plain word are
  // removed; quoted text with spaces is left alone. (\rm already works: \b matches after "\".)
  const unq = c0.replace(/(['"])([^'"\s;&|<>()`$]*)\1/g, "$2").replace(/(\w)\\(?=\w)/g, "$1"); // r\m runs rm too
  const r = classifyDangerRaw(c0), u = unq === c0 ? r : classifyDangerRaw(unq);
  const rank = { ok: 0, warn: 1, block: 2 };
  return rank[u.level] > rank[r.level] ? u : r;
}

function classifyDangerRaw(c) {
  const block = [
    [/:\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, "fork bomb"],
    [/\brm\s+(-\S*\s+)*['"]?(\/(\s|$|['"`;&|)}])|\/\*|(~|\$\{?HOME\b[^}\s\/'"]*\}?)['"]?\/?\*?['"]?(\s|$|['"`;&|)}])|\/(etc|usr|var|boot|bin|lib|sys|dev|opt|root)\b|\/(home|Users)(\/[^\s/'"`;&|)}]+)?\/?(\s|$|['"`;&|)}]))/i, "rm on a system/home path"],
    [/\bfind\s+['"]?(\/|~|\$\{?HOME\}?)\/?['"]?\s[^\n]*(-delete\b|-exec\s+rm\b)/i, "find deletes across a system/home path"],
    [/\bmkfs(\.\w+)?\b|\bdd\b[^\n]*\bof=\/dev\/|\b(wipefs|shred)\b|>\s*\/dev\/(sd|nvme|hd|mmcblk)/i, "writes/formats a raw disk"],
    [/\bgit\s+reset\s+--hard\b/i, "git reset --hard discards uncommitted work"],
    [/\bgit\s+push\b[^\n]*(--force(-with-lease)?\b|\s-[a-z]*f[a-z]*\b|\s\+\S)/i, "git force-push"],
    [/\bgit\s+push\b[^\n]*(--delete\b|--mirror\b|\s-d\b|\s:[^\s:])/i, "git push deletes remote branches/tags"],
    [/\bgit\s+clean\s+(?=(?:[^\n;&|]*\s)?(?:-[a-z]*f|--force\b))(?=(?:[^\n;&|]*\s)?-[a-z]*d)/i, "git clean -fd deletes untracked files"], // -fd, -f -d, --force -d
    [/\bchmod\s+(?=(?:[^\n]*\s)?(?:-[a-z]*R|--recursive\b))(-\S+\s+)*0*777\s+(-\S+\s+)*['"]?\//i, "chmod -R 777 on a root path"],
    [/\b(curl|wget|fetch)\b[^\n]*\|\s*(sudo\s+(-\S+\s+)*)?(sh|bash|zsh|dash|ksh|python\d?|perl|ruby|node|nodejs|php|Rscript|pwsh)\b/i, "pipe-to-shell of a downloaded script"],
    [/\b(sh|bash|zsh|dash|ksh|source|\.)\s[^\n]*(<\(|\$\(|`)\s*(curl|wget)\b/i, "runs a downloaded script"],
    [/\b(base64\s+(-\S*d\b|--decode\b)|xxd\s+(-\S+\s+)*-r|openssl\s+(base64|enc)\b[^\n|]*\s-d\b)[^\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash|ksh)\b/i, "pipes decoded (hidden) text into a shell"],
    [/\b(shutdown|reboot|halt|poweroff)\b|\binit\s+0\b/i, "powers off / reboots the machine"],
    [/\bDROP\s+(TABLE|DATABASE)\b|\bTRUNCATE\s+TABLE\b/i, "destructive SQL (DROP/TRUNCATE)"],
    [/(?:^|[^>&\d])>\|?\s*['"]?\/(etc|boot|usr|bin|sbin|lib|lib64)\/|\b(truncate|tee)\b[^\n|]*\s['"]?\/(etc|boot|usr|bin|sbin|lib|lib64)\//i, "overwrites a system file"],
    [/\bmv\s+(-\S+\s+)*['"]?(\/(etc|usr|var|boot|bin|sbin|lib|lib64|home|root|opt)?|~|\$\{?HOME\}?)\/?['"]?\s/i, "moves the root, home or a system directory"],
    [/\bkill\s+(-\S+\s+)*(-1|1)\s*(?:$|[;&|])/, "kills every process or init"],
  ];
  for (const [re, why] of block) if (re.test(c)) return { level: "block", why };
  const warn = [
    [/(^|\s)sudo\s/i, "runs as root (sudo)"],
    [/\bgit\s+checkout\s+(--\s|\.\s*$|\.\s)/i, "git checkout discards local changes"],
    [/\brm\s+-\S*r\S*f|\brm\s+-\S*f\S*r|\brm\s+-\S*r\b|\brm\s+(-\S+\s+)*--recursive\b/i, "recursive (force) delete"],
    [/\b(killall|pkill)\b/i, "kills processes by name"],
    [/\bgit\s+(restore\s+(?!--staged\b)\S|checkout\s+-f\b|stash\s+(clear|drop)\b|branch\s+-D\b)/, "git discards local changes, a stash or a branch"],
    [/\bfind\b[^\n]*\s(-delete|-exec\s+rm)\b/i, "find deletes the files it matches"],
    [/\bnpm\s+publish\b|\bgit\s+push\b/i, "publishes / pushes"],
    // a write (key + value, or --unset/--add/--edit…) to config shared by every repo; a bare key or --get only reads
    [/\bgit\s+config\s+(?:\S+\s+)*?--(?:global|system)\b[^\n;&|]*?\s(?:--(?:unset|unset-all|add|replace-all|edit|remove-section|rename-section)\b|-e\b|[A-Za-z][\w.-]*\s+(?:'[^']*'|"[^"]*"|[^\s;&|-]))/i, "changes your global git config, outside this project"],
  ];
  for (const [re, why] of warn) if (re.test(c)) return { level: "warn", why };
  return { level: "ok" };
}
function compactOutput(text, max) { text = String(text || ""); max = max || 4000; if (text.length <= max) return text; const head = text.slice(0, Math.floor(max * 0.6)); const tail = text.slice(-Math.max(1, Math.floor(max * 0.3))); return head + "\n… [" + (text.length - head.length - tail.length) + " chars trimmed to save tokens] …\n" + tail; }

// --- Inline-credential redaction for command lines (NSAFE-064) ------------
// scanSecrets/maskSecrets catch token-SHAPED values, but credentials passed on
// a command line hide behind a flag: `mysql -pHunter2`, `curl -u user:pass`,
// `--token=…`, an Authorization header, or URL userinfo. Those lines persist in
// the audit log and in on-disk history and are world-readable via `ps`. These
// two helpers strip the value while keeping the command readable. They never
// rewrite the command that actually runs — the real secret is still in argv, so
// the verdict should suggest an env/stdin alternative (saferAlternative).

// Catalog of credential-bearing flags, keyed by command ("*" = any). Used by
// redactArgv for callers that already hold a tokenized argv.
const CRED_FLAGS = Object.freeze([
  { cmd: "mysql", flag: "-p", kind: "attached" },
  { cmd: "mysqldump", flag: "-p", kind: "attached" },
  { cmd: "mariadb", flag: "-p", kind: "attached" },
  { cmd: "mysqladmin", flag: "-p", kind: "attached" },
  { cmd: "curl", flag: "-u", kind: "userpass" },
  { cmd: "curl", flag: "--user", kind: "userpass" },
  { cmd: "wget", flag: "--user", kind: "userpass" },
  { cmd: "*", flag: "--password", kind: "value" },
  { cmd: "*", flag: "--passwd", kind: "value" },
  { cmd: "*", flag: "--token", kind: "value" },
  { cmd: "*", flag: "--secret", kind: "value" },
  { cmd: "*", flag: "--api-key", kind: "value" },
  { cmd: "*", flag: "--access-token", kind: "value" },
  { cmd: "*", flag: "--auth-token", kind: "value" },
  { cmd: "*", flag: "--client-secret", kind: "value" },
].map(Object.freeze));
const _base = (p) => String(p || "").split(/[\\/]/).pop();
// Redact credential values in a tokenized argv. Returns a new argv plus a count.
// "attached" -pVALUE, "userpass" next token user:pass (password only), "value"
// --flag=VALUE or --flag VALUE.
function redactArgv(argv) {
  const out = Array.isArray(argv) ? argv.slice() : [];
  const cmd = _base(out[0]);
  let redactions = 0;
  const flags = CRED_FLAGS.filter((f) => f.cmd === "*" || f.cmd === cmd);
  for (let i = 1; i < out.length; i++) {
    const tok = String(out[i] == null ? "" : out[i]);
    for (const f of flags) {
      if (f.kind === "attached") {
        if (tok.length > f.flag.length && tok.startsWith(f.flag) && tok[f.flag.length] !== "=") { out[i] = f.flag + "[redacted:password]"; redactions++; break; }
      } else if (f.kind === "userpass") {
        if (tok === f.flag && i + 1 < out.length) { const nx = String(out[i + 1]); const c = nx.indexOf(":"); out[i + 1] = c >= 0 ? nx.slice(0, c + 1) + "[redacted:password]" : "[redacted:credential]"; redactions++; i++; break; }
      } else { // value
        if (tok === f.flag && i + 1 < out.length) { out[i + 1] = "[redacted:credential]"; redactions++; i++; break; }
        if (tok.startsWith(f.flag + "=")) { out[i] = f.flag + "=[redacted:credential]"; redactions++; break; }
      }
    }
  }
  return { argv: out, redactions };
}
// String-level redaction for a whole command line (what the audit log and
// on-disk history store). Handles URL userinfo and Authorization headers that a
// whitespace split would break, the flag forms above, then token-shaped secrets.
function redactCommandSecrets(cmd) {
  let s = String(cmd == null ? "" : cmd);
  // URL userinfo: scheme://user:password@host — redact the password.
  s = s.replace(/\b([a-z][a-z0-9+.-]*:\/\/[^\s/:@]+):([^\s/@]+)@/gi, "$1:[redacted:userinfo]@");
  // Authorization: Bearer|Basic|Token|Digest <value>  (quoted or bare).
  s = s.replace(/\b(Authorization\s*:\s*(?:Bearer|Basic|Token|Digest)\s+)([^\s"']+)/gi, "$1[redacted:auth-header]");
  // --flag=VALUE credential flags.
  s = s.replace(/(--?(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|bearer)=)(\S+)/gi, "$1[redacted:credential]");
  // --flag VALUE (next token) credential flags.
  s = s.replace(/(--?(?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s+)(?!-)(["']?)([^\s"']+)\2/gi, "$1[redacted:credential]");
  // curl/wget basic auth: -u user:pass / --user user:pass — redact the password.
  s = s.replace(/((?:^|\s)(?:-u|--user)\s+)(["']?)([^\s"':]+):([^\s"']+)\2/gi, "$1$2$3:[redacted:password]$2");
  // mysql-family attached password: -pSECRET (only when a mysql-family tool runs).
  if (/\b(mysql|mysqldump|mariadb|mysqladmin)\b/.test(s)) s = s.replace(/(\s-p)([^\s"'=-][^\s"']*)/g, "$1[redacted:password]");
  return maskSecrets(s); // token-shaped secrets anywhere (AKIA…, ghp_…, sk-…, JWTs, keys)
}

module.exports = { CONN_PW, scanSecrets, maskSecrets, classifyDanger, compactOutput, CRED_FLAGS, redactArgv, redactCommandSecrets };
