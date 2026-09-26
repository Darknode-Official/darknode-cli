"use strict";
// What the locally installed Codex CLI is actually set up with, read from ~/.codex:
// its default model (config.toml), the models its account can pick (models_cache.json,
// written by Codex itself) and how it is signed in (auth.json; only auth_mode is read,
// never the tokens). Everything is optional: on any missing or unreadable file the
// caller keeps the static defaults from engines.js.
const fs = require("fs"), path = require("path"), os = require("os");

function codexLocal(home = process.env.CODEX_HOME || path.join(os.homedir(), ".codex")) {
  const out = { model: "", models: [], authMode: "" };
  try {
    const toml = fs.readFileSync(path.join(home, "config.toml"), "utf8");
    const top = toml.split(/^\s*\[/m)[0]; // top-level keys only, not [profiles.x] model overrides
    const m = top.match(/^\s*model\s*=\s*"([^"]+)"/m); if (m) out.model = m[1];
  } catch (_) {}
  try {
    const j = JSON.parse(fs.readFileSync(path.join(home, "models_cache.json"), "utf8"));
    out.models = (Array.isArray(j.models) ? j.models : [])
      .filter((x) => x && typeof x.slug === "string" && x.visibility !== "hide")
      .sort((a, b) => (a.priority ?? 999) - (b.priority ?? 999))
      .map((x) => x.slug);
  } catch (_) {}
  try { const a = JSON.parse(fs.readFileSync(path.join(home, "auth.json"), "utf8")); if (typeof a.auth_mode === "string") out.authMode = a.auth_mode; } catch (_) {}
  return out;
}

module.exports = { codexLocal };
