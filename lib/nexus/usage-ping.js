"use strict";
// usage-ping — tells Darknode that a signed-in person uses Nexus, so the site owner's admin
// panel can list Nexus users (with version and OS). Sent only when a Darknode sign-in exists
// (/login), at most every 6 hours, never with prompts, files, paths or project names.
// Off with /shareusage off (saved in ~/.nexus/settings.json), NEXUS_SHARE_USAGE=0 or
// DO_NOT_TRACK=1. Never throws; the TUI fires it and forgets it.

const DEFAULT_API = "https://darknode-proxy.darknode-ai.workers.dev";
const EVERY_MS = 6 * 3600e3;
const OSES = new Set(["linux", "darwin", "win32"]);

const claims = (t) => { try { return JSON.parse(Buffer.from(String(t).split(".")[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")); } catch (_) { return null; } };

// deps: { readAuth, saveAuth, refresh(refreshToken) -> { id_token, refresh_token }, post(url, body, headers) -> { status },
//         readState() -> { at }, writeState(s), version, platform, env, enabled, now, api }
// -> "sent" | "off" | "signed-out" | "skipped" | "failed"
async function pingUsage(deps) {
  try {
    const env = deps.env || {}, now = deps.now || Date.now();
    if (deps.enabled === false || /^(0|false|off|no)$/i.test(String(env.NEXUS_SHARE_USAGE || "").trim()) || /^(1|true)$/i.test(String(env.DO_NOT_TRACK || "").trim())) return "off";
    const a = deps.readAuth();
    if (!a || !a.idToken || !a.uid) return "signed-out";
    const st = deps.readState() || {};
    if (st.at && now - st.at < EVERY_MS && st.uid === a.uid) return "skipped";
    let tok = a.idToken; const c = claims(tok);
    if (!c || !c.exp || c.exp * 1000 - now < 120000) {
      const r = await deps.refresh(a.refreshToken).catch(() => null);
      if (!r || !r.id_token) return "failed";
      tok = r.id_token;
      deps.saveAuth(Object.assign({}, a, { idToken: tok, refreshToken: r.refresh_token || a.refreshToken, ts: now }));
    }
    const body = { product: "nexus", version: String(deps.version || ""), os: OSES.has(deps.platform) ? deps.platform : "" };
    const r = await deps.post((deps.api || env.DARKNODE_API || DEFAULT_API) + "/api/v1/usage", body, { Authorization: "Bearer " + tok, "Content-Type": "application/json" });
    if (!r || r.status < 200 || r.status >= 300) return "failed";
    deps.writeState({ at: now, uid: a.uid });
    return "sent";
  } catch (_) { return "failed"; }
}

module.exports = { pingUsage, EVERY_MS };
