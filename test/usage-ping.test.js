"use strict";
// usage-ping: a signed-in Nexus tells Darknode it is in use (version + OS) at most every
// 6 hours, refreshes an expired token first, and sends nothing when off or signed out.
const { pingUsage, EVERY_MS } = require("../lib/nexus/usage-ping");
let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  FAIL " + name); } };
const jwt = (exp) => "h." + Buffer.from(JSON.stringify({ exp })).toString("base64url") + ".s";
const NOW = 1.8e12;

function deps(over = {}) {
  const log = { posts: [], saved: null, state: over.state || {} };
  const d = Object.assign({
    readAuth: () => ({ uid: "u1", idToken: jwt(NOW / 1000 + 3600), refreshToken: "r1" }),
    saveAuth: (a) => { log.saved = a; },
    refresh: async () => ({ id_token: jwt(NOW / 1000 + 3600), refresh_token: "r2" }),
    post: async (url, body, headers) => { log.posts.push({ url, body, headers }); return { status: 200 }; },
    readState: () => log.state, writeState: (s) => { log.state = s; },
    version: "2.56.0", platform: "linux", env: {}, now: NOW,
  }, over);
  return { d, log };
}

(async () => {
  { const { d, log } = deps(); const r = await pingUsage(d);
    ok("sends when signed in", r === "sent");
    ok("posts to the usage route", log.posts[0].url.endsWith("/api/v1/usage"));
    ok("only product, version and OS", JSON.stringify(log.posts[0].body) === JSON.stringify({ product: "nexus", version: "2.56.0", os: "linux" }));
    ok("bearer token", /^Bearer h\./.test(log.posts[0].headers.Authorization));
    ok("remembers when", log.state.at === NOW && log.state.uid === "u1"); }
  { const { d, log } = deps({ state: { at: NOW - 3600e3, uid: "u1" } });
    ok("waits 6 hours", (await pingUsage(d)) === "skipped" && !log.posts.length); }
  { const { d } = deps({ state: { at: NOW - 3600e3, uid: "someone-else" } });
    ok("a different account sends at once", (await pingUsage(d)) === "sent"); }
  { const { d } = deps({ state: { at: NOW - EVERY_MS - 1, uid: "u1" } });
    ok("sends again after 6 hours", (await pingUsage(d)) === "sent"); }
  { const { d, log } = deps({ readAuth: () => null }); ok("signed out sends nothing", (await pingUsage(d)) === "signed-out" && !log.posts.length); }
  for (const [label, over] of [["setting off", { enabled: false }], ["NEXUS_SHARE_USAGE=0", { env: { NEXUS_SHARE_USAGE: "0" } }], ["DO_NOT_TRACK=1", { env: { DO_NOT_TRACK: "1" } }]]) {
    const { d, log } = deps(over); ok(label + " sends nothing", (await pingUsage(d)) === "off" && !log.posts.length);
  }
  { const { d, log } = deps({ readAuth: () => ({ uid: "u1", idToken: jwt(NOW / 1000 - 10), refreshToken: "r1" }) });
    ok("an expired token is refreshed first", (await pingUsage(d)) === "sent" && log.saved && log.saved.refreshToken === "r2"); }
  { const { d, log } = deps({ readAuth: () => ({ uid: "u1", idToken: jwt(NOW / 1000 - 10), refreshToken: "r1" }), refresh: async () => { throw new Error("offline"); } });
    ok("a failed refresh sends nothing", (await pingUsage(d)) === "failed" && !log.posts.length); }
  { const { d, log } = deps({ post: async () => ({ status: 500 }) });
    ok("a server error is retried next launch", (await pingUsage(d)) === "failed" && !log.state.at); }
  { const { d } = deps({ post: async () => { throw new Error("ECONNREFUSED"); } });
    ok("never throws", (await pingUsage(d)) === "failed"); }
  { const { d, log } = deps({ platform: "aix" }); await pingUsage(d); ok("unknown OS is blank", log.posts[0].body.os === ""); }
  console.log("usage-ping: " + pass + " passed, " + fail + " failed");
  if (fail) process.exit(1);
})();
