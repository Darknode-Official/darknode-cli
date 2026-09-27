"use strict";
// ================= verify: detect a project's test / build / lint commands =================
// Devin's edge is a tight edit → run → observe → fix loop. Nexus could only do this via the
// opt-in /watch command. This module gives Nexus the first half for free: from the files at the
// repo root it infers the RIGHT command to run (the project's own test runner, then build, then
// lint / typecheck), so the agent can verify its own change instead of declaring success blind.
//
// Pure and testable: `detectProjectCommands(entries, files)` takes the list of root entry names
// and an optional { name: contentString } map (only package.json / Makefile content is used) and
// returns { test?, build?, lint?, typecheck?, source, pm }. `pickVerify` chooses the single most
// meaningful command to gate on. No filesystem access here — the caller does the walk + spawn.

function detectPackageManager(entries) {
  if (entries.includes("bun.lockb")) return "bun";
  if (entries.includes("pnpm-lock.yaml")) return "pnpm";
  if (entries.includes("yarn.lock")) return "yarn";
  return "npm";
}

function detectProjectCommands(entries, files) {
  entries = entries || []; files = files || {};
  const has = (n) => entries.includes(n);
  const out = {};
  const pm = detectPackageManager(entries);

  if (has("package.json")) {
    let pkg = {}; try { pkg = JSON.parse(files["package.json"] || "{}") || {}; } catch (_) { pkg = {}; }
    const s = pkg.scripts || {};
    // `npm test`/`yarn test`/`pnpm test`/`bun test` are the idiomatic test invocations; other
    // scripts go through `run`.
    const runScript = (name) => (pm === "npm" ? "npm run " + name : pm === "yarn" ? "yarn " + name : pm + " run " + name);
    const testInvoke = pm === "npm" ? "npm test" : pm === "bun" ? "bun test" : pm + " test";
    if (s.test) out.test = testInvoke;
    else if (s["test:unit"]) out.test = runScript("test:unit");
    else if (s["test:ci"]) out.test = runScript("test:ci");
    if (s.build) out.build = runScript("build");
    if (s.lint) out.lint = runScript("lint");
    if (s.typecheck) out.typecheck = runScript("typecheck");
    else if (s["type-check"]) out.typecheck = runScript("type-check");
    else if (s.tsc) out.typecheck = runScript("tsc");
    else if (has("tsconfig.json")) out.typecheck = (pm === "npm" ? "npx" : pm === "yarn" ? "yarn" : pm === "bun" ? "bunx" : "pnpm exec") + " tsc --noEmit";
    out.pm = pm; out.source = "package.json";
  }
  // Python
  if (!out.test && (has("pytest.ini") || has("tox.ini") || has("pyproject.toml") || has("setup.py") || has("setup.cfg") || has("conftest.py") || has("tests") || has("test"))) {
    out.test = "pytest -q"; out.source = out.source || "python";
  }
  // Rust
  if (has("Cargo.toml")) { if (!out.test) out.test = "cargo test"; if (!out.build) out.build = "cargo build"; out.source = out.source || "cargo"; }
  // Go
  if (has("go.mod")) { if (!out.test) out.test = "go test ./..."; if (!out.build) out.build = "go build ./..."; if (!out.lint) out.lint = "go vet ./..."; out.source = out.source || "go"; }
  // Ruby
  if (!out.test && has("Gemfile")) { out.test = has(".rspec") || has("spec") ? "bundle exec rspec" : "bundle exec rake test"; out.source = out.source || "ruby"; }
  // Make (only if it actually declares the target)
  const mk = files["Makefile"] || files["makefile"] || files["GNUmakefile"] || "";
  if (mk) {
    if (!out.test && /^test\s*:/m.test(mk)) out.test = "make test";
    if (!out.build && /^build\s*:/m.test(mk)) out.build = "make build";
    if (!out.lint && /^lint\s*:/m.test(mk)) out.lint = "make lint";
    out.source = out.source || "make";
  }
  // Gradle / Maven (JVM)
  if (!out.test && (has("gradlew") || has("build.gradle") || has("build.gradle.kts"))) { out.test = (has("gradlew") ? "./gradlew" : "gradle") + " test"; out.source = out.source || "gradle"; }
  if (!out.test && has("pom.xml")) { out.test = "mvn -q test"; out.build = out.build || "mvn -q package"; out.source = out.source || "maven"; }

  return out;
}

// Choose the single command that best proves a change is good: a real test suite first, then a
// build (compiles = at least not broken), then typecheck, then lint. Returns { kind, cmd } or null.
function pickVerify(cmds) {
  if (!cmds) return null;
  for (const kind of ["test", "build", "typecheck", "lint"]) if (cmds[kind]) return { kind, cmd: cmds[kind] };
  return null;
}

module.exports = { detectProjectCommands, pickVerify, detectPackageManager };
