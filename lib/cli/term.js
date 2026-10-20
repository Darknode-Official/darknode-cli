"use strict";
// ============================================================================
// Terminal mode registry — so every mode the TUI turns on (alt-screen, raw,
// bracketed paste, mouse, focus reporting, hidden cursor, window title) is
// always turned back off, even on a hard crash. A TUI that exits leaving echo
// off, the cursor hidden, or paste mode on is an availability bug and sometimes
// a safety one (a typed password echoing into the next shell).
//
// The registry records, per mode, the bytes that enable it and the bytes that
// disable it. teardown() writes the disable bytes in REVERSE registration order
// (so the alt-screen, registered first, is left last) and is idempotent — a
// second call writes nothing. The hard-crash path writes synchronously with
// fs.writeSync so the bytes reach the terminal before the process dies; a
// normal exit can use the same teardown.
//
// Pure except for the injected writer (default fs.writeSync to a fd). No deps.
// ============================================================================

const fs = require("fs");

// createRegistry({ fd?, write? }) -> registry.
//   fd:    file descriptor the default writer targets (default 1 / stdout).
//   write: inject a writer (tests); receives the disable string.
function createRegistry(opts) {
  opts = opts || {};
  const fd = opts.fd == null ? 1 : opts.fd;
  const write = typeof opts.write === "function"
    ? opts.write
    : (s) => { try { fs.writeSync(fd, s); } catch (_) {} };
  const modes = []; // [{ name, enable, disable }] in registration order
  let tornDown = false;

  return {
    // Record a mode. Re-registering a name replaces it and moves it to the top
    // of the stack (so it tears down first). Returns the enable bytes for the
    // caller to write. Registering re-arms teardown.
    register(name, enable, disable) {
      const i = modes.findIndex((m) => m.name === name);
      if (i >= 0) modes.splice(i, 1);
      modes.push({ name: String(name), enable: enable == null ? "" : String(enable), disable: disable == null ? "" : String(disable) });
      tornDown = false;
      return enable == null ? "" : String(enable);
    },
    // Enable bytes for all modes, in registration order (for re-entry).
    enableString() { return modes.map((m) => m.enable).join(""); },
    // Disable bytes for all modes, in reverse registration order (no state change).
    disableString() { let s = ""; for (let i = modes.length - 1; i >= 0; i--) s += modes[i].disable; return s; },
    // Write every disable string in reverse order, once. Each write is isolated
    // so one failure does not skip the rest. Idempotent. Returns true if it ran.
    teardown() {
      if (tornDown) return false;
      tornDown = true;
      for (let i = modes.length - 1; i >= 0; i--) { try { if (modes[i].disable) write(modes[i].disable); } catch (_) {} }
      return true;
    },
    // Let a fresh enable re-arm teardown without re-registering every mode.
    rearm() { tornDown = false; },
    get size() { return modes.length; },
    get isTornDown() { return tornDown; },
  };
}

module.exports = { createRegistry };
