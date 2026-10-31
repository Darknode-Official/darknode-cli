"use strict";
// @path mentions: inline a file's contents into the prompt sent to the engine.
//
//   expandAts(text, { cwd, max, onRead, fs }) -> text with each readable @file inlined
//
// A mention that is not a readable regular text file is left exactly as typed.
const path = require("path");

const TRAIL = /[.,;:!?)\]}'"]+$/; // prose punctuation after a mention: "fix @src/app.js." / "(see @a.js)"

// Read at most `max` chars of a regular file. Never reads a device, FIFO or directory
// (readFileSync on /dev/zero never returns), and refuses binary content.
function readHead(fsm, abs, max) {
  const st = fsm.statSync(abs);
  if (!st.isFile()) return null;
  const want = Math.min(st.size, max * 4 + 4); // utf8: up to 4 bytes per char
  const buf = Buffer.alloc(want);
  const fd = fsm.openSync(abs, "r");
  let n = 0; try { n = fsm.readSync(fd, buf, 0, want, 0); } finally { fsm.closeSync(fd); }
  const head = buf.subarray(0, n);
  if (head.includes(0)) return null; // a NUL byte: binary, not something to paste into a prompt
  const text = head.toString("utf8");
  const whole = st.size <= n && text.length <= max;
  return { text: text.length > max ? text.slice(0, max).replace(/[\uD800-\uDBFF]$/, "") : text, whole, size: st.size };
}

function expandAts(text, opts) {
  const o = opts || {}, fsm = o.fs || require("fs"), cwd = o.cwd || process.cwd(), max = o.max || 6000;
  const attach = (f) => {
    const abs = path.resolve(cwd, f);
    let r; try { r = readHead(fsm, abs, max); } catch (_) { return null; }
    if (!r) return null;
    if (r.whole && typeof o.onRead === "function") { try { o.onRead(abs, r.text); } catch (_) {} }
    const note = r.whole ? "" : "\n…[truncated: only the first " + r.text.length + " chars of " + f + " (" + r.size + " bytes) are shown — read the file for the rest before editing it]";
    return "\n\n--- " + f + " ---\n" + r.text + note + "\n--- end " + f + " ---\n";
  };
  return String(text).replace(/(^|[\s([{'])@(?:"([^"]+)"|(\S+))/g, (m, pre, fq, fu) => {
    if (fq) { const b = attach(fq); return b ? pre + b : m; }
    let b = attach(fu); if (b) return pre + b;
    const t = fu.match(TRAIL); if (!t || t[0].length === fu.length) return m;
    b = attach(fu.slice(0, -t[0].length));
    return b ? pre + b + t[0] : m; // keep the punctuation after the block so the sentence still reads
  });
}

module.exports = { expandAts, readHead };
