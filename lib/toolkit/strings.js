"use strict";
// `strings`-style extraction: pull runs of printable characters out of arbitrary
// input (bytes or text). The classic first move on an unknown binary/blob — surface
// URLs, keys, error messages, and format markers hiding in noise. Pure and tested.
//
// Returns [{ offset, text }]. Printable = ASCII 0x20..0x7e; runs shorter than `min`
// (default 4) are dropped.
function extractStrings(input, min = 4) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input == null ? "" : input), "utf8");
  min = Math.max(1, min | 0 || 4);
  const out = [];
  let start = -1, cur = "";
  const flush = (end) => {
    if (cur.length >= min) out.push({ offset: start, text: cur });
    start = -1; cur = "";
  };
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 0x20 && b <= 0x7e) {
      if (start < 0) start = i;
      cur += String.fromCharCode(b);
    } else {
      flush(i);
    }
  }
  flush(buf.length);
  return out;
}
module.exports = { extractStrings };
