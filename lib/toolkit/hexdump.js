"use strict";
// Canonical hex dump (xxd/`hexdump -C` style): 16 bytes per row with an 8-digit
// offset, two 8-byte columns, and an ASCII gutter where non-printable bytes show
// as ".". A staple for eyeballing binary/protocol data. Pure and tested.
function hexdump(input, opts = {}) {
  const width = opts.width || 16;
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input == null ? "" : input), "utf8");
  const lines = [];
  for (let off = 0; off < buf.length; off += width) {
    const slice = buf.subarray(off, off + width);
    let hex = "";
    for (let i = 0; i < width; i++) {
      hex += i < slice.length ? slice[i].toString(16).padStart(2, "0") + " " : "   ";
      if (i % 8 === 7) hex += " "; // extra space between the two 8-byte columns
    }
    let ascii = "";
    for (const b of slice) ascii += b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".";
    lines.push(off.toString(16).padStart(8, "0") + "  " + hex + "|" + ascii + "|");
  }
  // Trailing offset line, like real hexdump, so the total length is visible.
  if (buf.length) lines.push(buf.length.toString(16).padStart(8, "0"));
  else lines.push("(empty)");
  return lines.join("\n");
}
module.exports = { hexdump };
