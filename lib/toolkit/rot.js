"use strict";
// Caesar / ROT-N letter rotation (ROT13 is the n=13 case, its own inverse). Rotates
// A-Z and a-z by n, leaves everything else untouched. A CTF and quick-obfuscation
// staple. Pure and tested.
function rot(n, text) {
  n = ((n % 26) + 26) % 26;
  return String(text == null ? "" : text).replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= "Z" ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + n) % 26) + base);
  });
}
const rot13 = (text) => rot(13, text);
module.exports = { rot, rot13 };
