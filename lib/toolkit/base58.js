"use strict";
// Base58 (Bitcoin alphabet) encode/decode. Shows up constantly in crypto addresses,
// keys, IPFS CIDs, and some token formats — and it deliberately drops the ambiguous
// 0/O/I/l, so it's worth having distinct from base64. Pure; encode->decode round-trips.
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const MAP = (() => { const m = Object.create(null); for (let i = 0; i < ALPHABET.length; i++) m[ALPHABET[i]] = i; return m; })();

// Encode bytes (Buffer or utf8 string) to a base58 string. Leading zero bytes are
// preserved as leading "1"s, per the Bitcoin convention.
function b58encode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input == null ? "" : input), "utf8");
  if (!buf.length) return "";
  let zeros = 0;
  while (zeros < buf.length && buf[zeros] === 0) zeros++;
  const digits = [0];
  for (let i = zeros; i < buf.length; i++) {
    let carry = buf[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]];
  return out;
}

// Decode a base58 string back to a Buffer. Returns null if any character is outside
// the alphabet.
function b58decode(str) {
  str = String(str == null ? "" : str);
  if (!str.length) return Buffer.alloc(0);
  let zeros = 0;
  while (zeros < str.length && str[zeros] === "1") zeros++;
  const bytes = [0];
  for (let i = zeros; i < str.length; i++) {
    const val = MAP[str[i]];
    if (val === undefined) return null;
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  const out = Buffer.alloc(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) out[zeros + bytes.length - 1 - i] = bytes[i];
  return out;
}
module.exports = { b58encode, b58decode, B58_ALPHABET: ALPHABET };
