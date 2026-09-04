"use strict";
// Repeating-key XOR — the workhorse of CTF crypto and light obfuscation. XOR the
// data against a cyclically repeated key. Self-inverse: applying the same key to the
// output recovers the input. Pure and tested.
//
// xorBytes(keyBuf, dataBuf) -> Buffer. The string helpers below take a text key and
// emit/consume hex so the (often non-printable) result is safe to display and paste.
function xorBytes(keyBuf, dataBuf) {
  if (!keyBuf || !keyBuf.length) return Buffer.from(dataBuf); // empty key = identity
  const out = Buffer.alloc(dataBuf.length);
  for (let i = 0; i < dataBuf.length; i++) out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length];
  return out;
}
// Encrypt text (or a Buffer) with a text key; returns lowercase hex.
function xorEncryptHex(key, data) {
  const k = Buffer.from(String(key == null ? "" : key), "utf8");
  const d = Buffer.isBuffer(data) ? data : Buffer.from(String(data == null ? "" : data), "utf8");
  return xorBytes(k, d).toString("hex");
}
// Decrypt hex produced by xorEncryptHex back to a utf8 string. Returns null if the
// input isn't valid hex.
function xorDecryptHex(key, hex) {
  const clean = String(hex == null ? "" : hex).replace(/\s+/g, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) return null;
  const k = Buffer.from(String(key == null ? "" : key), "utf8");
  return xorBytes(k, Buffer.from(clean, "hex")).toString("utf8");
}
module.exports = { xorBytes, xorEncryptHex, xorDecryptHex };
