"use strict";
// Luhn (mod-10) checksum — the check-digit algorithm behind credit-card numbers,
// IMEIs, and many national IDs. Useful for validating/handling such values in test
// data and spotting well-formed-but-fake numbers. Pure and tested.
//
// Digits-only; separators (spaces/dashes) are ignored so "4539 1488 0343 6467" works.
function digitsOf(s) {
  return String(s == null ? "" : s).replace(/[\s-]/g, "");
}
function luhnSum(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum;
}
// True if `num` is a valid Luhn number. Returns false for non-digit or empty input.
function luhnValid(num) {
  const d = digitsOf(num);
  if (!d || !/^\d+$/.test(d)) return false;
  return luhnSum(d) % 10 === 0;
}
// Given a partial number (without the final check digit), return the check digit
// that makes the whole number Luhn-valid. Returns null on non-digit input.
function luhnCheckDigit(partial) {
  const d = digitsOf(partial);
  if (!d || !/^\d+$/.test(d)) return null;
  // The check digit sits in the "alt" position; compute the sum as if a 0 were
  // appended, then the digit that brings the total to a multiple of 10.
  const sum = luhnSum(d + "0");
  return (10 - (sum % 10)) % 10;
}
module.exports = { luhnValid, luhnCheckDigit };
