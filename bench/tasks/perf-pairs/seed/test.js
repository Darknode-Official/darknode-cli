const assert = require("assert");
const { countPairs } = require("./pairs.js");
assert.strictEqual(countPairs([1, 2, 3, 4], 5), 2);
assert.strictEqual(countPairs([2, 2, 2], 4), 3);
let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) % 1000;
const big = Array.from({ length: 200000 }, rnd);
const t = Date.now();
const got = countPairs(big, 999);
assert.ok(Date.now() - t < 3000, "too slow: " + (Date.now() - t) + "ms");
const freq = new Array(1000).fill(0); big.forEach((x) => freq[x]++);
let want = 0; for (let a = 0; a < 1000; a++) { const b = 999 - a; if (b > a && b < 1000) want += freq[a] * freq[b]; }
assert.strictEqual(got, want);
console.log("OK");
