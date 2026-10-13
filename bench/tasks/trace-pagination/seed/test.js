const assert = require("assert");
const { report } = require("./report.js");
const inv = (n) => Array.from({ length: n }, (_, i) => "INV-" + (i + 1));
assert.deepStrictEqual(report(inv(5)).rows, inv(5));
assert.strictEqual(report(inv(5)).pageCount, 2);
assert.deepStrictEqual(report(inv(6)).rows, inv(6));
assert.strictEqual(report(inv(6)).pageCount, 2);
console.log("OK");
