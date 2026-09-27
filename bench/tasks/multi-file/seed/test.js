const assert = require("assert");
const { total, product } = require("./calc.js");
assert.strictEqual(total([1, 2, 3]), 6);
assert.strictEqual(typeof product, "function");
assert.strictEqual(product([2, 3, 4]), 24);
assert.strictEqual(product([]), 1);
assert.strictEqual(product([5]), 5);
console.log("OK");
