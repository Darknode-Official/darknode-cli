const assert = require("assert");
const { inclusiveRange } = require("./range.js");
assert.deepStrictEqual(inclusiveRange(1, 3), [1, 2, 3]);
assert.deepStrictEqual(inclusiveRange(5, 5), [5]);
assert.deepStrictEqual(inclusiveRange(0, 0), [0]);
assert.deepStrictEqual(inclusiveRange(-2, 1), [-2, -1, 0, 1]);
console.log("OK");
