const assert = require("assert");
const { parseCSV } = require("./csv.js");
assert.deepStrictEqual(parseCSV(""), []);
assert.deepStrictEqual(parseCSV("a,b\n1,2"), [["a", "b"], ["1", "2"]]);
assert.deepStrictEqual(parseCSV("a,b\n1,2\n"), [["a", "b"], ["1", "2"]]);
assert.deepStrictEqual(parseCSV("x"), [["x"]]);
console.log("OK");
