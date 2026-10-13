const assert = require("assert");
const { parseCSV } = require("./csv.js");
assert.deepStrictEqual(parseCSV('a,"line1\nline2",c\n'), [["a", "line1\nline2", "c"]]);
assert.deepStrictEqual(parseCSV("a,,c\n"), [["a", "", "c"]]);
assert.deepStrictEqual(parseCSV('"",x'), [["", "x"]]);
assert.deepStrictEqual(parseCSV("a,b"), [["a", "b"]]);
assert.deepStrictEqual(parseCSV('"a\r\nb",c\r\n'), [["a\r\nb", "c"]]);
assert.deepStrictEqual(parseCSV("a,b,\n"), [["a", "b", ""]]);
console.log("HIDDEN OK");
