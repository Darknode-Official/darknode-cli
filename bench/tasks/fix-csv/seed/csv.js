// Parse simple CSV (no quoting) into an array of row arrays.
function parseCSV(text) {
  return String(text).split("\n").map((line) => line.split(",")); // BUG: "" -> [[""]]; trailing "\n" -> extra [""]
}
module.exports = { parseCSV };
