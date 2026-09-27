function parseCSV(text) {
  const s = String(text);
  if (s === "") return [];
  return s.replace(/\n$/, "").split("\n").map((line) => line.split(","));
}
module.exports = { parseCSV };
