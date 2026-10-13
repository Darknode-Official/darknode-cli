function parseCSV(text) {
  const rows = []; let row = [], f = "", q = false, i = 0, started = false;
  while (i < text.length) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { f += '"'; i += 2; continue; } q = false; i++; continue; }
      f += c; i++; continue;
    }
    if (c === '"') { q = true; started = true; i++; continue; }
    if (c === ",") { row.push(f); f = ""; started = true; i++; continue; }
    if (c === "\r" && text[i + 1] === "\n") { i++; continue; }
    if (c === "\n") { row.push(f); rows.push(row); row = []; f = ""; started = false; i++; continue; }
    f += c; started = true; i++;
  }
  if (started || f !== "" || row.length) { row.push(f); rows.push(row); }
  return rows;
}
module.exports = { parseCSV };
