function parse(v) { const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(v.trim()); if (!m) throw new Error("bad version " + v); return [+m[1], +m[2], +m[3]]; }
function cmp(a, b) { for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1; return 0; }
// Expand one comparator token into [op, version] pairs.
function expand(tok) {
  let m = /^(>=|<=|>|<|=)?\s*v?(.*)$/.exec(tok); let op = m[1] || "", rest = m[2];
  if (rest.startsWith("^") || rest.startsWith("~")) { const kind = rest[0]; const p = rest.slice(1).split(".");
    const M = +p[0], mi = p[1] === undefined || /x|\*/i.test(p[1]) ? null : +p[1], pa = p[2] === undefined || /x|\*/i.test(p[2]) ? null : +p[2];
    const lo = [M, mi ?? 0, pa ?? 0]; let hi;
    if (kind === "~") hi = mi === null ? [M + 1, 0, 0] : [M, mi + 1, 0];
    else if (M > 0 || mi === null) hi = [M + 1, 0, 0];
    else if (mi > 0 || pa === null) hi = [0, mi + 1, 0];
    else hi = [0, 0, pa + 1];
    return [[">=", lo], ["<", hi]]; }
  if (rest === "*" || rest === "" || /^[x*]$/i.test(rest)) return [];
  const p = rest.split("."); const isX = (x) => x === undefined || /^[x*]$/i.test(x);
  if (isX(p[1]) || isX(p[2])) { const M = +p[0];
    if (isX(p[1])) { const lo = [M, 0, 0], hi = [M + 1, 0, 0];
      if (op === "" || op === "=") return [[">=", lo], ["<", hi]]; if (op === ">") return [[">=", hi]]; if (op === ">=") return [[">=", lo]]; if (op === "<") return [["<", lo]]; return [["<", hi]]; }
    const mi = +p[1], lo = [M, mi, 0], hi = [M, mi + 1, 0];
    if (op === "" || op === "=") return [[">=", lo], ["<", hi]]; if (op === ">") return [[">=", hi]]; if (op === ">=") return [[">=", lo]]; if (op === "<") return [["<", lo]]; return [["<", hi]]; }
  return [[op || "=", parse(rest)]];
}
function test(v, [op, c]) { const r = cmp(v, c); return op === "=" ? r === 0 : op === ">" ? r > 0 : op === ">=" ? r >= 0 : op === "<" ? r < 0 : r <= 0; }
function satisfies(version, range) {
  const v = parse(version);
  return range.split("||").some((set) => {
    const toks = set.trim().replace(/(>=|<=|>|<|=)\s+/g, "$1").split(/\s+/).filter(Boolean);
    return toks.flatMap(expand).every((c) => test(v, c));
  });
}
module.exports = { satisfies };
