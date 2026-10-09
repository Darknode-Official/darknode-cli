function inclusiveRange(start, end) {
  const out = [];
  for (let i = start; i <= end; i++) out.push(i);
  return out;
}
module.exports = { inclusiveRange };
