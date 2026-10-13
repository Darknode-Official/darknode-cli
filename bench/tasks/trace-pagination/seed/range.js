// Half-open index range [start, end) for page p (0-based) of size s over n items.
function pageBounds(p, s, n) {
  const start = p * s;
  return [start, Math.min(start + s, n)];
}
module.exports = { pageBounds };
