function pLimit(n) {
  let active = 0;
  const queue = [];
  function next() {
    if (!queue.length) return;
    active++;
    const { fn, resolve, reject } = queue.shift();
    fn().then((v) => { active--; resolve(v); next(); }, reject);
  }
  return (fn) => new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    if (active <= n) next();
  });
}
module.exports = { pLimit };
