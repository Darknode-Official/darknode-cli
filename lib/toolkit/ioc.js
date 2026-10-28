"use strict";
// IOC defang / refang — make indicators (URLs, domains, IPs, emails) safe to paste
// into reports and tickets by neutralizing the clickable/executable bits, and reverse
// it. Pure and reversible (defang -> refang round-trips). A staple analyst tool.
function defang(s) {
  return String(s)
    .replace(/http(s?):\/\//gi, "hxxp$1[://]") // scheme first, before dots are bracketed
    .replace(/(?<![[({])\.(?![\])}])/g, "[.]") // a dot already bracketed stays as is: defanging twice must not give [[.]]
    .replace(/(?<!\[)@(?!\])/g, "[@]");
}
function refang(s) {
  return String(s)
    .replace(/\[\.\]|\(\.\)|\{\.\}|\s?[\[({]dot[\])}]\s?/gi, ".") // evil[.]com, evil(.)com, evil[dot]com, evil [dot] com
    .replace(/\[@\]|\s?\[at\]\s?/gi, "@")
    .replace(/\[:\](?=\/\/)/g, ":")
    .replace(/hxxp(s?)\[:\/\/\]/gi, (m, t) => "http" + t.toLowerCase() + "://") // bracketed scheme
    .replace(/hxxp(s?):\/\//gi, (m, t) => "http" + t.toLowerCase() + "://");    // also tolerate plain hxxp://
}
module.exports = { defang, refang };
