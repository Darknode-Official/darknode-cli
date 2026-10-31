"use strict";
// "#note" memories in .nexus/NEXUS.md.
//
//   noteText(input)          -> the note to save, or null when the input is a prompt
//   addNote(markdown, line)  -> markdown with "- line" appended to its ## Notes section

// A note is one line typed after "#". A pasted markdown document ("# Title\n..."), a shebang
// or C preprocessor line starts with "#" too, but it is something for the model to read.
function noteText(input) {
  const t = String(input == null ? "" : input).trim();
  if (t[0] !== "#" || /[\r\n]/.test(t)) return null;
  if (/^#!|^#\s*(include|define|undef|pragma|ifn?def|if|elif|else|endif|import|error|warning)\b/.test(t)) return null;
  const line = t.slice(1).trim();
  return line ? line : null;
}

function addNote(md, line) {
  const c = String(md || "");
  const lines = c.split("\n");
  let h = lines.findIndex((l) => /^##\s*Notes\s*$/i.test(l));
  if (h < 0) return c + (c && !c.endsWith("\n") ? "\n" : "") + (c ? "\n" : "") + "## Notes\n- " + line + "\n";
  // end of the Notes section: the next heading of level 1 or 2, else the end of the file
  let end = lines.length;
  for (let i = h + 1; i < lines.length; i++) if (/^#{1,2}\s/.test(lines[i])) { end = i; break; }
  let at = end; while (at > h + 1 && lines[at - 1].trim() === "") at--; // after the last note, before blank lines
  lines.splice(at, 0, "- " + line);
  const out = lines.join("\n");
  return out.endsWith("\n") ? out : out + "\n";
}

module.exports = { noteText, addNote };
