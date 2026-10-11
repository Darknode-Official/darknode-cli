"use strict";
// ================= view_image: let a multimodal model SEE a local image =================
// The agent can read text files, but a screenshot, diagram, error capture or UI mockup is
// only useful if the model can actually look at it. `view_image` takes a local image path,
// validates it, reads the bytes and returns them base64-encoded in the exact content-block
// shapes the providers understand — Anthropic `{type:"image",source:{type:"base64",...}}`
// and OpenAI/Ollama `{type:"image_url",image_url:{url:"data:<mime>;base64,..."}}`.
//
// SANDBOXING: it does NOT reinvent the path-escape guard. deviceTool passes its own `rp()`
// (resolve-inside-cwd-or-throw) in as `resolve`, exactly like batch.js is handed the agent's
// own dispatcher, so a path that escapes the project directory is rejected identically to
// every other file tool.
//
// The heavy base64 payload is returned under `__vision` (a non-transcript field, matching the
// `a.__act` internal-field convention in darknode.js). The agent loop lifts it out to forward
// the image to the model as a real vision message, then drops it so the raw bytes never bloat
// the text transcript. The visible result is just lean metadata + a one-line summary, so a
// loop that can't carry images for the active provider still degrades to a clear text note
// instead of crashing or dumping a megabyte of base64.
// Exposed agent tool (wired in darknode.js deviceTool): view_image.

const MAX_IMAGE_BYTES = 10 * 1024 * 1024; // refuse anything larger than ~10MB

// image file extension -> MIME media type. Anything not here is rejected (reported, never read).
const MIME_BY_EXT = {
  png: "image/png",
  jpg: "image/jpeg", jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  bmp: "image/bmp",
  svg: "image/svg+xml",
};

// Pure: map a path/extension to its image MIME type, or "" if it is not a supported image.
function mimeForExt(ext) {
  const e = String(ext || "").toLowerCase().replace(/^.*\./, "").replace(/^\./, "");
  return MIME_BY_EXT[e] || "";
}

// Pure: build the per-provider content blocks for one image. Both are returned so the caller
// can pick whichever matches the active provider; a loop that carries neither can ignore them.
function imageBlocks(mime, b64) {
  return {
    anthropic: { type: "image", source: { type: "base64", media_type: mime, data: b64 } },
    openai: { type: "image_url", image_url: { url: "data:" + mime + ";base64," + b64 } },
  };
}

// Wiring entry point used by deviceTool. `a` is the raw tool args, `cwd` the project root,
// `resolve` the agent's own rp() path-escape guard (injected — do not reinvent), and `opts`
// carries test seams ({ fs, maxBytes }). Returns a lean result object; the base64 image rides
// under `__vision`. Never throws: a bad path/type/size comes back as { error }.
function viewImageTool(a, cwd, resolve, opts) {
  a = a || {}; opts = opts || {};
  const fs = opts.fs || require("fs");
  const path = require("path");
  const maxBytes = opts.maxBytes || MAX_IMAGE_BYTES;
  const p = a.path || a.file || a.image || a.img;
  if (!p || typeof p !== "string") return { error: "view_image needs a 'path' to a local image file" };

  // Sandbox the path through the agent's own guard (falls back to a plain cwd-resolve only
  // when no guard was injected, e.g. a direct unit test that supplies an absolute path).
  let abs;
  try { abs = resolve ? resolve(p) : path.resolve(cwd || ".", p); }
  catch (e) { return { error: (e && e.message) || String(e) }; }

  const mime = mimeForExt(p);
  if (!mime) return { error: "unsupported image type: " + p + " — expected one of " + Object.keys(MIME_BY_EXT).join(", ") };

  let st;
  try { st = fs.statSync(abs); } catch (e) { return { error: "cannot read image: " + ((e && e.message) || e) }; }
  if (!st.isFile || !st.isFile()) return { error: p + " is not a file" };
  if (st.size > maxBytes) return { error: "image is too large: " + (st.size / 1048576).toFixed(1) + "MB exceeds the " + (maxBytes / 1048576).toFixed(0) + "MB limit" };

  let b64;
  try { b64 = fs.readFileSync(abs).toString("base64"); } catch (e) { return { error: "cannot read image: " + ((e && e.message) || e) }; }

  const name = path.basename(p);
  const blocks = imageBlocks(mime, b64);
  return {
    ok: true,
    path: p,
    media_type: mime,
    bytes: st.size,
    encoding: "base64",
    summary: "Loaded image " + name + " (" + mime + ", " + (st.size / 1024).toFixed(1) + "KB) — passed to the vision model.",
    // internal: the agent loop lifts this out to forward the image, then deletes it so the
    // base64 never lands in the text transcript. Not meant to be stringified into an observation.
    __vision: { name, mime, b64, anthropic: blocks.anthropic, openai: blocks.openai },
  };
}

module.exports = {
  viewImageTool, mimeForExt, imageBlocks,
  // exported for tests / wiring
  MIME_BY_EXT, MAX_IMAGE_BYTES,
};
