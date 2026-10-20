"use strict";
// ============================================================================
// Tiny JSON-schema-subset validator (NSAFE-039) — zero-dep, never throws.
//
// Validates model-supplied tool arguments BEFORE execution. Malformed or
// oversized arguments are an injection and crash vector (an object where a path
// string is expected makes fs/path choke; a 10 MB string wastes memory), so the
// dispatcher rejects them early with a typed error instead of letting the tool
// fail in some deeper, noisier way.
//
// Supported keywords: type (string|number|integer|boolean|array|object),
// properties, required, additionalProperties:false, enum, maxLength, pattern,
// items (arrays), and nested properties (objects). Any other keyword is ignored
// (treated as "no constraint") so an unrecognised keyword never rejects a value.
//
// opts:
//   coerceScalars  accept a number/boolean where a `string` is declared (they
//                  stringify losslessly) — the dispatcher sets this because the
//                  built-in tool schemas type numeric fields (count, line…) as
//                  string, and a model may legitimately send a JSON number.
//   ignorePattern  skip `pattern` entirely — set for schemas sourced from
//                  untrusted MCP servers, whose regexes can be ReDoS.
//
// Returns { ok, errors: [{path, code}] } with code one of
//   type | required | enum | maxLength | pattern | unknown-property
// maxLength is tested on the live string's .length (no slice/copy), so a huge
// value costs nothing to reject.
// ============================================================================

function matchesType(v, t, opts) {
  switch (t) {
    case "string": return typeof v === "string" || (opts.coerceScalars && (typeof v === "number" || typeof v === "boolean"));
    case "number": return typeof v === "number" && !Number.isNaN(v);
    case "integer": return typeof v === "number" && Number.isInteger(v);
    case "boolean": return typeof v === "boolean";
    case "array": return Array.isArray(v);
    case "object": return v !== null && typeof v === "object" && !Array.isArray(v);
    default: return true; // unknown type keyword = no constraint
  }
}

function checkValue(v, schema, pathStr, opts, errors) {
  if (!schema || typeof schema !== "object") return;
  if (schema.type && !matchesType(v, schema.type, opts)) { errors.push({ path: pathStr, code: "type" }); return; }
  if (Array.isArray(schema.enum) && !schema.enum.some((e) => e === v)) errors.push({ path: pathStr, code: "enum" });
  if (typeof v === "string") {
    if (typeof schema.maxLength === "number" && v.length > schema.maxLength) errors.push({ path: pathStr, code: "maxLength" });
    if (schema.pattern && !opts.ignorePattern) {
      let re = null; try { re = new RegExp(schema.pattern); } catch (_) { re = null; } // a bad regex is no constraint
      if (re) { let m = false; try { m = re.test(v); } catch (_) { m = true; } if (!m) errors.push({ path: pathStr, code: "pattern" }); }
    }
  }
  if (Array.isArray(v) && schema.items && typeof schema.items === "object") {
    for (let i = 0; i < v.length; i++) checkValue(v[i], schema.items, pathStr + "[" + i + "]", opts, errors);
  }
  // Descend whenever the object schema declares ANY object-level constraint, not
  // just `properties` — otherwise a nested `{additionalProperties:false}` or
  // `{required:[...]}` with no `properties` is silently ignored. validateInto
  // defaults props to {}, so this is safe when `properties` is absent.
  if (v !== null && typeof v === "object" && !Array.isArray(v) &&
      (schema.properties || schema.required || schema.additionalProperties === false)) {
    validateInto(schema, v, pathStr, opts, errors);
  }
}

function validateInto(schema, obj, prefix, opts, errors) {
  const props = schema.properties || {};
  const required = schema.required || [];
  const at = (key) => (prefix ? prefix + "." + key : key);
  for (const key of required) {
    if (!(key in obj) || obj[key] === undefined || obj[key] === null) errors.push({ path: at(key), code: "required" });
  }
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(obj)) if (!(key in props)) errors.push({ path: at(key), code: "unknown-property" });
  }
  for (const key of Object.keys(props)) {
    if (!(key in obj) || obj[key] === undefined || obj[key] === null) continue; // absence is a `required` concern, handled above
    checkValue(obj[key], props[key], at(key), opts, errors);
  }
}

function validateArgs(schema, args, opts) {
  opts = opts || {};
  const errors = [];
  if (!schema || typeof schema !== "object") return { ok: true, errors }; // nothing to validate against
  if (args === null || typeof args !== "object" || Array.isArray(args)) { errors.push({ path: "", code: "type" }); return { ok: false, errors }; }
  validateInto(schema, args, "", opts, errors);
  return { ok: errors.length === 0, errors };
}

module.exports = { validateArgs };
