export class Real {
  constructor(v) { this.v = v; }
}

export class UID {
  constructor(v) { this.v = v; }
}

const APPLE_EPOCH_MS = 978307200000;

function readUInt(dv, pos, size) {
  let n = 0;
  for (let i = 0; i < size; i++) n = n * 256 + dv.getUint8(pos + i);
  return n;
}

function readBigInt(dv, pos, size) {
  let n = 0n;
  for (let i = 0; i < size; i++) n = (n << 8n) | BigInt(dv.getUint8(pos + i));
  return n;
}

function parseBinary(u8) {
  const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const t = u8.length - 32;
  const offSize = u8[t + 6];
  const refSize = u8[t + 7];
  const count = readUInt(dv, t + 8, 8);
  const top = readUInt(dv, t + 16, 8);
  const tableOff = readUInt(dv, t + 24, 8);
  const offsets = new Array(count);
  for (let i = 0; i < count; i++) offsets[i] = readUInt(dv, tableOff + i * offSize, offSize);
  const cache = new Map();

  function readLen(p, lo) {
    if (lo !== 15) return { len: lo, start: p + 1 };
    const m = u8[p + 1];
    const nb = 1 << (m & 15);
    return { len: readUInt(dv, p + 2, nb), start: p + 2 + nb };
  }

  function obj(i) {
    if (cache.has(i)) return cache.get(i);
    const p = offsets[i];
    const marker = u8[p];
    const hi = marker >> 4;
    const lo = marker & 15;
    let v;
    if (marker === 0x00) v = null;
    else if (marker === 0x08) v = false;
    else if (marker === 0x09) v = true;
    else if (hi === 1) {
      const n = 1 << lo;
      if (n <= 4) v = readUInt(dv, p + 1, n);
      else {
        let b = readBigInt(dv, p + 1, Math.min(n, 8));
        if (n === 8) b = BigInt.asIntN(64, b);
        v = b >= BigInt(Number.MIN_SAFE_INTEGER) && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : b;
      }
    } else if (hi === 2) {
      v = new Real(lo === 2 ? dv.getFloat32(p + 1, false) : dv.getFloat64(p + 1, false));
    } else if (marker === 0x33) {
      v = new Date(dv.getFloat64(p + 1, false) * 1000 + APPLE_EPOCH_MS);
    } else if (hi === 4) {
      const { len, start } = readLen(p, lo);
      v = u8.slice(start, start + len);
    } else if (hi === 5) {
      const { len, start } = readLen(p, lo);
      let s = "";
      for (let k = 0; k < len; k++) s += String.fromCharCode(u8[start + k]);
      v = s;
    } else if (hi === 6) {
      const { len, start } = readLen(p, lo);
      let s = "";
      for (let k = 0; k < len; k++) s += String.fromCharCode(dv.getUint16(start + k * 2, false));
      v = s;
    } else if (hi === 8) {
      v = new UID(readUInt(dv, p + 1, lo + 1));
    } else if (hi === 0xa || hi === 0xc) {
      const { len, start } = readLen(p, lo);
      v = [];
      cache.set(i, v);
      for (let k = 0; k < len; k++) v.push(obj(readUInt(dv, start + k * refSize, refSize)));
      return v;
    } else if (hi === 0xd) {
      const { len, start } = readLen(p, lo);
      v = new Map();
      cache.set(i, v);
      for (let k = 0; k < len; k++) {
        const key = obj(readUInt(dv, start + k * refSize, refSize));
        const val = obj(readUInt(dv, start + (len + k) * refSize, refSize));
        v.set(key, val);
      }
      return v;
    } else throw new Error("Unsupported plist object marker 0x" + marker.toString(16));
    cache.set(i, v);
    return v;
  }

  return obj(top);
}

class Bytes {
  constructor() { this.a = []; }
  get length() { return this.a.length; }
  byte(b) { this.a.push(b & 255); }
  uint(n, size) {
    let b = typeof n === "bigint" ? n : BigInt(n);
    const tmp = [];
    for (let i = 0; i < size; i++) { tmp.unshift(Number(b & 255n)); b >>= 8n; }
    for (const x of tmp) this.a.push(x);
  }
  raw(u8) { for (let i = 0; i < u8.length; i++) this.a.push(u8[i]); }
  f64(x) {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setFloat64(0, x, false);
    this.raw(b);
  }
  f32(x) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setFloat32(0, x, false);
    this.raw(b);
  }
  done() { return Uint8Array.from(this.a); }
}

function writeIntObj(w, n) {
  if (typeof n === "bigint" || n < 0 || n >= 4294967296) {
    w.byte(0x13);
    w.uint(BigInt.asUintN(64, BigInt(n)), 8);
  } else if (n < 256) { w.byte(0x10); w.uint(n, 1); }
  else if (n < 65536) { w.byte(0x11); w.uint(n, 2); }
  else { w.byte(0x12); w.uint(n, 4); }
}

function writeHead(w, hi, len) {
  if (len < 15) w.byte((hi << 4) | len);
  else { w.byte((hi << 4) | 15); writeIntObj(w, len); }
}

function serializeBinary(root) {
  const list = [];
  function reg(v) {
    const i = list.length;
    const node = { v };
    list.push(node);
    if (Array.isArray(v)) node.refs = v.map(reg);
    else if (v instanceof Map) {
      node.keys = [...v.keys()].map(reg);
      node.vals = [...v.values()].map(reg);
    }
    return i;
  }
  reg(root);
  const refSize = list.length < 256 ? 1 : list.length < 65536 ? 2 : 4;
  const w = new Bytes();
  for (const c of "bplist00") w.byte(c.charCodeAt(0));
  const offsets = [];
  for (const node of list) {
    offsets.push(w.length);
    const v = node.v;
    if (v === null) w.byte(0x00);
    else if (v === false) w.byte(0x08);
    else if (v === true) w.byte(0x09);
    else if (typeof v === "number" || typeof v === "bigint") writeIntObj(w, v);
    else if (v instanceof Real) { w.byte(0x23); w.f64(v.v); }
    else if (v instanceof Date) { w.byte(0x33); w.f64((v.getTime() - APPLE_EPOCH_MS) / 1000); }
    else if (v instanceof UID) { const n = v.v < 256 ? 1 : v.v < 65536 ? 2 : 4; w.byte(0x80 | (n - 1)); w.uint(v.v, n); }
    else if (v instanceof Uint8Array) { writeHead(w, 4, v.length); w.raw(v); }
    else if (typeof v === "string") {
      let ascii = true;
      for (let k = 0; k < v.length; k++) if (v.charCodeAt(k) > 127) { ascii = false; break; }
      if (ascii) {
        writeHead(w, 5, v.length);
        for (let k = 0; k < v.length; k++) w.byte(v.charCodeAt(k));
      } else {
        writeHead(w, 6, v.length);
        for (let k = 0; k < v.length; k++) w.uint(v.charCodeAt(k), 2);
      }
    } else if (Array.isArray(v)) {
      writeHead(w, 0xa, v.length);
      for (const r of node.refs) w.uint(r, refSize);
    } else if (v instanceof Map) {
      writeHead(w, 0xd, v.size);
      for (const r of node.keys) w.uint(r, refSize);
      for (const r of node.vals) w.uint(r, refSize);
    } else throw new Error("Cannot serialize plist value");
  }
  const tableOff = w.length;
  const last = Math.max(tableOff, offsets[offsets.length - 1] || 0);
  const offSize = last < 256 ? 1 : last < 65536 ? 2 : last < 4294967296 ? 4 : 8;
  for (const o of offsets) w.uint(o, offSize);
  for (let i = 0; i < 6; i++) w.byte(0);
  w.byte(offSize);
  w.byte(refSize);
  w.uint(list.length, 8);
  w.uint(0, 8);
  w.uint(tableOff, 8);
  return w.done();
}

function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|amp|quot|apos);/g, (m, e) => {
    if (e === "lt") return "<";
    if (e === "gt") return ">";
    if (e === "amp") return "&";
    if (e === "quot") return '"';
    if (e === "apos") return "'";
    if (e[1] === "x") return String.fromCodePoint(parseInt(e.slice(2), 16));
    return String.fromCodePoint(parseInt(e.slice(1), 10));
  });
}

function escapeXml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function parseXML(text) {
  const toks = text.match(/<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<![^>]*>|<[^>]+>|[^<]+/g) || [];
  let i = 0;
  const isTag = (t) => t && t[0] === "<" && !t.startsWith("<!--") && !t.startsWith("<?") && !t.startsWith("<!");

  function nextTag() {
    while (i < toks.length && !isTag(toks[i])) i++;
    if (i >= toks.length) throw new Error("Unexpected end of XML plist");
    return toks[i++];
  }

  function tagName(t) {
    const m = /^<\/?\s*([A-Za-z0-9]+)/.exec(t);
    return m ? m[1] : "";
  }

  function readText(t) {
    if (/\/>$/.test(t)) return "";
    let s = "";
    while (i < toks.length && !isTag(toks[i])) {
      if (!toks[i].startsWith("<!--") && !toks[i].startsWith("<?")) s += toks[i];
      i++;
    }
    if (i < toks.length && /^<\//.test(toks[i])) i++;
    return decodeEntities(s);
  }

  function value(t) {
    const name = tagName(t);
    const self = /\/>$/.test(t);
    if (name === "true") return true;
    if (name === "false") return false;
    if (name === "string") return readText(t);
    if (name === "integer") {
      const s = readText(t).trim();
      const b = BigInt(s);
      return b >= BigInt(Number.MIN_SAFE_INTEGER) && b <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : b;
    }
    if (name === "real") return new Real(parseFloat(readText(t)));
    if (name === "date") return new Date(readText(t).trim());
    if (name === "data") {
      const b = atob(readText(t).replace(/\s+/g, ""));
      const u = new Uint8Array(b.length);
      for (let k = 0; k < b.length; k++) u[k] = b.charCodeAt(k);
      return u;
    }
    if (name === "array") {
      const a = [];
      if (self) return a;
      for (;;) {
        const n = nextTag();
        if (tagName(n) === "array" && n[1] === "/") return a;
        a.push(value(n));
      }
    }
    if (name === "dict") {
      const m = new Map();
      if (self) return m;
      for (;;) {
        const n = nextTag();
        if (tagName(n) === "dict" && n[1] === "/") return m;
        if (tagName(n) !== "key") throw new Error("Malformed dict in XML plist");
        const k = readText(n);
        m.set(k, value(nextTag()));
      }
    }
    throw new Error("Unsupported XML plist element <" + name + ">");
  }

  for (;;) {
    const t = nextTag();
    if (tagName(t) === "plist") break;
  }
  return value(nextTag());
}

function serializeXML(root) {
  const out = [];
  function emit(v, d) {
    const ind = "\t".repeat(d);
    if (v === true) out.push(ind + "<true/>");
    else if (v === false) out.push(ind + "<false/>");
    else if (typeof v === "number" || typeof v === "bigint") out.push(ind + "<integer>" + v.toString() + "</integer>");
    else if (v instanceof Real) out.push(ind + "<real>" + String(v.v) + "</real>");
    else if (v instanceof Date) out.push(ind + "<date>" + v.toISOString().replace(/\.\d+Z$/, "Z") + "</date>");
    else if (typeof v === "string") out.push(ind + "<string>" + escapeXml(v) + "</string>");
    else if (v instanceof Uint8Array) {
      let s = "";
      for (let k = 0; k < v.length; k += 0x8000) s += String.fromCharCode.apply(null, v.subarray(k, k + 0x8000));
      out.push(ind + "<data>" + btoa(s) + "</data>");
    } else if (Array.isArray(v)) {
      if (!v.length) out.push(ind + "<array/>");
      else {
        out.push(ind + "<array>");
        for (const x of v) emit(x, d + 1);
        out.push(ind + "</array>");
      }
    } else if (v instanceof Map) {
      if (!v.size) out.push(ind + "<dict/>");
      else {
        out.push(ind + "<dict>");
        for (const [k, x] of v) {
          out.push(ind + "\t<key>" + escapeXml(k) + "</key>");
          emit(x, d + 1);
        }
        out.push(ind + "</dict>");
      }
    } else throw new Error("Cannot serialize plist value");
  }
  emit(root, 0);
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0">\n' +
    out.join("\n") +
    "\n</plist>\n"
  );
}

export function parsePlist(u8) {
  const head = String.fromCharCode(...u8.subarray(0, 8));
  if (head === "bplist00") return { format: "binary", root: parseBinary(u8) };
  let text = new TextDecoder("utf-8").decode(u8);
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  return { format: "xml", root: parseXML(text) };
}

export function serializePlist(root, format) {
  if (format === "binary") return serializeBinary(root);
  return new TextEncoder().encode(serializeXML(root));
}
