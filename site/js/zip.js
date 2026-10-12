const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_EOCD = 0x06054b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_LOC64 = 0x07064b50;
const CAP32 = 0xffffffff;
const CAP16 = 0xffff;

function u64(dv, p) {
  return dv.getUint32(p, true) + dv.getUint32(p + 4, true) * 4294967296;
}

function setU64(dv, p, n) {
  dv.setUint32(p, n % 4294967296, true);
  dv.setUint32(p + 4, Math.floor(n / 4294967296), true);
}

async function bytes(blob, start, end) {
  return new Uint8Array(await blob.slice(start, end).arrayBuffer());
}

export async function readZip(blob) {
  const size = blob.size;
  const tailLen = Math.min(size, 65557);
  const tail = await bytes(blob, size - tailLen, size);
  const tdv = new DataView(tail.buffer);
  let eocd = -1;
  for (let p = tail.length - 22; p >= 0; p--) {
    if (tdv.getUint32(p, true) === SIG_EOCD && p + 22 + tdv.getUint16(p + 20, true) === tail.length) {
      eocd = p;
      break;
    }
  }
  if (eocd < 0) throw new Error("Not a valid zip/IPA file (no end-of-central-directory record).");
  let total = tdv.getUint16(eocd + 10, true);
  let cdSize = tdv.getUint32(eocd + 12, true);
  let cdOffset = tdv.getUint32(eocd + 16, true);
  if ((total === CAP16 || cdSize === CAP32 || cdOffset === CAP32) && eocd >= 20 && tdv.getUint32(eocd - 20, true) === SIG_LOC64) {
    const z64off = u64(tdv, eocd - 20 + 8);
    const rec = await bytes(blob, z64off, z64off + 56);
    const rdv = new DataView(rec.buffer);
    if (rdv.getUint32(0, true) !== SIG_EOCD64) throw new Error("Corrupt zip64 directory.");
    total = u64(rdv, 32);
    cdSize = u64(rdv, 40);
    cdOffset = u64(rdv, 48);
  }
  const cd = await bytes(blob, cdOffset, cdOffset + cdSize);
  const dv = new DataView(cd.buffer);
  const dec = new TextDecoder("utf-8");
  const entries = [];
  let p = 0;
  for (let n = 0; n < total; n++) {
    if (p + 46 > cd.length || dv.getUint32(p, true) !== SIG_CENTRAL) throw new Error("Corrupt zip central directory.");
    const e = {
      versionMadeBy: dv.getUint16(p + 4, true),
      versionNeeded: dv.getUint16(p + 6, true),
      flags: dv.getUint16(p + 8, true),
      method: dv.getUint16(p + 10, true),
      time: dv.getUint16(p + 12, true),
      date: dv.getUint16(p + 14, true),
      crc: dv.getUint32(p + 16, true),
      csize: dv.getUint32(p + 20, true),
      usize: dv.getUint32(p + 24, true),
      intAttr: dv.getUint16(p + 36, true),
      extAttr: dv.getUint32(p + 38, true),
      localOffset: dv.getUint32(p + 42, true),
    };
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    e.name = dec.decode(cd.subarray(p + 46, p + 46 + nameLen));
    let x = p + 46 + nameLen;
    const xend = x + extraLen;
    while (x + 4 <= xend) {
      const id = dv.getUint16(x, true);
      const len = dv.getUint16(x + 2, true);
      if (id === 1) {
        let q = x + 4;
        if (e.usize === CAP32) { e.usize = u64(dv, q); q += 8; }
        if (e.csize === CAP32) { e.csize = u64(dv, q); q += 8; }
        if (e.localOffset === CAP32) { e.localOffset = u64(dv, q); q += 8; }
      }
      x += 4 + len;
    }
    e.isDir = e.name.endsWith("/");
    entries.push(e);
    p += 46 + nameLen + extraLen + commentLen;
  }
  const order = entries.map((e, i) => i).sort((a, b) => entries[a].localOffset - entries[b].localOffset);
  for (let k = 0; k < order.length; k++) {
    const e = entries[order[k]];
    e.spanEnd = k + 1 < order.length ? entries[order[k + 1]].localOffset : cdOffset;
  }
  return { blob, entries, cdOffset };
}

export async function dataRange(blob, e) {
  const h = await bytes(blob, e.localOffset, e.localOffset + 30);
  const dv = new DataView(h.buffer);
  if (dv.getUint32(0, true) !== SIG_LOCAL) throw new Error("Corrupt zip local header for " + e.name);
  const start = e.localOffset + 30 + dv.getUint16(26, true) + dv.getUint16(28, true);
  return { start, end: start + e.csize };
}

export async function rawBlob(blob, e) {
  const { start, end } = await dataRange(blob, e);
  return blob.slice(start, end);
}

export async function inflateChunks(compressed, onChunk) {
  const rs = compressed.stream().pipeThrough(new DecompressionStream("deflate-raw"));
  const reader = rs.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    await onChunk(value);
  }
}

export async function readEntryBytes(blob, e) {
  const raw = await rawBlob(blob, e);
  if (e.method === 0) return new Uint8Array(await raw.arrayBuffer());
  if (e.method !== 8) throw new Error("Unsupported zip compression method " + e.method + " for " + e.name);
  const chunks = [];
  let len = 0;
  await inflateChunks(raw, (c) => { chunks.push(c); len += c.length; });
  const out = new Uint8Array(len);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

const CRC_TABLE = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

export function crc32(prev, u8) {
  let c = ~prev;
  const n = u8.length;
  let i = 0;
  for (; i + 4 <= n; i += 4) {
    c = CRC_TABLE[(c ^ u8[i]) & 255] ^ (c >>> 8);
    c = CRC_TABLE[(c ^ u8[i + 1]) & 255] ^ (c >>> 8);
    c = CRC_TABLE[(c ^ u8[i + 2]) & 255] ^ (c >>> 8);
    c = CRC_TABLE[(c ^ u8[i + 3]) & 255] ^ (c >>> 8);
  }
  for (; i < n; i++) c = CRC_TABLE[(c ^ u8[i]) & 255] ^ (c >>> 8);
  return ~c >>> 0;
}

export async function crc32OfBlob(blob, onProgress) {
  const reader = blob.stream().getReader();
  let crc = 0;
  let done = 0;
  for (;;) {
    const r = await reader.read();
    if (r.done) break;
    crc = crc32(crc, r.value);
    done += r.value.length;
    if (onProgress) onProgress(done / Math.max(1, blob.size));
  }
  return crc;
}

function dosNow() {
  const d = new Date();
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((Math.max(1980, d.getFullYear()) - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

export function unixAttr(mode) {
  return ((0o100000 | mode) << 16) >>> 0;
}

export class ZipWriter {
  constructor(opts = {}) {
    this.cap = opts.zip64Threshold || CAP32;
    this.forceZip64Directory = !!opts.forceZip64Directory;
    this.parts = [];
    this.offset = 0;
    this.central = [];
    this.enc = new TextEncoder();
  }

  pushBytes(u8) {
    this.parts.push({ bytes: u8 });
    this.offset += u8.length;
  }

  pushSlice(blob, start, end) {
    if (end <= start) return;
    const last = this.parts[this.parts.length - 1];
    if (last && last.blob === blob && last.end === start) last.end = end;
    else this.parts.push({ blob, start, end });
    this.offset += end - start;
  }

  copyVerbatim(srcBlob, entry) {
    const at = this.offset;
    this.pushSlice(srcBlob, entry.localOffset, entry.spanEnd);
    this.central.push({ ...entry, localOffset: at });
  }

  addEntry(meta, dataBlobOrBytes) {
    const nameBytes = this.enc.encode(meta.name);
    const ascii = /^[\x20-\x7e]*$/.test(meta.name);
    const now = dosNow();
    const e = {
      name: meta.name,
      nameBytes,
      versionMadeBy: meta.versionMadeBy ?? ((3 << 8) | 20),
      flags: ((meta.flags ?? 0) & ~8) | (ascii ? 0 : 0x800),
      method: meta.method,
      time: meta.time ?? now.time,
      date: meta.date ?? now.date,
      crc: meta.crc,
      csize: meta.csize,
      usize: meta.usize,
      intAttr: meta.intAttr ?? 0,
      extAttr: meta.extAttr ?? unixAttr(0o644),
    };
    const z64 = e.csize >= this.cap || e.usize >= this.cap;
    const extra = z64 ? 20 : 0;
    const h = new Uint8Array(30 + nameBytes.length + extra);
    const dv = new DataView(h.buffer);
    dv.setUint32(0, SIG_LOCAL, true);
    dv.setUint16(4, z64 ? 45 : 20, true);
    dv.setUint16(6, e.flags, true);
    dv.setUint16(8, e.method, true);
    dv.setUint16(10, e.time, true);
    dv.setUint16(12, e.date, true);
    dv.setUint32(14, e.crc, true);
    dv.setUint32(18, z64 ? CAP32 : e.csize, true);
    dv.setUint32(22, z64 ? CAP32 : e.usize, true);
    dv.setUint16(26, nameBytes.length, true);
    dv.setUint16(28, extra, true);
    h.set(nameBytes, 30);
    if (z64) {
      const x = 30 + nameBytes.length;
      dv.setUint16(x, 1, true);
      dv.setUint16(x + 2, 16, true);
      setU64(dv, x + 4, e.usize);
      setU64(dv, x + 12, e.csize);
    }
    e.localOffset = this.offset;
    this.pushBytes(h);
    if (dataBlobOrBytes instanceof Uint8Array) this.pushBytes(dataBlobOrBytes);
    else this.pushSlice(dataBlobOrBytes, 0, dataBlobOrBytes.size);
    this.central.push(e);
  }

  addStored(name, content, crc, extra = {}) {
    const size = content instanceof Uint8Array ? content.length : content.size;
    this.addEntry({ ...extra, name, method: 0, crc, csize: size, usize: size }, content);
  }

  finish() {
    const records = [];
    let cdSize = 0;
    for (const e of this.central) {
      const nameBytes = e.nameBytes || this.enc.encode(e.name);
      const needU = e.usize >= this.cap;
      const needC = e.csize >= this.cap;
      const needO = e.localOffset >= this.cap;
      const extraLen = needU || needC || needO ? 4 + (needU ? 8 : 0) + (needC ? 8 : 0) + (needO ? 8 : 0) : 0;
      const r = new Uint8Array(46 + nameBytes.length + extraLen);
      const dv = new DataView(r.buffer);
      dv.setUint32(0, SIG_CENTRAL, true);
      dv.setUint16(4, e.versionMadeBy, true);
      dv.setUint16(6, extraLen ? Math.max(45, e.versionNeeded || 20) : e.versionNeeded || 20, true);
      dv.setUint16(8, e.flags, true);
      dv.setUint16(10, e.method, true);
      dv.setUint16(12, e.time, true);
      dv.setUint16(14, e.date, true);
      dv.setUint32(16, e.crc, true);
      dv.setUint32(20, needC ? CAP32 : e.csize, true);
      dv.setUint32(24, needU ? CAP32 : e.usize, true);
      dv.setUint16(28, nameBytes.length, true);
      dv.setUint16(30, extraLen, true);
      dv.setUint16(32, 0, true);
      dv.setUint16(34, 0, true);
      dv.setUint16(36, e.intAttr, true);
      dv.setUint32(38, e.extAttr, true);
      dv.setUint32(42, needO ? CAP32 : e.localOffset, true);
      r.set(nameBytes, 46);
      if (extraLen) {
        let x = 46 + nameBytes.length;
        dv.setUint16(x, 1, true);
        dv.setUint16(x + 2, extraLen - 4, true);
        x += 4;
        if (needU) { setU64(dv, x, e.usize); x += 8; }
        if (needC) { setU64(dv, x, e.csize); x += 8; }
        if (needO) { setU64(dv, x, e.localOffset); x += 8; }
      }
      records.push(r);
      cdSize += r.length;
    }
    const cdOffset = this.offset;
    for (const r of records) this.pushBytes(r);
    const count = this.central.length;
    const need64 = this.forceZip64Directory || count >= CAP16 || cdOffset >= this.cap || cdSize >= this.cap;
    if (need64) {
      const z = new Uint8Array(56 + 20);
      const dv = new DataView(z.buffer);
      dv.setUint32(0, SIG_EOCD64, true);
      setU64(dv, 4, 44);
      dv.setUint16(12, 45, true);
      dv.setUint16(14, 45, true);
      dv.setUint32(16, 0, true);
      dv.setUint32(20, 0, true);
      setU64(dv, 24, count);
      setU64(dv, 32, count);
      setU64(dv, 40, cdSize);
      setU64(dv, 48, cdOffset);
      dv.setUint32(56, SIG_LOC64, true);
      dv.setUint32(60, 0, true);
      setU64(dv, 64, this.offset);
      dv.setUint32(72, 1, true);
      this.pushBytes(z);
    }
    const e = new Uint8Array(22);
    const dv = new DataView(e.buffer);
    dv.setUint32(0, SIG_EOCD, true);
    dv.setUint16(4, 0, true);
    dv.setUint16(6, 0, true);
    dv.setUint16(8, need64 ? CAP16 : count, true);
    dv.setUint16(10, need64 ? CAP16 : count, true);
    dv.setUint32(12, need64 ? CAP32 : cdSize, true);
    dv.setUint32(16, need64 ? CAP32 : cdOffset, true);
    dv.setUint16(20, 0, true);
    this.pushBytes(e);
    const blobParts = this.parts.map((p) => (p.bytes ? p.bytes : p.blob.slice(p.start, p.end)));
    return new Blob(blobParts, { type: "application/octet-stream" });
  }
}
