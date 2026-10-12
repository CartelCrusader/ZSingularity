const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;
const LC_SEGMENT_64 = 0x19;
const LC_CODE_SIGNATURE = 0x1d;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_LOAD_DYLIB = 0xc;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LAZY_LOAD_DYLIB = 0x20;
const DYLIB_CMDS = new Set([LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB]);
const ZEROFILL = new Set([1, 0xc, 0x12]);

const CPU = { 0x0100000c: "arm64", 0x01000007: "x86_64", 0x0200000c: "arm64_32" };

function cstr(u8, start, end) {
  let s = "";
  for (let i = start; i < end && u8[i] !== 0; i++) s += String.fromCharCode(u8[i]);
  return s;
}

async function patchThin(read, base, dylibPath) {
  const head = await read(base, 32);
  const dv = new DataView(head.buffer, head.byteOffset, head.byteLength);
  if (dv.getUint32(0, true) !== MH_MAGIC_64) throw new Error("Main executable is not a 64-bit Mach-O.");
  const cputype = dv.getUint32(4, true);
  const ncmds = dv.getUint32(16, true);
  const sizeofcmds = dv.getUint32(20, true);
  const cmds = await read(base + 32, sizeofcmds);
  const cdv = new DataView(cmds.buffer, cmds.byteOffset, cmds.byteLength);
  let limit = Infinity;
  let sigPos = -1;
  let sigSize = 0;
  let cryptid = 0;
  let already = false;
  let p = 0;
  for (let i = 0; i < ncmds; i++) {
    const cmd = cdv.getUint32(p, true);
    const size = cdv.getUint32(p + 4, true);
    if (size < 8 || p + size > cmds.length) throw new Error("Corrupt Mach-O load commands.");
    if (cmd === LC_SEGMENT_64) {
      const nsects = cdv.getUint32(p + 64, true);
      for (let s = 0; s < nsects; s++) {
        const sp = p + 72 + s * 80;
        const secSize = Number(cdv.getBigUint64(sp + 40, true));
        const off = cdv.getUint32(sp + 48, true);
        const type = cdv.getUint32(sp + 64, true) & 0xff;
        if (off > 0 && secSize > 0 && !ZEROFILL.has(type) && off < limit) limit = off;
      }
    } else if (cmd === LC_CODE_SIGNATURE) {
      sigPos = p;
      sigSize = size;
    } else if (cmd === LC_ENCRYPTION_INFO_64) {
      cryptid = cdv.getUint32(p + 16, true);
    } else if (DYLIB_CMDS.has(cmd)) {
      const nameOff = cdv.getUint32(p + 8, true);
      if (cstr(cmds, p + nameOff, p + size) === dylibPath) already = true;
    }
    p += size;
  }
  const info = { arch: CPU[cputype] || "0x" + cputype.toString(16), cryptid, already, patches: [] };
  if (cryptid !== 0 || already) return info;
  const nameBytes = new TextEncoder().encode(dylibPath);
  const need = (24 + nameBytes.length + 1 + 7) & ~7;
  const free = limit - (32 + sizeofcmds);
  if (!isFinite(limit) || free < need) {
    throw new Error("The main executable has no spare room in its Mach-O header for a new load command (needs " + need + " bytes, has " + Math.max(0, free) + ").");
  }
  const cmd = new Uint8Array(need);
  const ddv = new DataView(cmd.buffer);
  ddv.setUint32(0, LC_LOAD_DYLIB, true);
  ddv.setUint32(4, need, true);
  ddv.setUint32(8, 24, true);
  ddv.setUint32(12, 2, true);
  ddv.setUint32(16, 0x00010000, true);
  ddv.setUint32(20, 0x00010000, true);
  cmd.set(nameBytes, 24);
  const insertAt = sigPos >= 0 && sigPos + sigSize === sizeofcmds ? sigPos : sizeofcmds;
  const tail = cmds.subarray(insertAt, sizeofcmds);
  const region = new Uint8Array(need + tail.length);
  region.set(cmd, 0);
  region.set(tail, need);
  const counts = new Uint8Array(8);
  const cdv2 = new DataView(counts.buffer);
  cdv2.setUint32(0, ncmds + 1, true);
  cdv2.setUint32(4, sizeofcmds + need, true);
  info.patches.push({ offset: base + 16, bytes: counts });
  info.patches.push({ offset: base + 32 + insertAt, bytes: region });
  return info;
}

export async function patchMachO(read, dylibPath) {
  const head = await read(0, 8);
  const dv = new DataView(head.buffer, head.byteOffset, head.byteLength);
  const magic = dv.getUint32(0, false);
  if (magic !== FAT_MAGIC && magic !== FAT_MAGIC_64) {
    const r = await patchThin(read, 0, dylibPath);
    return { slices: [r], patches: r.patches };
  }
  const is64 = magic === FAT_MAGIC_64;
  const n = dv.getUint32(4, false);
  const stride = is64 ? 32 : 20;
  const table = await read(8, n * stride);
  const tdv = new DataView(table.buffer, table.byteOffset, table.byteLength);
  const slices = [];
  const patches = [];
  for (let i = 0; i < n; i++) {
    const o = i * stride;
    const offset = is64 ? Number(tdv.getBigUint64(o + 8, false)) : tdv.getUint32(o + 8, false);
    const r = await patchThin(read, offset, dylibPath);
    slices.push(r);
    patches.push(...r.patches);
  }
  return { slices, patches };
}

export class ChunkedBuffer {
  constructor(chunks) {
    this.chunks = chunks;
    this.starts = [];
    let o = 0;
    for (const c of chunks) { this.starts.push(o); o += c.length; }
    this.length = o;
  }

  locate(offset) {
    let lo = 0;
    let hi = this.chunks.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.starts[mid] <= offset) lo = mid; else hi = mid - 1;
    }
    return lo;
  }

  read(offset, len) {
    const out = new Uint8Array(len);
    let i = this.locate(offset);
    let done = 0;
    while (done < len) {
      const c = this.chunks[i];
      const within = offset + done - this.starts[i];
      const take = Math.min(len - done, c.length - within);
      out.set(c.subarray(within, within + take), done);
      done += take;
      i++;
    }
    return out;
  }

  write(offset, bytes) {
    let i = this.locate(offset);
    let done = 0;
    while (done < bytes.length) {
      const c = this.chunks[i];
      const within = offset + done - this.starts[i];
      const take = Math.min(bytes.length - done, c.length - within);
      c.set(bytes.subarray(done, done + take), within);
      done += take;
      i++;
    }
  }
}
