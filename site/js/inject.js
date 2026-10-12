import { parsePlist, serializePlist } from "./plist.js";
import { readZip, dataRange, rawBlob, readEntryBytes, inflateChunks, crc32, crc32OfBlob, ZipWriter, unixAttr } from "./zip.js";
import { patchMachO, ChunkedBuffer } from "./macho.js";

const TRUE_KEYS = [
  "CADisableMinimumFrameDuration",
  "CADisableMinimumFrameDurationOnPhone",
  "LSSupportsGameMode",
  "LSSupportsOpeningDocumentsInPlace",
  "UIFileSharingEnabled",
];
const LOCATION_KEYS = ["NSLocationWhenInUseUsageDescription", "NSLocationAlwaysAndWhenInUseUsageDescription"];
const LOCATION_TEXT = "Used by the Keep Alive developer tool to prevent suspension during testing.";
const DYLIB_NAME = "ZSingularity.dylib";
const DYLIB_REF = "@executable_path/Frameworks/" + DYLIB_NAME;

function metaOf(e) {
  return { versionMadeBy: e.versionMadeBy, time: e.time, date: e.date, intAttr: e.intAttr, extAttr: e.extAttr };
}

export async function inject(ipa, payload, opts = {}) {
  const progress = opts.onProgress || (() => {});
  const warnings = [];
  progress("Reading IPA", 0);
  const zip = await readZip(ipa);
  const plistEntry = zip.entries.find((e) => /^Payload\/[^/]+\.app\/Info\.plist$/i.test(e.name));
  if (!plistEntry) throw new Error("No Payload/<App>.app/Info.plist found. Is this a valid .ipa?");
  const appDir = plistEntry.name.replace(/\/Info\.plist$/i, "");

  progress("Patching Info.plist", 0);
  const parsed = parsePlist(await readEntryBytes(ipa, plistEntry));
  const root = parsed.root;
  const gameVersion = root.get("CFBundleShortVersionString");
  const appId = root.get("CFBundleIdentifier");
  const exeName = root.get("CFBundleExecutable");
  if (!gameVersion) throw new Error("CFBundleShortVersionString is missing from the game's Info.plist.");
  if (!appId || !exeName) throw new Error("CFBundleIdentifier or CFBundleExecutable is missing from Info.plist.");
  for (const k of TRUE_KEYS) root.set(k, true);
  for (const k of LOCATION_KEYS) root.set(k, LOCATION_TEXT);
  root.set("UIBackgroundModes", ["location"]);
  const plistBytes = serializePlist(root, parsed.format);

  const exeEntry = zip.entries.find((e) => e.name === appDir + "/" + exeName);
  if (!exeEntry) throw new Error("Main executable " + exeName + " not found in the app bundle.");

  progress("Patching executable", 0);
  let exeBlob = null;
  let exeCrc = 0;
  let machInfo;
  if (exeEntry.method === 0) {
    const { start, end } = await dataRange(ipa, exeEntry);
    const src = ipa.slice(start, end);
    machInfo = await patchMachO(async (o, l) => new Uint8Array(await src.slice(o, o + l).arrayBuffer()), DYLIB_REF);
    checkMach(machInfo, warnings);
    if (machInfo.patches.length) {
      const patches = [...machInfo.patches].sort((a, b) => a.offset - b.offset);
      const parts = [];
      let at = 0;
      for (const p of patches) {
        parts.push(src.slice(at, p.offset), p.bytes);
        at = p.offset + p.bytes.length;
      }
      parts.push(src.slice(at));
      exeBlob = new Blob(parts);
      exeCrc = await crc32OfBlob(exeBlob, (f) => progress("Patching executable", f));
    }
  } else if (exeEntry.method === 8) {
    const raw = await rawBlob(ipa, exeEntry);
    const chunks = [];
    let got = 0;
    await inflateChunks(raw, (c) => {
      chunks.push(c);
      got += c.length;
      progress("Patching executable", Math.min(0.5, (got / Math.max(1, exeEntry.usize)) * 0.5));
    });
    const buf = new ChunkedBuffer(chunks);
    machInfo = await patchMachO(async (o, l) => buf.read(o, l), DYLIB_REF);
    checkMach(machInfo, warnings);
    if (machInfo.patches.length) {
      for (const p of machInfo.patches) buf.write(p.offset, p.bytes);
      let crc = 0;
      let done = 0;
      for (const c of chunks) {
        crc = crc32(crc, c);
        done += c.length;
        progress("Patching executable", 0.5 + 0.5 * (done / Math.max(1, buf.length)));
      }
      exeCrc = crc;
      exeBlob = new Blob(chunks);
    }
  } else throw new Error("Unsupported compression method " + exeEntry.method + " on the main executable.");

  let appex = null;
  if (opts.embedAppex !== false && payload.appex) {
    const azip = await readZip(payload.appex);
    const list = azip.entries.filter((e) => !e.isDir && !e.name.startsWith("__MACOSX/") && !e.name.endsWith(".DS_Store") && !e.name.includes("/_CodeSignature/"));
    const infoEntry = list.find((e) => /^[^/]+\.appex\/Info\.plist$/i.test(e.name));
    if (!infoEntry) throw new Error("The extension archive has no <name>.appex/Info.plist.");
    const bundleDir = infoEntry.name.replace(/\/Info\.plist$/i, "");
    const bundleName = bundleDir.replace(/\.appex$/i, "");
    const aParsed = parsePlist(await readEntryBytes(azip.blob, infoEntry));
    aParsed.root.set("CFBundleIdentifier", appId + "." + bundleName);
    const aExe = aParsed.root.get("CFBundleExecutable");
    appex = { azip, list, infoEntry, bundleDir, aExe, infoBytes: serializePlist(aParsed.root, aParsed.format) };
  }

  const dylibDest = appDir + "/Frameworks/" + DYLIB_NAME;
  const drop = (e) => {
    if (e.name === dylibDest) return true;
    if (e.name.startsWith(appDir + "/_CodeSignature/")) return true;
    if (appex && e.name.startsWith(appDir + "/PlugIns/" + appex.bundleDir + "/")) return true;
    return false;
  };

  progress("Writing IPA", 0);
  const w = new ZipWriter({ zip64Threshold: opts.zip64Threshold, forceZip64Directory: opts.forceZip64Directory });
  const sorted = [...zip.entries].sort((a, b) => a.localOffset - b.localOffset);
  let i = 0;
  for (const e of sorted) {
    i++;
    if (drop(e)) continue;
    if (e === plistEntry) w.addStored(e.name, plistBytes, crc32(0, plistBytes), metaOf(e));
    else if (e === exeEntry && exeBlob) w.addStored(e.name, exeBlob, exeCrc, metaOf(e));
    else w.copyVerbatim(ipa, e);
    if (i % 256 === 0) progress("Writing IPA", i / sorted.length);
  }
  w.addStored(dylibDest, payload.dylib, crc32(0, payload.dylib), { extAttr: unixAttr(0o755) });
  if (appex) {
    for (const ae of appex.list) {
      const dest = appDir + "/PlugIns/" + ae.name;
      if (ae === appex.infoEntry) {
        w.addStored(dest, appex.infoBytes, crc32(0, appex.infoBytes), { extAttr: unixAttr(0o644) });
        continue;
      }
      const isExe = appex.aExe && ae.name === appex.bundleDir + "/" + appex.aExe;
      const mode = isExe ? 0o755 : (ae.extAttr >>> 16) & 0o777 || 0o644;
      const raw = await rawBlob(appex.azip.blob, ae);
      w.addEntry(
        { name: dest, method: ae.method, crc: ae.crc, csize: ae.csize, usize: ae.usize, time: ae.time, date: ae.date, extAttr: unixAttr(mode) },
        raw
      );
    }
  } else if (opts.embedAppex !== false) warnings.push("No memory donor extension was supplied, so RamBypass will be unavailable.");
  const blob = w.finish();
  progress("Done", 1);
  return {
    blob,
    gameVersion,
    appId,
    exeName,
    appDir,
    arch: machInfo.slices.map((s) => s.arch),
    alreadyInjected: machInfo.slices.every((s) => s.already),
    embeddedAppex: !!appex,
    warnings,
  };
}

function checkMach(m, warnings) {
  for (const s of m.slices) {
    if (s.cryptid !== 0) throw new Error("This IPA is still FairPlay-encrypted (App Store build). Use a decrypted IPA.");
  }
  if (!m.slices.some((s) => s.arch === "arm64")) warnings.push("The main executable has no arm64 slice.");
  if (m.slices.every((s) => s.already)) warnings.push("The executable already loads ZSingularity; the dylib was just replaced.");
}
