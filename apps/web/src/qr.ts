/**
 * QR Code Model 2, versions 1–6, ECC-L, byte mode (single RS block).
 * Encodes locally so the public identity never leaves the device for a QR API.
 * v6 is the last ECC-L version with one Reed-Solomon block (136 data codewords).
 */
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]!;
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a]! + LOG[b]!]!;
}

function rsEncode(data: Uint8Array, nsym: number): Uint8Array {
  let gen = [1];
  for (let i = 0; i < nsym; i++) {
    const next = new Array<number>(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gfMul(gen[j]!, EXP[i]!);
      next[j + 1] ^= gen[j]!;
    }
    gen = next;
  }
  const res = new Uint8Array(data.length + nsym);
  res.set(data);
  for (let i = 0; i < data.length; i++) {
    const coef = res[i]!;
    if (coef === 0) continue;
    for (let j = 0; j < gen.length; j++) {
      res[i + j] ^= gfMul(gen[j]!, coef);
    }
  }
  return res.slice(data.length);
}

const VERSIONS: { version: number; data: number; ec: number }[] = [
  { version: 1, data: 19, ec: 7 },
  { version: 2, data: 34, ec: 10 },
  { version: 3, data: 55, ec: 15 },
  { version: 4, data: 80, ec: 20 },
  { version: 5, data: 108, ec: 26 },
  { version: 6, data: 136, ec: 36 },
];

const ALIGN: Record<number, number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
};

/** Max byte-mode payload for v6 ECC-L after mode/length/terminator. */
export const QR_MAX_BYTES = 133;

function encodeBytes(payload: Uint8Array): Uint8Array {
  const headerBits = 4 + 8 + payload.length * 8 + 4;
  const needed = Math.ceil(headerBits / 8);
  const spec = VERSIONS.find((v) => v.data >= needed);
  if (!spec) throw new Error("QR payload too long");
  const bits: number[] = [];
  const push = (value: number, n: number) => {
    for (let i = n - 1; i >= 0; i--) bits.push((value >> i) & 1);
  };
  push(0b0100, 4);
  push(payload.length, 8);
  for (const b of payload) push(b, 8);
  const capacity = spec.data * 8;
  const term = Math.min(4, capacity - bits.length);
  for (let i = 0; i < term; i++) bits.push(0);
  while (bits.length % 8 !== 0) bits.push(0);
  const bytes = new Uint8Array(spec.data);
  for (let i = 0; i < bits.length / 8; i++) {
    let v = 0;
    for (let j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j]!;
    bytes[i] = v;
  }
  const pads = [0xec, 0x11];
  let p = 0;
  for (let i = bits.length / 8; i < spec.data; i++) {
    bytes[i] = pads[p % 2]!;
    p += 1;
  }
  const ecc = rsEncode(bytes, spec.ec);
  const out = new Uint8Array(bytes.length + ecc.length);
  out.set(bytes);
  out.set(ecc, bytes.length);
  return out;
}

function sizeOf(version: number): number {
  return 21 + (version - 1) * 4;
}

function reserved(version: number): boolean[][] {
  const n = sizeOf(version);
  const r = Array.from({ length: n }, () => Array<boolean>(n).fill(false));
  const mark = (r0: number, c0: number, h: number, w: number) => {
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        const yy = r0 + y;
        const xx = c0 + x;
        if (yy >= 0 && xx >= 0 && yy < n && xx < n) r[yy]![xx] = true;
      }
    }
  };
  mark(0, 0, 9, 9);
  mark(0, n - 8, 9, 8);
  mark(n - 8, 0, 8, 9);
  mark(6, 0, 1, n);
  mark(0, 6, n, 1);
  const pos = ALIGN[version] ?? [];
  for (const y of pos) {
    for (const x of pos) {
      if ((y === 6 && x === 6) || (y === 6 && x === n - 7) || (y === n - 7 && x === 6)) continue;
      mark(y - 2, x - 2, 5, 5);
    }
  }
  return r;
}

function placeFinders(mod: boolean[][], n: number): void {
  const draw = (r0: number, c0: number) => {
    for (let y = -1; y <= 7; y++) {
      for (let x = -1; x <= 7; x++) {
        const yy = r0 + y;
        const xx = c0 + x;
        if (yy < 0 || xx < 0 || yy >= n || xx >= n) continue;
        const on =
          x === -1 || y === -1 || x === 7 || y === 7
            ? false
            : x === 0 || y === 0 || x === 6 || y === 6 || (x >= 2 && x <= 4 && y >= 2 && y <= 4);
        mod[yy]![xx] = on;
      }
    }
  };
  draw(0, 0);
  draw(0, n - 7);
  draw(n - 7, 0);
}

function placeTiming(mod: boolean[][], n: number): void {
  for (let i = 8; i < n - 8; i++) {
    mod[6]![i] = i % 2 === 0;
    mod[i]![6] = i % 2 === 0;
  }
}

function placeAlign(mod: boolean[][], version: number): void {
  const n = mod.length;
  const pos = ALIGN[version] ?? [];
  for (const cy of pos) {
    for (const cx of pos) {
      if ((cy === 6 && cx === 6) || (cy === 6 && cx === n - 7) || (cy === n - 7 && cx === 6)) continue;
      for (let y = -2; y <= 2; y++) {
        for (let x = -2; x <= 2; x++) {
          const d = Math.max(Math.abs(x), Math.abs(y));
          mod[cy + y]![cx + x] = d !== 1;
        }
      }
    }
  }
}

function maskBit(mask: number, r: number, c: number): boolean {
  switch (mask) {
    case 0:
      return (r + c) % 2 === 0;
    case 1:
      return r % 2 === 0;
    case 2:
      return c % 3 === 0;
    case 3:
      return (r + c) % 3 === 0;
    case 4:
      return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
    case 5:
      return ((r * c) % 2) + ((r * c) % 3) === 0;
    case 6:
      return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
    default:
      return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
  }
}

function placeData(mod: boolean[][], reservedMap: boolean[][], data: Uint8Array, mask: number): void {
  const n = mod.length;
  const bits: number[] = [];
  for (const b of data) {
    for (let i = 7; i >= 0; i--) bits.push((b >> i) & 1);
  }
  let bi = 0;
  let upward = true;
  for (let col = n - 1; col > 0; col -= 2) {
    if (col === 6) col = 5;
    for (let i = 0; i < n; i++) {
      const row = upward ? n - 1 - i : i;
      for (const c of [col, col - 1]) {
        if (reservedMap[row]![c]) continue;
        const bit = bi < bits.length ? bits[bi]! : 0;
        bi += 1;
        mod[row]![c] = (bit === 1) !== maskBit(mask, row, c);
      }
    }
    upward = !upward;
  }
}

const FORMAT_MASK = 0x5412;
function formatBits(eccLsb: number, mask: number): number {
  const data = (eccLsb << 3) | mask;
  let d = data << 10;
  let poly = 0x537;
  for (let i = 14; i >= 10; i--) {
    if ((d >> i) & 1) d ^= poly << (i - 10);
  }
  return ((data << 10) | d) ^ FORMAT_MASK;
}

function placeFormat(mod: boolean[][], bits: number): void {
  const n = mod.length;
  for (let i = 0; i < 15; i++) {
    const on = ((bits >> i) & 1) === 1;
    if (i < 6) mod[i]![8] = on;
    else if (i < 8) mod[i + 1]![8] = on;
    else mod[n - 15 + i]![8] = on;
    if (i < 8) mod[8]![n - 1 - i] = on;
    else if (i === 8) mod[8]![7] = on;
    else mod[8]![14 - i] = on;
  }
  mod[n - 8]![8] = true;
}

function score(mod: boolean[][]): number {
  const n = mod.length;
  let s = 0;
  for (let r = 0; r < n; r++) {
    let run = 1;
    for (let c = 1; c < n; c++) {
      if (mod[r]![c] === mod[r]![c - 1]) run += 1;
      else {
        if (run >= 5) s += run - 2;
        run = 1;
      }
    }
    if (run >= 5) s += run - 2;
  }
  for (let c = 0; c < n; c++) {
    let run = 1;
    for (let r = 1; r < n; r++) {
      if (mod[r]![c] === mod[r - 1]![c]) run += 1;
      else {
        if (run >= 5) s += run - 2;
        run = 1;
      }
    }
    if (run >= 5) s += run - 2;
  }
  for (let r = 0; r < n - 1; r++) {
    for (let c = 0; c < n - 1; c++) {
      const v = mod[r]![c];
      if (v === mod[r]![c + 1] && v === mod[r + 1]![c] && v === mod[r + 1]![c + 1]) s += 3;
    }
  }
  let dark = 0;
  for (const row of mod) for (const cell of row) if (cell) dark += 1;
  s += Math.abs((dark * 100) / (n * n) - 50) / 5 * 10;
  return s;
}

export function qrModulesFromBytes(payload: Uint8Array): boolean[][] {
  const headerBits = 4 + 8 + payload.length * 8 + 4;
  const needed = Math.ceil(headerBits / 8);
  const spec = VERSIONS.find((v) => v.data >= needed);
  if (!spec) throw new Error("QR payload too long");
  const data = encodeBytes(payload);
  const n = sizeOf(spec.version);
  const reservedMap = reserved(spec.version);
  let best: boolean[][] | null = null;
  let bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const mod = Array.from({ length: n }, () => Array<boolean>(n).fill(false));
    placeFinders(mod, n);
    placeTiming(mod, n);
    placeAlign(mod, spec.version);
    placeFormat(mod, formatBits(0b01, mask));
    placeData(mod, reservedMap, data, mask);
    placeFormat(mod, formatBits(0b01, mask));
    const sc = score(mod);
    if (sc < bestScore) {
      bestScore = sc;
      best = mod;
    }
  }
  return best!;
}

export function qrModules(text: string): boolean[][] {
  return qrModulesFromBytes(new TextEncoder().encode(text));
}

export function qrSvgFromBytes(payload: Uint8Array, modulePx = 4): string {
  const mod = qrModulesFromBytes(payload);
  const n = mod.length;
  const quiet = 4;
  const dim = (n + quiet * 2) * modulePx;
  let rects = "";
  for (let y = 0; y < n; y++) {
    for (let x = 0; x < n; x++) {
      if (!mod[y]![x]) continue;
      const px = (x + quiet) * modulePx;
      const py = (y + quiet) * modulePx;
      rects += `<rect x="${px}" y="${py}" width="${modulePx}" height="${modulePx}"/>`;
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${dim}" height="${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#fff"/>${rects}</svg>`;
}

export function qrSvg(text: string, modulePx = 4): string {
  return qrSvgFromBytes(new TextEncoder().encode(text), modulePx);
}
