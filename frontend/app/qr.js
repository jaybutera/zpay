/* Minimal QR encoder, byte mode, for the ZIP 321 payment URI.
   No build step and no CDN: the page that tells you which address to pay
   should not be loading code from a third party to draw it.

   Byte mode only, error correction level M, smallest version that fits.
   That covers a zcash: URI with a t-address and an amount, which is about
   80 characters, comfortably inside version 5. */

'use strict';

const QR = (() => {

  // ---------- GF(256) for Reed-Solomon ----------
  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (() => {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;      // the QR generator polynomial
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  const mul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];

  function rsGenerator(degree) {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
      const next = new Array(poly.length + 1).fill(0);
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= mul(poly[j], EXP[i]);
      }
      poly = next;
    }
    return poly;
  }

  function rsEncode(data, ecLen) {
    const gen = rsGenerator(ecLen);
    const res = new Array(ecLen).fill(0);
    for (const byte of data) {
      const factor = byte ^ res[0];
      res.shift();
      res.push(0);
      for (let i = 0; i < ecLen; i++) res[i] ^= mul(gen[i + 1], factor);
    }
    return res;
  }

  // ---------- version tables, error correction level M ----------
  // [total codewords, ec codewords per block, group1 blocks, group2 blocks]
  const VERSIONS = {
    1:  [26,   10, 1, 0],
    2:  [44,   16, 1, 0],
    3:  [70,   26, 1, 0],
    4:  [100,  18, 2, 0],
    5:  [134,  24, 2, 0],
    6:  [172,  16, 4, 0],
    7:  [196,  18, 4, 0],
    8:  [242,  22, 2, 2],
    9:  [292,  22, 3, 2],
    10: [346,  26, 4, 1],
  };

  const ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
  };

  // Format information for level M and each mask, pre-computed with the
  // BCH(15,5) code and the 0x5412 mask the spec fixes.
  const FORMAT_M = [
    0x5412, 0x5125, 0x5E7C, 0x5B4B, 0x45F9, 0x40CE, 0x4F97, 0x4AA0,
  ];

  // Version information for versions 7 and up, BCH(18,6).
  const VERSION_INFO = {
    7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3,
  };

  function capacityBytes(version) {
    const [total, ecPerBlock, g1, g2] = VERSIONS[version];
    const blocks = g1 + g2;
    const dataCodewords = total - ecPerBlock * blocks;
    // 4 bits mode + count bits, then the payload.
    const countBits = version < 10 ? 8 : 16;
    return dataCodewords - Math.ceil((4 + countBits) / 8);
  }

  function pickVersion(byteLen) {
    for (let v = 1; v <= 10; v++) {
      if (byteLen <= capacityBytes(v)) return v;
    }
    throw new Error('payload too long for this encoder');
  }

  // ---------- bit stream ----------
  function buildData(bytes, version) {
    const [total, ecPerBlock, g1, g2] = VERSIONS[version];
    const blocks = g1 + g2;
    const dataCodewords = total - ecPerBlock * blocks;

    const bits = [];
    const push = (val, len) => {
      for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1);
    };

    push(0b0100, 4);                                  // byte mode
    push(bytes.length, version < 10 ? 8 : 16);
    for (const b of bytes) push(b, 8);

    // terminator, then pad to a byte boundary
    const capacityBits = dataCodewords * 8;
    for (let i = 0; i < 4 && bits.length < capacityBits; i++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);

    const words = [];
    for (let i = 0; i < bits.length; i += 8) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
      words.push(v);
    }
    // the two alternating pad bytes the spec names
    const PAD = [0xEC, 0x11];
    let k = 0;
    while (words.length < dataCodewords) words.push(PAD[k++ % 2]);

    // split into blocks, interleave data then ec
    const shortLen = Math.floor(dataCodewords / blocks);
    const dataBlocks = [];
    const ecBlocks = [];
    let pos = 0;
    for (let i = 0; i < blocks; i++) {
      const len = i < g1 ? shortLen : shortLen + 1;
      const block = words.slice(pos, pos + len);
      pos += len;
      dataBlocks.push(block);
      ecBlocks.push(rsEncode(block, ecPerBlock));
    }

    const out = [];
    const maxData = Math.max(...dataBlocks.map((b) => b.length));
    for (let i = 0; i < maxData; i++) {
      for (const block of dataBlocks) if (i < block.length) out.push(block[i]);
    }
    for (let i = 0; i < ecPerBlock; i++) {
      for (const block of ecBlocks) out.push(block[i]);
    }
    return out;
  }

  // ---------- matrix ----------
  function buildMatrix(version, codewords, mask) {
    const size = version * 4 + 17;
    const m = Array.from({ length: size }, () => new Array(size).fill(null));

    const setFinder = (r, c) => {
      for (let i = -1; i <= 7; i++) {
        for (let j = -1; j <= 7; j++) {
          const rr = r + i, cc = c + j;
          if (rr < 0 || rr >= size || cc < 0 || cc >= size) continue;
          const on = (i >= 0 && i <= 6 && (j === 0 || j === 6)) ||
                     (j >= 0 && j <= 6 && (i === 0 || i === 6)) ||
                     (i >= 2 && i <= 4 && j >= 2 && j <= 4);
          m[rr][cc] = on ? 1 : 0;
        }
      }
    };
    setFinder(0, 0);
    setFinder(0, size - 7);
    setFinder(size - 7, 0);

    // timing patterns
    for (let i = 8; i < size - 8; i++) {
      m[6][i] = i % 2 === 0 ? 1 : 0;
      m[i][6] = i % 2 === 0 ? 1 : 0;
    }

    // alignment patterns, skipping the ones that collide with finders
    const centers = ALIGN[version];
    for (const r of centers) {
      for (const c of centers) {
        if ((r <= 8 && c <= 8) || (r <= 8 && c >= size - 9) || (r >= size - 9 && c <= 8)) continue;
        for (let i = -2; i <= 2; i++) {
          for (let j = -2; j <= 2; j++) {
            m[r + i][c + j] = (Math.abs(i) === 2 || Math.abs(j) === 2 || (i === 0 && j === 0)) ? 1 : 0;
          }
        }
      }
    }

    // dark module, always set
    m[size - 8][8] = 1;

    // reserve format areas so data placement skips them
    const reserve = (r, c) => { if (m[r][c] === null) m[r][c] = 2; };
    for (let i = 0; i < 9; i++) { reserve(8, i); reserve(i, 8); }
    for (let i = 0; i < 8; i++) { reserve(8, size - 1 - i); reserve(size - 1 - i, 8); }
    if (version >= 7) {
      for (let i = 0; i < 6; i++) {
        for (let j = 0; j < 3; j++) {
          reserve(i, size - 11 + j);
          reserve(size - 11 + j, i);
        }
      }
    }

    // place the data, zig-zagging up and down two columns at a time
    let bitIdx = 0;
    const totalBits = codewords.length * 8;
    let upward = true;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--;                        // the timing column is skipped
      for (let n = 0; n < size; n++) {
        const row = upward ? size - 1 - n : n;
        for (let k = 0; k < 2; k++) {
          const c = col - k;
          if (m[row][c] !== null) continue;
          let bit = 0;
          if (bitIdx < totalBits) {
            bit = (codewords[bitIdx >> 3] >> (7 - (bitIdx & 7))) & 1;
            bitIdx++;
          }
          if (maskAt(mask, row, c)) bit ^= 1;
          m[row][c] = bit;
        }
      }
      upward = !upward;
    }

    // Format information. Bit 0 is the most significant of the 15, which is
    // the detail a decoder is unforgiving about: written least-significant
    // first every module of the data area still decodes and the symbol reads
    // as nothing at all.
    const fmt = FORMAT_M[mask];
    for (let i = 0; i < 15; i++) {
      const bit = (fmt >> (14 - i)) & 1;
      // around the top-left finder
      if (i < 6) m[8][i] = bit;
      else if (i === 6) m[8][7] = bit;
      else if (i === 7) m[8][8] = bit;
      else if (i === 8) m[7][8] = bit;
      else m[14 - i][8] = bit;
      // The split second copy. The lower run stops one short of the dark
      // module at [size-8][8], which is fixed and is not a format bit; writing
      // over it is a one-module error the whole symbol fails on.
      if (i < 7) m[size - 1 - i][8] = bit;
      else m[8][size - 15 + i] = bit;
    }

    // Restated after the format bits, because it sits inside the range they
    // are written across.
    m[size - 8][8] = 1;

    if (version >= 7) {
      const vi = VERSION_INFO[version];
      for (let i = 0; i < 18; i++) {
        const bit = (vi >> i) & 1;
        const r = Math.floor(i / 3);
        const c = i % 3;
        m[r][size - 11 + c] = bit;
        m[size - 11 + c][r] = bit;
      }
    }

    // anything still reserved but unwritten is light
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) if (m[r][c] === 2 || m[r][c] === null) m[r][c] = 0;
    }
    return m;
  }

  function maskAt(mask, r, c) {
    switch (mask) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      default: return (((r + c) % 2) + ((r * c) % 3)) % 2 === 0;
    }
  }

  /** Encode a string and return a square matrix of 0/1. */
  function encode(text) {
    const bytes = new TextEncoder().encode(text);
    const version = pickVersion(bytes.length);
    const codewords = buildData(bytes, version);
    // Mask 0 is used unconditionally. The spec's penalty scoring picks the
    // prettiest mask; every mask is decodable, and a payment URI is scanned
    // once from a bright screen.
    return buildMatrix(version, codewords, 0);
  }

  /** Draw onto a canvas, sized to fit whatever the element's box is. */
  function draw(canvas, text) {
    const m = encode(text);
    const n = m.length;
    const quiet = 4;
    const total = n + quiet * 2;
    const px = Math.max(1, Math.floor(canvas.width / total));
    const size = px * total;

    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');
    // Always light-on-dark-agnostic: a QR must be dark modules on white, so the
    // white is drawn rather than inherited from the page's dark background.
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (m[r][c]) ctx.fillRect((c + quiet) * px, (r + quiet) * px, px, px);
      }
    }
  }

  return { encode, draw };
})();
