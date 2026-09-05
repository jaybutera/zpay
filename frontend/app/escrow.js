/* zpay: the user's half of the native Zcash escrow, in the browser.

   This file is the client side of specs/zec-native-escrow.md. It exists
   because the sender pays from any Zcash wallet, and that wallet knows nothing
   about the escrow: it just sends coins to a t3 address. Somebody has to hold
   the user's key `u`, derive the 2-of-2 + timelock address that key sits in,
   pre-sign the release once the coins have landed, and sign the refund at `T`
   if nobody pays. That somebody is this page.

   Everything here is checked against crates/zecp2p-escrow, which is the code
   the LP runs. The check is frontend/app/test/escrow-vectors.js, driven by
   `cargo run -p zecp2p-escrow --example frontend_vectors`. A digest that
   disagrees with the LP's by one byte is a pre-signature that decrypts to a
   signature over the wrong transaction, and the LP finds out after it has paid
   the dollars; so nothing in this file is "close enough".

   Plain ES2020. No build step, no dependencies, no CDN. Works as a browser
   global (`Escrow`) and as a CommonJS module for the tests and the mock. */

'use strict';

const Escrow = (() => {

  // ======================================================================
  // bytes
  // ======================================================================

  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  function fromHex(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-fA-F]/.test(hex)) {
      throw new Error('not hex: ' + String(hex).slice(0, 20));
    }
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function concat(...parts) {
    let n = 0;
    for (const p of parts) n += p.length;
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const ascii = (s) => new TextEncoder().encode(s);
  const u32le = (n) => new Uint8Array([n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff]);
  function u64le(n) {
    let v = BigInt(n);
    const out = new Uint8Array(8);
    for (let i = 0; i < 8; i++) { out[i] = Number(v & 0xffn); v >>= 8n; }
    return out;
  }
  function compactSize(n) {
    if (n < 253) return new Uint8Array([n]);
    if (n <= 0xffff) return new Uint8Array([253, n & 0xff, n >> 8]);
    return concat(new Uint8Array([254]), u32le(n));
  }
  const reversed = (bytes) => Uint8Array.from(bytes).reverse();
  function bytesEq(a, b) {
    if (a.length !== b.length) return false;
    let d = 0;
    for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
    return d === 0;
  }

  // ======================================================================
  // SHA-256
  // ======================================================================

  const SHA_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function sha256(msg) {
    const len = msg.length;
    const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
    padded.set(msg);
    padded[len] = 0x80;
    const bits = BigInt(len) * 8n;
    for (let i = 0; i < 8; i++) padded[padded.length - 1 - i] = Number((bits >> BigInt(8 * i)) & 0xffn);

    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const W = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) {
        W[i] = (padded[off + 4 * i] << 24) | (padded[off + 4 * i + 1] << 16) | (padded[off + 4 * i + 2] << 8) | padded[off + 4 * i + 3];
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
        const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA_K[i] + W[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      out[4 * i] = H[i] >>> 24; out[4 * i + 1] = (H[i] >>> 16) & 0xff; out[4 * i + 2] = (H[i] >>> 8) & 0xff; out[4 * i + 3] = H[i] & 0xff;
    }
    return out;
  }

  const sha256d = (m) => sha256(sha256(m));

  /** BIP 340 tagged hash: sha256(sha256(tag) || sha256(tag) || data). */
  function taggedHash(tag, data) {
    const t = sha256(ascii(tag));
    return sha256(concat(t, t, data));
  }

  // ======================================================================
  // RIPEMD-160, for hash160 and therefore the t3 address
  // ======================================================================

  const RMD_R = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
  ];
  const RMD_RR = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
  ];
  const RMD_S = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
  ];
  const RMD_SS = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
  ];
  const RMD_K = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const RMD_KK = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

  function ripemd160(msg) {
    const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
    const f = (j, x, y, z) =>
      j < 16 ? x ^ y ^ z :
      j < 32 ? (x & y) | (~x & z) :
      j < 48 ? (x | ~y) ^ z :
      j < 64 ? (x & z) | (y & ~z) :
      x ^ (y | ~z);

    const len = msg.length;
    const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
    padded.set(msg);
    padded[len] = 0x80;
    const bits = BigInt(len) * 8n;
    for (let i = 0; i < 8; i++) padded[padded.length - 8 + i] = Number((bits >> BigInt(8 * i)) & 0xffn);

    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const X = new Uint32Array(16);
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) {
        X[i] = padded[off + 4 * i] | (padded[off + 4 * i + 1] << 8) | (padded[off + 4 * i + 2] << 16) | (padded[off + 4 * i + 3] << 24);
      }
      let A = h0, B = h1, C = h2, D = h3, E = h4;
      let AA = h0, BB = h1, CC = h2, DD = h3, EE = h4;
      for (let j = 0; j < 80; j++) {
        let T = rotl((A + f(j, B, C, D) + X[RMD_R[j]] + RMD_K[j >> 4]) >>> 0, RMD_S[j]);
        T = (T + E) >>> 0;
        A = E; E = D; D = rotl(C, 10); C = B; B = T;
        T = rotl((AA + f(79 - j, BB, CC, DD) + X[RMD_RR[j]] + RMD_KK[j >> 4]) >>> 0, RMD_SS[j]);
        T = (T + EE) >>> 0;
        AA = EE; EE = DD; DD = rotl(CC, 10); CC = BB; BB = T;
      }
      const T = (h1 + C + DD) >>> 0;
      h1 = (h2 + D + EE) >>> 0;
      h2 = (h3 + E + AA) >>> 0;
      h3 = (h4 + A + BB) >>> 0;
      h4 = (h0 + B + CC) >>> 0;
      h0 = T;
    }
    const out = new Uint8Array(20);
    [h0, h1, h2, h3, h4].forEach((h, i) => {
      out[4 * i] = h & 0xff; out[4 * i + 1] = (h >>> 8) & 0xff; out[4 * i + 2] = (h >>> 16) & 0xff; out[4 * i + 3] = h >>> 24;
    });
    return out;
  }

  const hash160 = (data) => ripemd160(sha256(data));

  // ======================================================================
  // BLAKE2b-256 with a 16-byte personalization: the ZIP 244 hash
  // ======================================================================
  //
  // 64-bit words are kept as pairs of 32-bit words (low, high), since the
  // arithmetic is all additions, rotations and xors and BigInt would make the
  // sighash of one transaction take a visible fraction of a second.

  const B2B_IV32 = new Uint32Array([
    0xf3bcc908, 0x6a09e667, 0x84caa73b, 0xbb67ae85, 0xfe94f82b, 0x3c6ef372, 0x5f1d36f1, 0xa54ff53a,
    0xade682d1, 0x510e527f, 0x2b3e6c1f, 0x9b05688c, 0xfb41bd6b, 0x1f83d9ab, 0x137e2179, 0x5be0cd19,
  ]);
  const B2B_SIGMA = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
  ].map((x) => x * 2);

  function blake2b(msg, outlen, personal) {
    const v = new Uint32Array(32);
    const m = new Uint32Array(32);
    const h = new Uint32Array(16);
    const b = new Uint8Array(128);
    let t = 0;   // bytes hashed so far; safe as a double for anything we hash
    let c = 0;   // bytes in b

    const ADD64AA = (a, bb) => {
      const o0 = v[a] + v[bb];
      let o1 = v[a + 1] + v[bb + 1];
      if (o0 >= 0x100000000) o1++;
      v[a] = o0; v[a + 1] = o1;
    };
    const ADD64AC = (a, b0, b1) => {
      let o0 = v[a] + b0;
      if (b0 < 0) o0 += 0x100000000;
      let o1 = v[a + 1] + b1;
      if (o0 >= 0x100000000) o1++;
      v[a] = o0; v[a + 1] = o1;
    };
    const get32 = (arr, i) => arr[i] ^ (arr[i + 1] << 8) ^ (arr[i + 2] << 16) ^ (arr[i + 3] << 24);
    const G = (a, bb, cc, d, ix, iy) => {
      const x0 = m[ix], x1 = m[ix + 1], y0 = m[iy], y1 = m[iy + 1];
      ADD64AA(a, bb); ADD64AC(a, x0, x1);
      let xor0 = v[d] ^ v[a], xor1 = v[d + 1] ^ v[a + 1];
      v[d] = xor1; v[d + 1] = xor0;
      ADD64AA(cc, d);
      xor0 = v[bb] ^ v[cc]; xor1 = v[bb + 1] ^ v[cc + 1];
      v[bb] = (xor0 >>> 24) ^ (xor1 << 8); v[bb + 1] = (xor1 >>> 24) ^ (xor0 << 8);
      ADD64AA(a, bb); ADD64AC(a, y0, y1);
      xor0 = v[d] ^ v[a]; xor1 = v[d + 1] ^ v[a + 1];
      v[d] = (xor0 >>> 16) ^ (xor1 << 16); v[d + 1] = (xor1 >>> 16) ^ (xor0 << 16);
      ADD64AA(cc, d);
      xor0 = v[bb] ^ v[cc]; xor1 = v[bb + 1] ^ v[cc + 1];
      v[bb] = (xor1 >>> 31) ^ (xor0 << 1); v[bb + 1] = (xor0 >>> 31) ^ (xor1 << 1);
    };
    const compress = (last) => {
      for (let i = 0; i < 16; i++) { v[i] = h[i]; v[i + 16] = B2B_IV32[i]; }
      v[24] ^= t; v[25] ^= t / 0x100000000;
      if (last) { v[28] = ~v[28]; v[29] = ~v[29]; }
      for (let i = 0; i < 32; i++) m[i] = get32(b, 4 * i);
      for (let i = 0; i < 12; i++) {
        const s = i * 16;
        G(0, 8, 16, 24, B2B_SIGMA[s + 0], B2B_SIGMA[s + 1]);
        G(2, 10, 18, 26, B2B_SIGMA[s + 2], B2B_SIGMA[s + 3]);
        G(4, 12, 20, 28, B2B_SIGMA[s + 4], B2B_SIGMA[s + 5]);
        G(6, 14, 22, 30, B2B_SIGMA[s + 6], B2B_SIGMA[s + 7]);
        G(0, 10, 20, 30, B2B_SIGMA[s + 8], B2B_SIGMA[s + 9]);
        G(2, 12, 22, 24, B2B_SIGMA[s + 10], B2B_SIGMA[s + 11]);
        G(4, 14, 16, 26, B2B_SIGMA[s + 12], B2B_SIGMA[s + 13]);
        G(6, 8, 18, 28, B2B_SIGMA[s + 14], B2B_SIGMA[s + 15]);
      }
      for (let i = 0; i < 16; i++) h[i] = h[i] ^ v[i] ^ v[i + 16];
    };

    // Parameter block: digest length, no key, fanout 1, depth 1, and the
    // personalization in the last sixteen bytes (words 12..15).
    for (let i = 0; i < 16; i++) h[i] = B2B_IV32[i];
    h[0] ^= 0x01010000 ^ outlen;
    if (personal) {
      if (personal.length !== 16) throw new Error('personalization must be 16 bytes');
      for (let i = 0; i < 4; i++) h[12 + i] ^= get32(personal, 4 * i);
    }

    for (let i = 0; i < msg.length; i++) {
      if (c === 128) { t += c; compress(false); c = 0; }
      b[c++] = msg[i];
    }
    t += c;
    while (c < 128) b[c++] = 0;
    compress(true);

    const out = new Uint8Array(outlen);
    for (let i = 0; i < outlen; i++) out[i] = h[i >> 2] >> (8 * (i & 3));
    return out;
  }

  const blake2b256 = (msg, personal) => blake2b(msg, 32, personal);

  // ======================================================================
  // secp256k1
  // ======================================================================

  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

  const mod = (x, m) => ((x % m) + m) % m;
  function modPow(base, exp, m) {
    let r = 1n, b = mod(base, m), e = exp;
    while (e > 0n) {
      if (e & 1n) r = (r * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return r;
  }
  function invMod(x, m) {
    let [old_r, r] = [mod(x, m), m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    if (old_r !== 1n) throw new Error('no inverse');
    return mod(old_s, m);
  }

  const bigToBytes = (n, len) => fromHex(n.toString(16).padStart(len * 2, '0'));
  const bytesToBig = (b) => BigInt('0x' + (toHex(b) || '0'));

  // Jacobian points {X, Y, Z}; Z = 0 is the point at infinity.
  const INF = { X: 0n, Y: 1n, Z: 0n };
  const G = { X: Gx, Y: Gy, Z: 1n };

  function jDouble(p) {
    if (p.Z === 0n || p.Y === 0n) return INF;
    const Y2 = (p.Y * p.Y) % P;
    const S = (4n * p.X * Y2) % P;
    const M = (3n * p.X * p.X) % P;
    const X3 = mod(M * M - 2n * S, P);
    const Y3 = mod(M * (S - X3) - 8n * Y2 * Y2, P);
    const Z3 = (2n * p.Y * p.Z) % P;
    return { X: X3, Y: Y3, Z: Z3 };
  }
  function jAdd(p, q) {
    if (p.Z === 0n) return q;
    if (q.Z === 0n) return p;
    const Z1Z1 = (p.Z * p.Z) % P, Z2Z2 = (q.Z * q.Z) % P;
    const U1 = (p.X * Z2Z2) % P, U2 = (q.X * Z1Z1) % P;
    const S1 = (p.Y * Z2Z2 * q.Z) % P, S2 = (q.Y * Z1Z1 * p.Z) % P;
    if (U1 === U2) {
      if (S1 !== S2) return INF;
      return jDouble(p);
    }
    const H = mod(U2 - U1, P), R = mod(S2 - S1, P);
    const HH = (H * H) % P, HHH = (HH * H) % P;
    const V = (U1 * HH) % P;
    const X3 = mod(R * R - HHH - 2n * V, P);
    const Y3 = mod(R * (V - X3) - S1 * HHH, P);
    const Z3 = (H * p.Z * q.Z) % P;
    return { X: X3, Y: Y3, Z: Z3 };
  }
  function jMul(k, p) {
    let r = INF, a = p, n = mod(k, N);
    while (n > 0n) {
      if (n & 1n) r = jAdd(r, a);
      a = jDouble(a);
      n >>= 1n;
    }
    return r;
  }
  function toAffine(p) {
    if (p.Z === 0n) return null;
    const zi = invMod(p.Z, P), zi2 = (zi * zi) % P;
    return { x: (p.X * zi2) % P, y: (p.Y * zi2 * zi) % P };
  }
  const fromAffine = (a) => a ? { X: a.x, Y: a.y, Z: 1n } : INF;

  /** k*G as an affine point. */
  const mulG = (k) => toAffine(jMul(k, G));
  /** k*Q for an affine Q. */
  const mulPoint = (k, q) => toAffine(jMul(k, fromAffine(q)));
  /** a*G + b*Q. */
  const mulAdd = (a, b, q) => toAffine(jAdd(jMul(a, G), jMul(b, fromAffine(q))));
  const addPoints = (a, b) => toAffine(jAdd(fromAffine(a), fromAffine(b)));
  const negPoint = (a) => a ? { x: a.x, y: mod(-a.y, P) } : null;

  function pointToBytes(p) {
    if (!p) throw new Error('cannot serialize the point at infinity');
    return concat(new Uint8Array([(p.y & 1n) === 0n ? 2 : 3]), bigToBytes(p.x, 32));
  }
  function pointFromBytes(b) {
    if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) throw new Error('not a compressed public key');
    const x = bytesToBig(b.slice(1));
    if (x >= P) throw new Error('public key x out of range');
    const y2 = mod(x * x * x + 7n, P);
    let y = modPow(y2, (P + 1n) / 4n, P);
    if ((y * y) % P !== y2) throw new Error('public key is not on the curve');
    if ((y & 1n) !== BigInt(b[0] & 1)) y = P - y;
    return { x, y };
  }

  function randomScalar() {
    for (;;) {
      const raw = new Uint8Array(32);
      crypto.getRandomValues(raw);
      const d = bytesToBig(raw);
      if (d !== 0n && d < N) return d;
    }
  }
  const scalarFromBytes = (b) => {
    const d = bytesToBig(b);
    if (d === 0n || d >= N) throw new Error('scalar out of range');
    return d;
  };
  const pubkey = (d) => pointToBytes(mulG(d));

  // ======================================================================
  // ECDSA over a 32-byte digest, low-S, DER + SIGHASH_ALL
  // ======================================================================

  function ecdsaSign(d, digest) {
    const z = mod(bytesToBig(digest), N);
    for (;;) {
      const k = randomScalar();
      const R = mulG(k);
      const r = mod(R.x, N);
      if (r === 0n) continue;
      let s = mod(invMod(k, N) * (z + r * d), N);
      if (s === 0n) continue;
      if (s > N / 2n) s = N - s;
      return { r, s };
    }
  }

  function ecdsaVerify(pub, digest, sig) {
    if (sig.r <= 0n || sig.r >= N || sig.s <= 0n || sig.s >= N) return false;
    const z = mod(bytesToBig(digest), N);
    const w = invMod(sig.s, N);
    const pt = mulAdd(mod(z * w, N), mod(sig.r * w, N), pub);
    return !!pt && mod(pt.x, N) === sig.r;
  }

  function derInt(n) {
    let b = bigToBytes(n, 32);
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = concat(new Uint8Array([0]), b);
    return concat(new Uint8Array([0x02, b.length]), b);
  }
  /** DER with the SIGHASH_ALL byte, exactly as tx::encode_signature writes it. */
  function encodeSignature(sig) {
    const s = sig.s > N / 2n ? N - sig.s : sig.s;
    const body = concat(derInt(sig.r), derInt(s));
    return concat(new Uint8Array([0x30, body.length]), body, new Uint8Array([0x01]));
  }

  // ======================================================================
  // ECDSA adaptor signatures with a DLEQ proof: the libsecp256k1-zkp format
  // ======================================================================
  //
  // The 162-byte layout is R (33) || R' (33) || s' (32) || e (32) || s (32),
  // where R = k*Y, R' = k*G, and (e, s) proves log_G(R') = log_Y(R). This is
  // what `EcdsaAdaptorSignature::from_slice` in secp256k1-zkp reads, and the
  // vectors check that the LP's `verify` accepts what this produces.

  function dleqChallenge(p1, gen2, p2, r1, r2) {
    const data = concat(pointToBytes(p1), pointToBytes(gen2), pointToBytes(p2), pointToBytes(r1), pointToBytes(r2));
    return mod(bytesToBig(taggedHash('DLEQ', data)), N);
  }

  /** Proves p1 = sk*G and p2 = sk*gen2 share a discrete log. */
  function dleqProve(sk, gen2, p1, p2) {
    const k = randomScalar();
    const r1 = mulG(k);
    const r2 = mulPoint(k, gen2);
    const e = dleqChallenge(p1, gen2, p2, r1, r2);
    const s = mod(k + e * sk, N);
    return { e, s };
  }

  function dleqVerify(proof, p1, gen2, p2) {
    const negE = mod(-proof.e, N);
    const r1 = mulAdd(proof.s, negE, p1);                       // s*G - e*P1
    const r2 = addPoints(mulPoint(proof.s, gen2), mulPoint(negE, p2)); // s*Y - e*P2
    if (!r1 || !r2) return false;
    return dleqChallenge(p1, gen2, p2, r1, r2) === proof.e;
  }

  /** The user's pre-signature over `digest`, encrypted under Y (spec 5.3). */
  function adaptorEncrypt(d, digest, Y) {
    for (;;) {
      const k = randomScalar();
      const Rp = mulG(k);            // R' = k*G
      const R = mulPoint(k, Y);      // R  = k*Y
      const sigr = mod(R.x, N);
      if (sigr === 0n) continue;
      const proof = dleqProve(k, Y, Rp, R);
      const z = mod(bytesToBig(digest), N);
      const sp = mod(invMod(k, N) * (z + sigr * d), N);
      if (sp === 0n) continue;
      return concat(pointToBytes(R), pointToBytes(Rp), bigToBytes(sp, 32), bigToBytes(proof.e, 32), bigToBytes(proof.s, 32));
    }
  }

  function adaptorParse(bytes) {
    if (bytes.length !== 162) throw new Error('an adaptor signature is 162 bytes');
    const R = pointFromBytes(bytes.slice(0, 33));
    const Rp = pointFromBytes(bytes.slice(33, 66));
    const sp = bytesToBig(bytes.slice(66, 98));
    const e = bytesToBig(bytes.slice(98, 130));
    const s = bytesToBig(bytes.slice(130, 162));
    if (sp === 0n || sp >= N || s >= N) throw new Error('adaptor signature scalar out of range');
    return { R, Rp, sp, e: mod(e, N), s, sigr: mod(R.x, N) };
  }

  /** What the LP checks before it pays (spec 5.3 step 5). */
  function adaptorVerify(bytes, digest, pub, Y) {
    let a;
    try { a = adaptorParse(bytes); } catch (_) { return false; }
    if (a.sigr === 0n) return false;
    if (!dleqVerify({ e: a.e, s: a.s }, a.Rp, Y, a.R)) return false;
    const z = mod(bytesToBig(digest), N);
    const w = invMod(a.sp, N);
    const expect = mulAdd(mod(z * w, N), mod(a.sigr * w, N), pub);
    return !!expect && expect.x === a.Rp.x && expect.y === a.Rp.y;
  }

  /** Completes the pre-signature with the attestor's scalar (spec 5.6). */
  function adaptorDecrypt(bytes, y) {
    const a = adaptorParse(bytes);
    let s = mod(a.sp * invMod(y, N), N);
    if (s > N / 2n) s = N - s;
    return { r: a.sigr, s };
  }

  /** Re-derives the scalar from an on-chain signature (spec 5.6, last line). */
  function adaptorRecover(bytes, sig, Y) {
    const a = adaptorParse(bytes);
    let y = mod(a.sp * invMod(sig.s, N), N);
    const Yg = mulG(y);
    if (Yg.x === Y.x && Yg.y === Y.y) return y;
    y = N - y;
    const Yg2 = mulG(y);
    if (Yg2.x === Y.x && Yg2.y === Y.y) return y;
    throw new Error('the signature was not made from this pre-signature');
  }

  // ======================================================================
  // The escrow script, its address, and the two spends (spec 4)
  // ======================================================================

  const OP = { IF: 0x63, ELSE: 0x67, ENDIF: 0x68, DROP: 0x75, PUSH_0: 0x00, PUSH_1: 0x51, PUSH_2: 0x52,
    CHECKMULTISIG: 0xae, CHECKSIG: 0xac, CLTV: 0xb1, HASH160: 0xa9, EQUAL: 0x87, DUP: 0x76, EQUALVERIFY: 0x88 };

  function encodeScriptNum(n) {
    if (n === 0) return new Uint8Array(0);
    if (n < 0 || n > 0x7fffffff) throw new Error('height out of range');
    const out = [];
    let v = n;
    while (v > 0) { out.push(v & 0xff); v = Math.floor(v / 256); }
    if (out[out.length - 1] & 0x80) out.push(0);
    return new Uint8Array(out);
  }
  function pushData(data) {
    const n = data.length;
    if (n < 0x4c) return concat(new Uint8Array([n]), data);
    if (n <= 0xff) return concat(new Uint8Array([0x4c, n]), data);
    return concat(new Uint8Array([0x4d, n & 0xff, n >> 8]), data);
  }

  function redeemScript(uPub, lPub, refundHeight) {
    return concat(
      new Uint8Array([OP.IF, OP.PUSH_2]), pushData(uPub), pushData(lPub), new Uint8Array([OP.PUSH_2, OP.CHECKMULTISIG]),
      new Uint8Array([OP.ELSE]), pushData(encodeScriptNum(refundHeight)), new Uint8Array([OP.CLTV, OP.DROP]),
      pushData(uPub), new Uint8Array([OP.CHECKSIG, OP.ENDIF]),
    );
  }
  const p2shScript = (redeem) => concat(new Uint8Array([OP.HASH160]), pushData(hash160(redeem)), new Uint8Array([OP.EQUAL]));
  const p2pkhScript = (h) => concat(new Uint8Array([OP.DUP, OP.HASH160]), pushData(h), new Uint8Array([OP.EQUALVERIFY, OP.CHECKSIG]));
  const releaseScriptSig = (sigU, sigL, redeem) =>
    concat(new Uint8Array([OP.PUSH_0]), pushData(sigU), pushData(sigL), new Uint8Array([OP.PUSH_1]), pushData(redeem));
  const refundScriptSig = (sigU, redeem) => concat(pushData(sigU), new Uint8Array([OP.PUSH_0]), pushData(redeem));

  // ---------- base58check and t-addresses ----------

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const PREFIX = {
    main: { p2pkh: [0x1c, 0xb8], p2sh: [0x1c, 0xbd] },   // t1, t3
    test: { p2pkh: [0x1d, 0x25], p2sh: [0x1c, 0xba] },   // tm, t2
  };

  function base58check(prefix, hash) {
    const payload = concat(new Uint8Array(prefix), hash);
    const full = concat(payload, sha256d(payload).slice(0, 4));
    let n = bytesToBig(full);
    let s = '';
    while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
    for (const b of full) { if (b !== 0) break; s = '1' + s; }
    return s;
  }
  function base58decode(str) {
    let n = 0n;
    for (const c of str) {
      const i = B58.indexOf(c);
      if (i < 0) throw new Error(`"${c}" is not a base58 character`);
      n = n * 58n + BigInt(i);
    }
    let bytes = n === 0n ? new Uint8Array(0) : bigToBytes(n, Math.ceil(n.toString(16).length / 2));
    let zeros = 0;
    for (const c of str) { if (c !== '1') break; zeros++; }
    return concat(new Uint8Array(zeros), bytes);
  }

  const escrowAddress = (redeem, network) => base58check(PREFIX[network].p2sh, hash160(redeem));

  /** scriptPubKey for a t1/t3 (or tm/t2) address, refusing the wrong network. */
  function scriptForAddress(addr, network) {
    const full = base58decode(addr.trim());
    if (full.length !== 26) throw new Error('that is not a transparent Zcash address');
    const payload = full.slice(0, 22), check = full.slice(22);
    if (!bytesEq(check, sha256d(payload).slice(0, 4))) throw new Error('address checksum does not match; it is mistyped');
    const pre = [full[0], full[1]];
    const hash = full.slice(2, 22);
    for (const [net, kinds] of Object.entries(PREFIX)) {
      for (const [kind, p] of Object.entries(kinds)) {
        if (p[0] === pre[0] && p[1] === pre[1]) {
          if (net !== network) throw new Error(`that is a ${net}net address and this page is on ${network}net`);
          return kind === 'p2sh' ? concat(new Uint8Array([OP.HASH160]), pushData(hash), new Uint8Array([OP.EQUAL])) : p2pkhScript(hash);
        }
      }
    }
    throw new Error('not a transparent Zcash address (t1… or t3…)');
  }

  function zecString(zat) {
    const v = BigInt(zat);
    const whole = v / 100000000n;
    const frac = (v % 100000000n).toString().padStart(8, '0').replace(/0+$/, '');
    return frac ? `${whole}.${frac}` : String(whole);
  }
  /** A ZIP 321 URI with the amount filled in. */
  const zip321 = (address, amountZat) => `zcash:${address}?amount=${zecString(amountZat)}`;

  // ---------- ZIP 317 fees, as fees.rs computes them ----------

  const MARGINAL_FEE_ZAT = 5000, GRACE_ACTIONS = 2, P2PKH_IN = 150, P2PKH_OUT = 34, MAX_SIG = 73;
  const pushLen = (n) => (n < 0x4c ? 1 : n <= 0xff ? 2 : 3) + n;
  const compactLen = (n) => (n < 253 ? 1 : n <= 0xffff ? 3 : 5);
  const txinSize = (ss) => 36 + compactLen(ss) + ss + 4;
  function conventionalFee(inBytes, outBytes, shielded) {
    const tIn = Math.ceil(inBytes / P2PKH_IN), tOut = Math.ceil(outBytes / P2PKH_OUT);
    const actions = Math.max(tIn, tOut) + shielded;
    return MARGINAL_FEE_ZAT * Math.max(actions, GRACE_ACTIONS);
  }
  const releaseFee = (redeemLen, nOutputs) =>
    conventionalFee(txinSize(1 + pushLen(MAX_SIG) + pushLen(MAX_SIG) + 1 + pushLen(redeemLen)), nOutputs * P2PKH_OUT, 0);
  const refundFeeTransparent = (redeemLen) =>
    conventionalFee(txinSize(pushLen(MAX_SIG) + 1 + pushLen(redeemLen)), P2PKH_OUT, 0);

  // ---------- v5 transactions and the ZIP 244 digests ----------

  const TX_VERSION_V5 = 0x80000005;
  const VERSION_GROUP_V5 = 0x26a7270a;
  const RELEASE_SEQUENCE = 0xffffffff;
  const REFUND_SEQUENCE = 0xfffffffe;

  /** The release's output set, in the order ReleaseSplit::outputs fixes. */
  function releaseOutputs(amountZat, split) {
    const committed = split.minerFeeZat + split.platformFeeZat;
    const payout = amountZat - committed;
    if (!(payout > 0)) throw new Error('the escrow does not cover the fees');
    const outs = [{ script: split.payoutScript, valueZat: payout }];
    if (split.platformFeeZat > 0) {
      if (!split.treasuryScript || !split.treasuryScript.length) throw new Error('a platform fee with no treasury script');
      outs.push({ script: split.treasuryScript, valueZat: split.platformFeeZat });
    }
    return outs;
  }

  /** One-input, transparent-only v5 transaction description. */
  function escrowTx(terms, outputs, sequence, lockTime) {
    for (const o of outputs) if (!o.script || !o.script.length) throw new Error('an output with an empty script');
    return {
      branchId: terms.consensusBranchId,
      lockTime,
      expiryHeight: 0,
      input: {
        txid: terms.fundingTxid,            // internal byte order
        vout: terms.vout,
        sequence,
        valueZat: terms.amountZat,
        scriptPubKey: terms.scriptPubKey,
      },
      outputs,
    };
  }
  const buildRelease = (terms, split) => escrowTx(terms, releaseOutputs(terms.amountZat, split), RELEASE_SEQUENCE, 0);
  function buildRefund(terms, userScript, feeZat) {
    const value = terms.amountZat - feeZat;
    if (!(value > 0)) throw new Error('the escrow does not cover the refund fee');
    return escrowTx(terms, [{ script: userScript, valueZat: value }], REFUND_SEQUENCE, terms.refundHeight);
  }

  const pers = (s) => { const b = ascii(s); if (b.length !== 16) throw new Error('bad personalization ' + s); return b; };
  const serOutput = (o) => concat(u64le(o.valueZat), compactSize(o.script.length), o.script);
  const serPrevout = (i) => concat(i.txid, u32le(i.vout));

  function headerDigest(tx) {
    return blake2b256(concat(u32le(TX_VERSION_V5), u32le(VERSION_GROUP_V5), u32le(tx.branchId), u32le(tx.lockTime), u32le(tx.expiryHeight)), pers('ZTxIdHeadersHash'));
  }
  const prevoutsDigest = (tx) => blake2b256(serPrevout(tx.input), pers('ZTxIdPrevoutHash'));
  const sequenceDigest = (tx) => blake2b256(u32le(tx.input.sequence), pers('ZTxIdSequencHash'));
  const outputsDigest = (tx) => blake2b256(concat(...tx.outputs.map(serOutput)), pers('ZTxIdOutputsHash'));
  const emptySapling = () => blake2b256(new Uint8Array(0), pers('ZTxIdSaplingHash'));
  const emptyOrchard = () => blake2b256(new Uint8Array(0), pers('ZTxIdOrchardHash'));
  const txHashPers = (branchId) => concat(ascii('ZcashTxHash_'), u32le(branchId));

  /** The ZIP 244 txid, internal byte order. */
  function txid(tx) {
    const transparent = blake2b256(concat(prevoutsDigest(tx), sequenceDigest(tx), outputsDigest(tx)), pers('ZTxIdTranspaHash'));
    return blake2b256(concat(headerDigest(tx), transparent, emptySapling(), emptyOrchard()), txHashPers(tx.branchId));
  }

  /** The SIGHASH_ALL digest for the single transparent input (spec 4.6). */
  function sighash(tx) {
    const i = tx.input;
    const amounts = blake2b256(u64le(i.valueZat), pers('ZTxTrAmountsHash'));
    const scripts = blake2b256(concat(compactSize(i.scriptPubKey.length), i.scriptPubKey), pers('ZTxTrScriptsHash'));
    const txin = blake2b256(concat(serPrevout(i), u64le(i.valueZat), compactSize(i.scriptPubKey.length), i.scriptPubKey, u32le(i.sequence)), pers('Zcash___TxInHash'));
    const transparent = blake2b256(
      concat(new Uint8Array([0x01]), prevoutsDigest(tx), amounts, scripts, sequenceDigest(tx), outputsDigest(tx), txin),
      pers('ZTxIdTranspaHash'),
    );
    return blake2b256(concat(headerDigest(tx), transparent, emptySapling(), emptyOrchard()), txHashPers(tx.branchId));
  }

  /** The bytes a node accepts, ZIP 225 layout. */
  function serialize(tx, scriptSig) {
    const i = tx.input;
    return concat(
      u32le(TX_VERSION_V5), u32le(VERSION_GROUP_V5), u32le(tx.branchId), u32le(tx.lockTime), u32le(tx.expiryHeight),
      compactSize(1), serPrevout(i), compactSize(scriptSig.length), scriptSig, u32le(i.sequence),
      compactSize(tx.outputs.length), ...tx.outputs.map(serOutput),
      new Uint8Array([0, 0]),   // no Sapling spends, no Sapling outputs
      new Uint8Array([0]),      // no Orchard actions
    );
  }

  // ======================================================================
  // Terms, the event, the outcome point (spec 5.1, 5.2)
  // ======================================================================

  /** Canonical JSON exactly as terms.rs writes it: sorted keys, no
      whitespace, integers as decimal strings, funding_txid in internal order. */
  function canonicalJson(t) {
    return '{' +
      `"amount_zat":"${t.amountZat}",` +
      `"funding_txid":"${toHex(t.fundingTxid)}",` +
      `"l_pub":"${toHex(t.lPub)}",` +
      `"lock_confirmed_ms":"${t.lockConfirmedMs}",` +
      `"payee_hash":"${toHex(t.payeeHash)}",` +
      `"platform_fee_zat":"${t.platformFeeZat}",` +
      `"rate_18dec":"${t.rate18dec}",` +
      `"refund_height":"${t.refundHeight}",` +
      `"treasury_script":"${toHex(t.treasuryScript)}",` +
      `"u_pub":"${toHex(t.uPub)}",` +
      `"usd_amount_6dec":"${t.usdAmount6dec}",` +
      `"vout":"${t.vout}"` +
      '}';
  }
  const termsHash = (t) => sha256(ascii(canonicalJson(t)));
  const intentHash = (t) => sha256(concat(ascii('zecp2p-intent-v1'), ascii(canonicalJson(t))));
  const eventId = (fundingTxid, vout) => sha256(concat(ascii('zecp2p-escrow-v1'), fundingTxid, u32le(vout)));

  const IDENTITY_RATE_18DEC = '1000000000000000000';
  const OUTCOME_PAID = 'paid';

  function outcomeChallenge(R, Pk, event, tHash) {
    const e = bytesToBig(taggedHash('zecp2p-outcome-v1', concat(pointToBytes(R), pointToBytes(Pk), event, tHash, ascii(OUTCOME_PAID))));
    if (e === 0n || e >= N) throw new Error('outcome challenge out of range');
    return e;
  }
  /** Y = R + e*P. */
  function outcomePoint(R, Pk, event, tHash) {
    const e = outcomeChallenge(R, Pk, event, tHash);
    const y = addPoints(R, mulPoint(e, Pk));
    if (!y) throw new Error('outcome point is infinity');
    return y;
  }
  /** The attestor's side, for the mock and the tests: s = k + e*d. */
  function signOutcome(k, d, event, tHash) {
    const R = mulG(k), Pk = mulG(d);
    const e = outcomeChallenge(R, Pk, event, tHash);
    return mod(k + e * d, N);
  }

  /** The WireTerms the coordinator relays, decoded into what the page uses. */
  function termsFromWire(w) {
    return {
      fundingTxid: fromHex(w.funding_txid),
      vout: Number(w.vout),
      amountZat: Number(w.amount_zat),
      uPub: fromHex(w.u_pub),
      lPub: fromHex(w.l_pub),
      refundHeight: Number(w.refund_height),
      usdAmount6dec: Number(w.usd_amount_6dec),
      rate18dec: String(w.rate_18dec),
      payeeHash: fromHex(w.payee_hash),
      lockConfirmedMs: Number(w.lock_confirmed_ms),
      platformFeeZat: Number(w.platform_fee_zat || 0),
      treasuryScript: fromHex(w.treasury_script || ''),
    };
  }
  function termsToWire(t) {
    return {
      funding_txid: toHex(t.fundingTxid), vout: t.vout, amount_zat: t.amountZat,
      u_pub: toHex(t.uPub), l_pub: toHex(t.lPub), refund_height: t.refundHeight,
      usd_amount_6dec: t.usdAmount6dec, rate_18dec: String(t.rate18dec), payee_hash: toHex(t.payeeHash),
      lock_confirmed_ms: t.lockConfirmedMs, platform_fee_zat: t.platformFeeZat, treasury_script: toHex(t.treasuryScript),
    };
  }

  // ======================================================================
  // The handshake, end to end (spec 5.3), as prepare_escrow does it
  // ======================================================================

  /** Escrow terms plus the derived scripts, for building spends. */
  function escrowTerms(t, consensusBranchId) {
    const redeem = redeemScript(t.uPub, t.lPub, t.refundHeight);
    return {
      fundingTxid: t.fundingTxid, vout: t.vout, amountZat: t.amountZat,
      uPub: t.uPub, lPub: t.lPub, refundHeight: t.refundHeight, consensusBranchId,
      redeemScript: redeem, scriptPubKey: p2shScript(redeem),
    };
  }

  /**
   * Builds and self-verifies the pre-signature. Every argument is something
   * the two parties must agree on exactly, and the whole canonical terms are
   * rebuilt here from what the page already knew and compared to what the LP
   * sent, so a field the LP changed is refused before anything is signed.
   *
   *   own:        { uPriv, amountZat, lPub, refundHeight, usdAmount6dec,
   *                 payeeHash, platformFeeZat, treasuryScript }
   *   chain:      { fundingTxid (internal order), vout, consensusBranchId }
   *   lpTerms:    WireTerms as relayed
   *   announce:   { P, R, eventId } as bytes
   *   pinnedP:    the attestor key the page trusts, 33 bytes
   *   payout:     { lpOutputScript, minerFeeZat }
   */
  function prepareEscrow(own, chain, lpTerms, announce, pinnedP, payout) {
    const uPub = pubkey(own.uPriv);
    const lp = termsFromWire(lpTerms);

    const canonical = {
      fundingTxid: chain.fundingTxid, vout: chain.vout, amountZat: own.amountZat,
      uPub, lPub: own.lPub, refundHeight: own.refundHeight,
      usdAmount6dec: own.usdAmount6dec, rate18dec: IDENTITY_RATE_18DEC, payeeHash: own.payeeHash,
      lockConfirmedMs: lp.lockConfirmedMs,
      platformFeeZat: own.platformFeeZat, treasuryScript: own.treasuryScript,
    };
    const ours = termsHash(canonical), theirs = termsHash(lp);
    if (!bytesEq(ours, theirs)) {
      throw new Error('The terms the payer sent are not the ones you accepted. Nothing was signed.');
    }

    if (!bytesEq(announce.P, pinnedP)) throw new Error('The announcement is not from the attestor this page trusts.');
    const expectEvent = eventId(chain.fundingTxid, chain.vout);
    if (!bytesEq(announce.eventId, expectEvent)) throw new Error('The announcement is for a different escrow.');

    const terms = escrowTerms(canonical, chain.consensusBranchId);
    const nOut = own.platformFeeZat > 0 ? 2 : 1;
    const expectFee = releaseFee(terms.redeemScript.length, nOut);
    if (payout.minerFeeZat !== expectFee) {
      throw new Error(`The payer proposes a ${payout.minerFeeZat} zat miner fee; the conventional fee is ${expectFee}.`);
    }

    const split = { payoutScript: payout.lpOutputScript, minerFeeZat: payout.minerFeeZat, platformFeeZat: own.platformFeeZat, treasuryScript: own.treasuryScript };
    const release = buildRelease(terms, split);
    const digest = sighash(release);

    const Y = outcomePoint(pointFromBytes(announce.R), pointFromBytes(announce.P), announce.eventId, ours);
    const preSig = adaptorEncrypt(own.uPriv, digest, Y);
    if (!adaptorVerify(preSig, digest, pointFromBytes(uPub), Y)) throw new Error('The pre-signature failed its own check.');

    return { preSignature: preSig, outcomePoint: Y, digest, terms, canonical, termsHash: ours, split, release };
  }

  /** The refund at T: signed by u alone, to any transparent address. */
  function signRefund(uPriv, terms, userScript, feeZat) {
    const tx = buildRefund(terms, userScript, feeZat);
    const digest = sighash(tx);
    const sig = encodeSignature(ecdsaSign(uPriv, digest));
    const scriptSig = refundScriptSig(sig, terms.redeemScript);
    return { tx, digest, scriptSig, raw: serialize(tx, scriptSig), txid: txid(tx) };
  }

  return {
    // bytes
    toHex, fromHex, concat, reversed, bytesEq, ascii, u32le, u64le, compactSize,
    // hashes
    sha256, sha256d, taggedHash, ripemd160, hash160, blake2b, blake2b256,
    // curve
    N, P, mod, invMod, randomScalar, scalarFromBytes, pubkey, mulG, mulPoint, addPoints, pointToBytes, pointFromBytes, bigToBytes, bytesToBig,
    ecdsaSign, ecdsaVerify, encodeSignature,
    dleqProve, dleqVerify, adaptorEncrypt, adaptorVerify, adaptorDecrypt, adaptorRecover, adaptorParse,
    // zcash
    redeemScript, p2shScript, p2pkhScript, releaseScriptSig, refundScriptSig, base58check, base58decode,
    escrowAddress, scriptForAddress, zecString, zip321,
    releaseFee, refundFeeTransparent, releaseOutputs, buildRelease, buildRefund, sighash, txid, serialize,
    // terms
    canonicalJson, termsHash, intentHash, eventId, outcomeChallenge, outcomePoint, signOutcome, termsFromWire, termsToWire,
    IDENTITY_RATE_18DEC, escrowTerms, prepareEscrow, signRefund,
  };
})();

if (typeof module !== 'undefined' && module.exports) module.exports = Escrow;
