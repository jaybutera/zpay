// Deciding whether a string is a Zcash address, rather than measuring it.
//
// U1-4. Both front ends checked a prefix and a length, so `t1AAAA…` and the
// repo's own placeholder (one character off a real address) were accepted and
// sent to 1Click as `refundTo`. 1Click's own validation is no backstop: it
// accepted both. A refund to a string that decodes to nothing is a refund
// nobody can spend.
//
// Two checksums, no dependencies:
//   - base58check over double SHA-256, for t1 and t3
//   - bech32m, for u1
//
// This is the same decision the coordinator makes in `near.rs`. It runs here so
// a typo is caught before a quote is taken, not so the server can trust it: the
// coordinator decodes every address it is given regardless of what the page did.

(function (global) {
  'use strict';

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

  // ---------- SHA-256 ----------
  // Written out because base58check needs it synchronously and WebCrypto's
  // digest is a promise; a validator that returns a promise cannot be called
  // from a submit handler's guard clause without restructuring both routes.

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(bytes) {
    const H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    const len = bytes.length;
    const withPad = new Uint8Array((((len + 8) >> 6) + 1) << 6);
    withPad.set(bytes);
    withPad[len] = 0x80;
    // Length in bits, big-endian, in the last eight bytes. Addresses are tens
    // of bytes, so the high word is always zero.
    const bits = len * 8;
    new DataView(withPad.buffer).setUint32(withPad.length - 4, bits >>> 0);
    new DataView(withPad.buffer).setUint32(withPad.length - 8, Math.floor(bits / 0x100000000));

    const w = new Uint32Array(64);
    const view = new DataView(withPad.buffer);

    for (let off = 0; off < withPad.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }

      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }

    const out = new Uint8Array(32);
    const ov = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) ov.setUint32(i * 4, H[i]);
    return out;
  }

  // ---------- base58check ----------

  function base58Decode(s) {
    // Big-endian base conversion over byte digits, so no BigInt is needed and
    // the leading-zero case (a '1' prefix) stays explicit.
    const bytes = [0];
    for (const ch of s) {
      const v = B58.indexOf(ch);
      if (v < 0) return null;
      let carry = v;
      for (let i = 0; i < bytes.length; i++) {
        carry += bytes[i] * 58;
        bytes[i] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    for (let i = 0; i < s.length && s[i] === '1'; i++) bytes.push(0);
    return new Uint8Array(bytes.reverse());
  }

  /// The payload of a base58check string, or null if the checksum fails.
  function base58checkDecode(s) {
    const raw = base58Decode(s);
    if (!raw || raw.length < 5) return null;

    const payload = raw.slice(0, raw.length - 4);
    const given = raw.slice(raw.length - 4);
    const want = sha256(sha256(payload)).slice(0, 4);
    for (let i = 0; i < 4; i++) if (given[i] !== want[i]) return null;
    return payload;
  }

  // ---------- bech32m ----------

  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= GEN[i];
    }
    return chk >>> 0;
  }

  function hrpExpand(hrp) {
    const out = [];
    for (const c of hrp) out.push(c.charCodeAt(0) >> 5);
    out.push(0);
    for (const c of hrp) out.push(c.charCodeAt(0) & 31);
    return out;
  }

  /// Whether a string is well-formed bech32m under the given HRP.
  function bech32mValid(s, hrp) {
    // Mixed case is invalid per BIP 173, and the checksum is defined over one
    // case, so this is a real rule rather than tidiness.
    if (s !== s.toLowerCase() && s !== s.toUpperCase()) return false;
    s = s.toLowerCase();

    const sep = s.lastIndexOf('1');
    if (sep < 1 || sep + 7 > s.length) return false;
    if (s.slice(0, sep) !== hrp) return false;

    const data = [];
    for (const c of s.slice(sep + 1)) {
      const v = CHARSET.indexOf(c);
      if (v < 0) return false;
      data.push(v);
    }
    // 0x2bc830a3 is the bech32m constant; bech32's is 1.
    return polymod(hrpExpand(hrp).concat(data)) === 0x2bc830a3;
  }

  // ---------- the check the pages call ----------

  // Zcash mainnet base58 version bytes.
  const P2PKH = [0x1c, 0xb8]; // t1
  const P2SH = [0x1c, 0xbd];  // t3

  /// null when the address is usable, otherwise a sentence to show.
  function validateZcashAddress(a) {
    a = (a || '').trim();
    if (!a) return 'Enter a Zcash address.';

    if (/^u1/i.test(a)) {
      if (!bech32mValid(a, 'u')) {
        return 'That unified address is not valid. Check it was copied whole.';
      }
      return null;
    }

    if (/^t[13]/.test(a)) {
      const payload = base58checkDecode(a);
      if (!payload || payload.length !== 22) {
        return 'That t-address is not valid. Check it was copied whole.';
      }
      const v = [payload[0], payload[1]];
      const isP2pkh = v[0] === P2PKH[0] && v[1] === P2PKH[1];
      const isP2sh = v[0] === P2SH[0] && v[1] === P2SH[1];
      if (!isP2pkh && !isP2sh) {
        return 'That is not a Zcash mainnet address.';
      }
      return null;
    }

    if (/^(zs|zc)/i.test(a)) {
      return 'Use a unified address (u1…) or a transparent one (t1… / t3…).';
    }

    return 'Use a Zcash address: u1… (shielded) or t1… / t3….';
  }

  /// The form of `a` the coordinator accepts, or the input unchanged.
  ///
  /// U2-6. BIP 173 lets a bech32m string be all upper case, `bech32mValid`
  /// allows it, and a QR scanner hands back exactly that, because upper case
  /// packs into fewer QR modules. The server matched `starts_with("u1")` case
  /// sensitively and refused the same address as "not a Zcash address", so a
  /// pasted `U1…` passed this page and failed on submit. Lower-casing here is
  /// the whole fix on the sender's side: the two encodings are the same
  /// address, and the lower-case one is what both decoders take.
  ///
  /// Transparent addresses are base58, which is case-significant, so they are
  /// returned untouched. Only bech32m is normalised, and only when the whole
  /// string is one case, which is the only form the spec allows.
  function normalizeZcashAddress(a) {
    const t = (a || '').trim();
    if (/^U1[0-9A-Z]*$/.test(t)) return t.toLowerCase();
    return t;
  }

  global.ZAddr = {
    validateZcashAddress,
    normalizeZcashAddress,
    base58checkDecode,
    bech32mValid,
    sha256,
  };
})(typeof window !== 'undefined' ? window : globalThis);

if (typeof module !== 'undefined' && module.exports) {
  module.exports = (typeof window !== 'undefined' ? window : globalThis).ZAddr;
}
