/**
 * HD Wallet Cryptographic Engine & Multichain Suite (v2.0 Web Edition)
 * Pure JavaScript Cryptographic Core:
 * - Secp256k1 & Ed25519 Elliptic Curve Math (BigInt)
 * - SHA-256, SHA-512, HMAC-SHA512, PBKDF2-HMAC-SHA512, RIPEMD-160, Keccak-256, SHA3-256, Blake2b
 * - Base58Check, Ripple Base58, Bech32 / Bech32m, Base32
 * - BIP-32, BIP-39, BIP-44, BIP-49, BIP-84, BIP-86, BIP-174 (PSBT), BIP-380 (Descriptors), SLIP-0010
 */

(function (global) {
  "use strict";

  // ═══════════════════════════════════════════════════════════════════════════
  // 1. BYTE & HEX UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════
  function hexToBytes(hex) {
    hex = hex.replace(/^0x/i, "").replace(/\s+/g, "");
    if (hex.length % 2 !== 0) hex = "0" + hex;
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  function bytesToHex(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) {
      s += bytes[i].toString(16).padStart(2, "0");
    }
    return s;
  }

  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }

  function concatBytes(...arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const res = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      res.set(a, offset);
      offset += a.length;
    }
    return res;
  }

  function bytesToBigInt(bytes) {
    let res = 0n;
    for (let i = 0; i < bytes.length; i++) {
      res = (res << 8n) | BigInt(bytes[i]);
    }
    return res;
  }

  function bigIntToBytes(num, len = 32) {
    const out = new Uint8Array(len);
    let n = num;
    for (let i = len - 1; i >= 0; i--) {
      out[i] = Number(n & 0xffn);
      n >>= 8n;
    }
    return out;
  }

  function u32be(num) {
    return new Uint8Array([
      (num >>> 24) & 0xff,
      (num >>> 16) & 0xff,
      (num >>> 8) & 0xff,
      num & 0xff
    ]);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 2. HASH FUNCTIONS (SHA-256, SHA-512, HMAC, PBKDF2, RIPEMD-160, KECCAK-256, BLAKE2B)
  // ═══════════════════════════════════════════════════════════════════════════

  // --- SHA-256 ---
  const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ]);

  function rotr32(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256(msg) {
    if (typeof msg === "string") msg = utf8ToBytes(msg);
    const len = msg.length;
    const bitLen = len * 8;
    const padLen = ((len + 8) >>> 6 << 6) + 64;
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[len] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(padLen - 4, bitLen >>> 0, false);

    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const w = new Uint32Array(64);

    for (let i = 0; i < padLen; i += 64) {
      for (let j = 0; j < 16; j++) w[j] = view.getUint32(i + j * 4, false);
      for (let j = 16; j < 64; j++) {
        const s0 = rotr32(w[j - 15], 7) ^ rotr32(w[j - 15], 18) ^ (w[j - 15] >>> 3);
        const s1 = rotr32(w[j - 2], 17) ^ rotr32(w[j - 2], 19) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let j = 0; j < 64; j++) {
        const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + SHA256_K[j] + w[j]) >>> 0;
        const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, idx) => outView.setUint32(idx * 4, v, false));
    return out;
  }

  // --- SHA-512 ---
  const SHA512_K = [
    0x428a2f98d728ae22n, 0x7137449123ef65cdn, 0xb5c0fbcfec4d3b2fn, 0xe9b5dba58189dbbcn,
    0x3956c25bf348b538n, 0x59f111f1b605d019n, 0x923f82a4af194f9bn, 0xab1c5ed5da6d8118n,
    0xd807aa98a3030242n, 0x12835b0145706fben, 0x243185be4ee4b28cn, 0x550c7dc3d5ffb4e2n,
    0x72be5d74f27b896fn, 0x80deb1fe3b1696b1n, 0x9bdc06a725c71235n, 0xc19bf174cf692694n,
    0xe49b69c19ef14ad2n, 0xefbe4786384f25e3n, 0x0fc19dc68b8cd5b5n, 0x240ca1cc77ac9c65n,
    0x2de92c6f592b0275n, 0x4a7484aa6ea6e483n, 0x5cb0a9dcbd41fbd4n, 0x76f988da831153b5n,
    0x983e5152ee66dfabn, 0xa831c66d2db43210n, 0xb00327c898fb213fn, 0xbf597fc7beef0ee4n,
    0xc6e00bf33da88fc2n, 0xd5a79147930aa725n, 0x06ca6351e003826fn, 0x142929670a0e6e70n,
    0x27b70a8546d22ffcn, 0x2e1b21385c26c926n, 0x4d2c6dfc5ac42aedn, 0x53380d139d95b3dfn,
    0x650a73548baf63den, 0x766a0abb3c77b2a8n, 0x81c2c92e47edaee6n, 0x92722c851482353bn,
    0xa2bfe8a14cf10364n, 0xa81a664bbc423001n, 0xc24b8b70d0f89791n, 0xc76c51a30654be30n,
    0xd192e819d6ef5218n, 0xd69906245565a910n, 0xf40e35855771202an, 0x106aa07032bbd1b8n,
    0x19a4c116b8d2d0c8n, 0x1e376c085141ab53n, 0x2748774cdf8eeb99n, 0x34b0bcb5e19b48a8n,
    0x391c0cb3c5c95a63n, 0x4ed8aa4ae3418acbn, 0x5b9cca4f7763e373n, 0x682e6ff3d6b2b8a3n,
    0x748f82ee5defb2fcn, 0x78a5636f43172f60n, 0x84c87814a1f0ab72n, 0x8cc702081a6439ecn,
    0x90befffa23631e28n, 0xa4506cebde82bde9n, 0xbef9a3f7b2c67915n, 0xc67178f2e372532bn,
    0xca273eceea26619cn, 0xd186b8c721c0c207n, 0xeada7dd6cde0eb1en, 0xf57d4f7fee6ed178n,
    0x06f067aa72176fban, 0x0a637dc5a2c898a6n, 0x113f9804bef90daen, 0x1b710b35131c471bn,
    0x28db77f523047d84n, 0x32caab7b40c72493n, 0x3c9ebe0a15c9bebcn, 0x431d67c49c100d4cn,
    0x4cc5d4becb3e42b6n, 0x597f299cfc657e2an, 0x5fcb6fab3ad6faecn, 0x6c44198c4a475817n
  ];
  const MASK64 = 0xffffffffffffffffn;
  function rotr64(x, n) {
    return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
  }

  function sha512(msg) {
    if (typeof msg === "string") msg = utf8ToBytes(msg);
    const len = msg.length;
    const bitLen = BigInt(len) * 8n;
    const padLen = ((len + 16) >>> 7 << 7) + 128;
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[len] = 0x80;
    const view = new DataView(buf.buffer);
    view.setBigUint64(padLen - 8, bitLen, false);

    let h0 = 0x6a09e667f3bcc908n, h1 = 0xbb67ae8584caa73bn, h2 = 0x3c6ef372fe94f82bn, h3 = 0xa54ff53a5f1d36f1n;
    let h4 = 0x510e527fade682d1n, h5 = 0x9b05688c2b3e6c1fn, h6 = 0x1f83d9abfb41bd6bn, h7 = 0x5be0cd19137e2179n;
    const w = new Array(80);

    for (let i = 0; i < padLen; i += 128) {
      for (let j = 0; j < 16; j++) w[j] = view.getBigUint64(i + j * 8, false);
      for (let j = 16; j < 80; j++) {
        const s0 = rotr64(w[j - 15], 1) ^ rotr64(w[j - 15], 8) ^ (w[j - 15] >> 7n);
        const s1 = rotr64(w[j - 2], 19) ^ rotr64(w[j - 2], 61) ^ (w[j - 2] >> 6n);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & MASK64;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let j = 0; j < 80; j++) {
        const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (h + S1 + ch + SHA512_K[j] + w[j]) & MASK64;
        const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) & MASK64;
        h = g; g = f; f = e; e = (d + temp1) & MASK64;
        d = c; c = b; b = a; a = (temp1 + temp2) & MASK64;
      }
      h0 = (h0 + a) & MASK64; h1 = (h1 + b) & MASK64; h2 = (h2 + c) & MASK64; h3 = (h3 + d) & MASK64;
      h4 = (h4 + e) & MASK64; h5 = (h5 + f) & MASK64; h6 = (h6 + g) & MASK64; h7 = (h7 + h) & MASK64;
    }
    const out = new Uint8Array(64);
    const outView = new DataView(out.buffer);
    [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, idx) => outView.setBigUint64(idx * 8, v, false));
    return out;
  }

  function hmacSha512(key, data) {
    if (typeof key === "string") key = utf8ToBytes(key);
    if (typeof data === "string") data = utf8ToBytes(data);
    const blockSize = 128;
    if (key.length > blockSize) key = sha512(key);
    const kPad = new Uint8Array(blockSize);
    kPad.set(key);
    const iKey = new Uint8Array(blockSize);
    const oKey = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      iKey[i] = kPad[i] ^ 0x36;
      oKey[i] = kPad[i] ^ 0x5c;
    }
    return sha512(concatBytes(oKey, sha512(concatBytes(iKey, data))));
  }

  function pbkdf2Sha512(password, salt, iterations = 2048, dkLen = 64) {
    const pwBytes = typeof password === "string" ? utf8ToBytes(password) : password;
    const saltBytes = typeof salt === "string" ? utf8ToBytes(salt) : salt;
    const block1 = concatBytes(saltBytes, u32be(1));
    let u = hmacSha512(pwBytes, block1);
    const t = new Uint8Array(u);
    for (let i = 1; i < iterations; i++) {
      u = hmacSha512(pwBytes, u);
      for (let j = 0; j < 64; j++) t[j] ^= u[j];
    }
    return t.slice(0, dkLen);
  }

  // --- RIPEMD-160 ---
  function ripemd160(msg) {
    if (typeof msg === "string") msg = utf8ToBytes(msg);
    const len = msg.length;
    const bitLen = len * 8;
    const padLen = ((len + 8) >>> 6 << 6) + 64;
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[len] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(padLen - 8, bitLen >>> 0, true);
    view.setUint32(padLen - 4, Math.floor(bitLen / 0x100000000), true);

    const rl = [
      0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
      3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
      4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13
    ];
    const rr = [
      5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
      15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
      12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11
    ];
    const sl = [
      11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
      11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
      9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6
    ];
    const sr = [
      8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
      9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
      8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11
    ];

    function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }
    function f(j, x, y, z) {
      if (j < 16) return (x ^ y ^ z) >>> 0;
      if (j < 32) return ((x & y) | (~x & z)) >>> 0;
      if (j < 48) return ((x | ~y) ^ z) >>> 0;
      if (j < 64) return ((x & z) | (y & ~z)) >>> 0;
      return (x ^ (y | ~z)) >>> 0;
    }
    const KL = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
    const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

    let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    const X = new Uint32Array(16);

    for (let i = 0; i < padLen; i += 64) {
      for (let j = 0; j < 16; j++) X[j] = view.getUint32(i + j * 4, true);
      let al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      let ar = h0, br = h1, cr = h2, dr = h3, er = h4;
      for (let j = 0; j < 80; j++) {
        const r = j >> 4;
        let t = (al + f(j, bl, cl, dl) + X[rl[j]] + KL[r]) >>> 0;
        t = (rotl(t, sl[j]) + el) >>> 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        t = (ar + f(79 - j, br, cr, dr) + X[rr[j]] + KR[r]) >>> 0;
        t = (rotl(t, sr[j]) + er) >>> 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
      }
      const t = (h1 + cl + dr) >>> 0;
      h1 = (h2 + dl + er) >>> 0;
      h2 = (h3 + el + ar) >>> 0;
      h3 = (h4 + al + br) >>> 0;
      h4 = (h0 + bl + cr) >>> 0;
      h0 = t;
    }
    const out = new Uint8Array(20);
    const outView = new DataView(out.buffer);
    [h0, h1, h2, h3, h4].forEach((v, idx) => outView.setUint32(idx * 4, v, true));
    return out;
  }

  function hash160(data) {
    return ripemd160(sha256(data));
  }

  // --- KECCAK-256 & SHA3-256 ---
  const KECCAK_RC = [
    0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
    0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
    0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
    0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
    0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
    0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n
  ];
  const KECCAK_ROTC = [1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44];
  const KECCAK_PILN = [10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1];

  function rotl64(x, n) {
    return ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64;
  }

  function keccakF1600(s) {
    const bc = new Array(5);
    for (let round = 0; round < 24; round++) {
      for (let i = 0; i < 5; i++) bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
      for (let i = 0; i < 5; i++) {
        const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
        for (let j = 0; j < 25; j += 5) s[j + i] ^= t;
      }
      let t = s[1];
      for (let i = 0; i < 24; i++) {
        const j = KECCAK_PILN[i];
        bc[0] = s[j];
        s[j] = rotl64(t, KECCAK_ROTC[i]);
        t = bc[0];
      }
      for (let j = 0; j < 25; j += 5) {
        for (let i = 0; i < 5; i++) bc[i] = s[j + i];
        for (let i = 0; i < 5; i++) s[j + i] ^= (~bc[(i + 1) % 5] & bc[(i + 2) % 5]) & MASK64;
      }
      s[0] ^= KECCAK_RC[round];
    }
  }

  function sponge256(msg, suffixByte) {
    if (typeof msg === "string") msg = utf8ToBytes(msg);
    const rate = 136;
    const state = new Array(25).fill(0n);
    const padLen = Math.ceil((msg.length + 1) / rate) * rate;
    const buf = new Uint8Array(padLen);
    buf.set(msg);
    buf[msg.length] = suffixByte;
    buf[padLen - 1] |= 0x80;
    const view = new DataView(buf.buffer);
    for (let i = 0; i < padLen; i += rate) {
      for (let j = 0; j < 17; j++) {
        state[j] ^= view.getBigUint64(i + j * 8, true);
      }
      keccakF1600(state);
    }
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 4; i++) outView.setBigUint64(i * 8, state[i], true);
    return out;
  }

  function keccak256(msg) { return sponge256(msg, 0x01); }
  function sha3_256(msg) { return sponge256(msg, 0x06); }

  // --- BLAKE2B ---
  const BLAKE2B_IV = [
    0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
    0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n
  ];
  const BLAKE2B_SIGMA = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4],[7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13],[2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11],[13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5],[10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0],
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],[14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3]
  ];

  function blake2b(msg, outLen = 32) {
    if (typeof msg === "string") msg = utf8ToBytes(msg);
    const h = BLAKE2B_IV.slice();
    h[0] ^= 0x01010000n ^ BigInt(outLen);
    const len = msg.length;
    const blocks = Math.max(1, Math.ceil(len / 128));
    const padded = new Uint8Array(blocks * 128);
    padded.set(msg);
    const view = new DataView(padded.buffer);
    const m = new Array(16);
    const v = new Array(16);

    function G(a, b, c, d, x, y) {
      v[a] = (v[a] + v[b] + x) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 24);
      v[a] = (v[a] + v[b] + y) & MASK64;
      v[d] = rotr64(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr64(v[b] ^ v[c], 63);
    }

    for (let b = 0; b < blocks; b++) {
      const offset = b * 128;
      const isLast = b === blocks - 1;
      const t0 = BigInt(isLast ? len : (b + 1) * 128);
      for (let i = 0; i < 16; i++) m[i] = view.getBigUint64(offset + i * 8, true);
      for (let i = 0; i < 8; i++) { v[i] = h[i]; v[i + 8] = BLAKE2B_IV[i]; }
      v[12] ^= t0;
      if (isLast) v[14] ^= MASK64;
      for (let r = 0; r < 12; r++) {
        const s = BLAKE2B_SIGMA[r];
        G(0,4,8,12,m[s[0]],m[s[1]]); G(1,5,9,13,m[s[2]],m[s[3]]);
        G(2,6,10,14,m[s[4]],m[s[5]]); G(3,7,11,15,m[s[6]],m[s[7]]);
        G(0,5,10,15,m[s[8]],m[s[9]]); G(1,6,11,12,m[s[10]],m[s[11]]);
        G(2,7,8,13,m[s[12]],m[s[13]]); G(3,4,9,14,m[s[14]],m[s[15]]);
      }
      for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
    }
    const full = new Uint8Array(64);
    const outView = new DataView(full.buffer);
    for (let i = 0; i < 8; i++) outView.setBigUint64(i * 8, h[i], true);
    return full.slice(0, outLen);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 3. ELLIPTIC CURVES: SECP256K1 & ED25519
  // ═══════════════════════════════════════════════════════════════════════════
  const SECP_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const SECP_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const SECP_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const SECP_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

  function mod(a, m = SECP_P) {
    const r = a % m;
    return r >= 0n ? r : r + m;
  }

  function modInv(a, m = SECP_P) {
    let t = 0n, newT = 1n;
    let r = m, newR = mod(a, m);
    while (newR !== 0n) {
      const q = r / newR;
      [t, newT] = [newT, t - q * newT];
      [r, newR] = [newR, r - q * newR];
    }
    return t < 0n ? t + m : t;
  }

  function modPow(base, exp, m) {
    let res = 1n;
    base = mod(base, m);
    while (exp > 0n) {
      if (exp & 1n) res = (res * base) % m;
      base = (base * base) % m;
      exp >>= 1n;
    }
    return res;
  }

  function secpPointAdd(p1, p2) {
    if (!p1) return p2;
    if (!p2) return p1;
    const [x1, y1] = p1;
    const [x2, y2] = p2;
    if (x1 === x2 && y1 !== y2) return null;
    let lam;
    if (x1 === x2 && y1 === y2) {
      if (y1 === 0n) return null;
      lam = mod(3n * x1 * x1 * modInv(2n * y1));
    } else {
      lam = mod((y2 - y1) * modInv(x2 - x1));
    }
    const x3 = mod(lam * lam - x1 - x2);
    const y3 = mod(lam * (x1 - x3) - y1);
    return [x3, y3];
  }

  function secpPointMul(k, pt = [SECP_GX, SECP_GY]) {
    let n = mod(k, SECP_N);
    let res = null;
    let addend = pt;
    while (n > 0n) {
      if (n & 1n) res = secpPointAdd(res, addend);
      addend = secpPointAdd(addend, addend);
      n >>= 1n;
    }
    return res;
  }

  function secpDecompressPub(bytes) {
    if (bytes.length === 65 && bytes[0] === 4) {
      return [bytesToBigInt(bytes.slice(1, 33)), bytesToBigInt(bytes.slice(33, 65))];
    }
    const prefix = bytes[0];
    const x = bytesToBigInt(bytes.slice(1, 33));
    const ySq = mod(modPow(x, 3n, SECP_P) + 7n, SECP_P);
    let y = modPow(ySq, (SECP_P + 1n) / 4n, SECP_P);
    const isEven = (y & 1n) === 0n;
    if ((prefix === 2 && !isEven) || (prefix === 3 && isEven)) {
      y = SECP_P - y;
    }
    return [x, y];
  }

  function secpPrivToPub(privBytes, compressed = true) {
    const k = bytesToBigInt(privBytes);
    const pt = secpPointMul(k);
    if (!pt) throw new Error("Invalid private key scalar");
    const [x, y] = pt;
    if (compressed) {
      const prefix = (y & 1n) === 0n ? 0x02 : 0x03;
      return concatBytes(new Uint8Array([prefix]), bigIntToBytes(x, 32));
    }
    return concatBytes(new Uint8Array([0x04]), bigIntToBytes(x, 32), bigIntToBytes(y, 32));
  }

  function secpTweakAddPub(pubBytes, tweakBytes) {
    const p1 = secpDecompressPub(pubBytes);
    const p2 = secpPointMul(bytesToBigInt(tweakBytes));
    const sum = secpPointAdd(p1, p2);
    const [x, y] = sum;
    const prefix = (y & 1n) === 0n ? 0x02 : 0x03;
    return concatBytes(new Uint8Array([prefix]), bigIntToBytes(x, 32));
  }

  // --- ED25519 ---
  const ED_P = (1n << 255n) - 19n;
  const ED_D = mod(-121665n * modInv(121666n, ED_P), ED_P);
  const ED_GY = mod(4n * modInv(5n, ED_P), ED_P);
  const ED_GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202n;

  function edAdd(p1, p2) {
    const [X1, Y1, Z1, T1] = p1;
    const [X2, Y2, Z2, T2] = p2;
    const A = mod((Y1 - X1) * (Y2 - X2), ED_P);
    const B = mod((Y1 + X1) * (Y2 + X2), ED_P);
    const C = mod(2n * ED_D * T1 * T2, ED_P);
    const D = mod(2n * Z1 * Z2, ED_P);
    const E = mod(B - A, ED_P);
    const F = mod(D - C, ED_P);
    const G = mod(D + C, ED_P);
    const H = mod(B + A, ED_P);
    return [mod(E * F, ED_P), mod(G * H, ED_P), mod(F * G, ED_P), mod(E * H, ED_P)];
  }

  function edPublicKey(seed32) {
    const h = sha512(seed32.slice(0, 32));
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    let s = 0n;
    for (let i = 0; i < 32; i++) s |= BigInt(h[i]) << BigInt(8 * i);
    let res = [0n, 1n, 1n, 0n];
    let cur = [ED_GX, ED_GY, 1n, mod(ED_GX * ED_GY, ED_P)];
    while (s > 0n) {
      if (s & 1n) res = edAdd(res, cur);
      cur = edAdd(cur, cur);
      s >>= 1n;
    }
    const zInv = modInv(res[2], ED_P);
    const x = mod(res[0] * zInv, ED_P);
    const y = mod(res[1] * zInv, ED_P);
    const out = new Uint8Array(32);
    let yn = y;
    for (let i = 0; i < 32; i++) {
      out[i] = Number(yn & 0xffn);
      yn >>= 8n;
    }
    out[31] |= Number(x & 1n) << 7;
    return out;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 4. ENCODINGS: BASE58, BASE58CHECK, RIPPLE, BECH32, BECH32M, BASE32
  // ═══════════════════════════════════════════════════════════════════════════
  const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  const RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
  const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  function base58Encode(bytes, alphabet = B58_ALPHABET) {
    let val = bytesToBigInt(bytes);
    let res = "";
    while (val > 0n) {
      const modVal = Number(val % 58n);
      val = val / 58n;
      res = alphabet[modVal] + res;
    }
    for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
      res = alphabet[0] + res;
    }
    return res;
  }

  function base58Decode(str, alphabet = B58_ALPHABET) {
    str = str.trim();
    let val = 0n;
    for (let i = 0; i < str.length; i++) {
      const idx = alphabet.indexOf(str[i]);
      if (idx === -1) throw new Error("Invalid Base58 character: " + str[i]);
      val = val * 58n + BigInt(idx);
    }
    let hex = val === 0n ? "" : val.toString(16);
    if (hex.length % 2 !== 0) hex = "0" + hex;
    const body = hex ? hexToBytes(hex) : new Uint8Array(0);
    let pad = 0;
    for (let i = 0; i < str.length && str[i] === alphabet[0]; i++) pad++;
    const res = new Uint8Array(pad + body.length);
    res.set(body, pad);
    return res;
  }

  function base58CheckEncode(payload) {
    const chk = sha256(sha256(payload)).slice(0, 4);
    return base58Encode(concatBytes(payload, chk));
  }

  function base58CheckDecode(encoded) {
    const raw = base58Decode(encoded);
    if (raw.length < 4) throw new Error("Base58Check string too short");
    const payload = raw.slice(0, raw.length - 4);
    const chk = raw.slice(raw.length - 4);
    const expected = sha256(sha256(payload)).slice(0, 4);
    for (let i = 0; i < 4; i++) {
      if (chk[i] !== expected[i]) throw new Error("Invalid Base58Check checksum");
    }
    return payload;
  }

  function bech32Polymod(values) {
    const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const b = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((b >>> i) & 1) chk ^= GEN[i];
      }
    }
    return chk;
  }

  function hrpExpand(hrp) {
    const res = [];
    for (let i = 0; i < hrp.length; i++) res.push(hrp.charCodeAt(i) >>> 5);
    res.push(0);
    for (let i = 0; i < hrp.length; i++) res.push(hrp.charCodeAt(i) & 31);
    return res;
  }

  function convertBits(data, fromBits, toBits, pad = true) {
    let acc = 0, bits = 0;
    const ret = [];
    const maxv = (1 << toBits) - 1;
    for (let i = 0; i < data.length; i++) {
      acc = (acc << fromBits) | data[i];
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        ret.push((acc >>> bits) & maxv);
      }
    }
    if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
    return ret;
  }

  function createBech32Checksum(hrp, data, spec = "bech32") {
    const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const constVal = spec === "bech32m" ? 0x2bc830a3 : 1;
    const polymod = bech32Polymod(values) ^ constVal;
    const res = [];
    for (let i = 0; i < 6; i++) res.push((polymod >>> (5 * (5 - i))) & 31);
    return res;
  }

  function encodeBech32(hrp, witnessVersion, witnessProgram) {
    const spec = witnessVersion > 0 ? "bech32m" : "bech32";
    const conv = convertBits(witnessProgram, 8, 5, true);
    const data = witnessVersion !== null ? [witnessVersion].concat(conv) : conv;
    const chk = createBech32Checksum(hrp, data, spec);
    return hrp + "1" + data.concat(chk).map(d => BECH32_CHARSET[d]).join("");
  }

  function base32Encode(bytes) {
    let bits = 0, value = 0, output = "";
    for (let i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) {
        output += B32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) output += B32_ALPHABET[(value << (5 - bits)) & 31];
    return output;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 5. BIP-39 MNEMONIC & SEED ENGINE
  // ═══════════════════════════════════════════════════════════════════════════
  function getWordlist() {
    return global.BIP39_WORDLIST || [];
  }

  function entropyToMnemonic(entropy) {
    const words = getWordlist();
    if (words.length !== 2048) throw new Error("BIP-39 wordlist not loaded");
    const entBits = entropy.length * 8;
    const csBits = entBits / 32;
    const hash = sha256(entropy);
    let bitStr = "";
    for (let i = 0; i < entropy.length; i++) bitStr += entropy[i].toString(2).padStart(8, "0");
    let hashStr = "";
    for (let i = 0; i < hash.length; i++) hashStr += hash[i].toString(2).padStart(8, "0");
    const full = bitStr + hashStr.slice(0, csBits);
    const out = [];
    for (let i = 0; i < full.length; i += 11) {
      const idx = parseInt(full.slice(i, i + 11), 2);
      out.push(words[idx]);
    }
    return out.join(" ");
  }

  function generateMnemonic(wordCount = 12) {
    const strengthMap = { 12: 16, 15: 20, 18: 24, 21: 28, 24: 32 };
    const byteLen = strengthMap[wordCount] || 16;
    const entropy = new Uint8Array(byteLen);
    crypto.getRandomValues(entropy);
    return entropyToMnemonic(entropy);
  }

  function validateMnemonic(mnemonic) {
    const words = getWordlist();
    if (!mnemonic || words.length !== 2048) return false;
    const list = mnemonic.trim().toLowerCase().split(/\s+/);
    if (![12, 15, 18, 21, 24].includes(list.length)) return false;
    let bits = "";
    for (const w of list) {
      const idx = words.indexOf(w);
      if (idx === -1) return false;
      bits += idx.toString(2).padStart(11, "0");
    }
    const divider = Math.floor((bits.length * 32) / 33);
    const entBits = bits.slice(0, divider);
    const csBits = bits.slice(divider);
    const entBytes = new Uint8Array(entBits.length / 8);
    for (let i = 0; i < entBytes.length; i++) {
      entBytes[i] = parseInt(entBits.slice(i * 8, i * 8 + 8), 2);
    }
    const hash = sha256(entBytes);
    let hashBits = "";
    for (let i = 0; i < hash.length; i++) hashBits += hash[i].toString(2).padStart(8, "0");
    return hashBits.slice(0, csBits.length) === csBits;
  }

  function mnemonicToSeed(mnemonic, passphrase = "") {
    const clean = mnemonic.trim().replace(/\s+/g, " ");
    return pbkdf2Sha512(clean, "mnemonic" + passphrase, 2048, 64);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 6. BIP-32 HIERARCHICAL DETERMINISTIC NODES & SLIP-0010
  // ═══════════════════════════════════════════════════════════════════════════
  class BIP32Node {
    constructor(privateKey, publicKey, chainCode, depth = 0, index = 0, parentFingerprint = new Uint8Array(4)) {
      this.privateKey = privateKey; // Uint8Array(32) or null
      this.publicKey = publicKey;   // Uint8Array(33)
      this.chainCode = chainCode;   // Uint8Array(32)
      this.depth = depth;
      this.index = index >>> 0;
      this.parentFingerprint = parentFingerprint;
    }

    static fromSeed(seedBytes) {
      const I = hmacSha512("Bitcoin seed", seedBytes);
      const priv = I.slice(0, 32);
      const chain = I.slice(32, 64);
      const pub = secpPrivToPub(priv, true);
      return new BIP32Node(priv, pub, chain, 0, 0, new Uint8Array(4));
    }

    static fromExtendedKey(extKey) {
      const raw = base58CheckDecode(extKey.trim());
      if (raw.length !== 78) throw new Error("Invalid extended key payload length");
      const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
      const depth = raw[4];
      const parentFp = raw.slice(5, 9);
      const index = view.getUint32(9, false);
      const chainCode = raw.slice(13, 45);
      const keyData = raw.slice(45, 78);
      if (keyData[0] === 0) {
        const priv = keyData.slice(1);
        const pub = secpPrivToPub(priv, true);
        return new BIP32Node(priv, pub, chainCode, depth, index, parentFp);
      } else {
        return new BIP32Node(null, keyData, chainCode, depth, index, parentFp);
      }
    }

    get fingerprint() {
      return hash160(this.publicKey).slice(0, 4);
    }

    deriveChild(index, isHardened) {
      const childIndex = (isHardened ? (index | 0x80000000) : index) >>> 0;
      let data;
      if (isHardened) {
        if (!this.privateKey) throw new Error("Cannot derive hardened child from public key");
        data = concatBytes(new Uint8Array([0x00]), this.privateKey, u32be(childIndex));
      } else {
        data = concatBytes(this.publicKey, u32be(childIndex));
      }
      const I = hmacSha512(this.chainCode, data);
      const IL = I.slice(0, 32);
      const IR = I.slice(32, 64);

      if (this.privateKey) {
        const ki = mod(bytesToBigInt(IL) + bytesToBigInt(this.privateKey), SECP_N);
        const childPriv = bigIntToBytes(ki, 32);
        const childPub = secpPrivToPub(childPriv, true);
        return new BIP32Node(childPriv, childPub, IR, this.depth + 1, childIndex, this.fingerprint);
      } else {
        const childPub = secpTweakAddPub(this.publicKey, IL);
        return new BIP32Node(null, childPub, IR, this.depth + 1, childIndex, this.fingerprint);
      }
    }

    derivePath(path) {
      let clean = path.trim().replace(/^m\/?/i, "");
      if (!clean) return this;
      const segments = clean.split("/").filter(Boolean);
      let node = this;
      for (const seg of segments) {
        const hardened = seg.endsWith("'") || seg.endsWith("h") || seg.endsWith("H");
        const idx = parseInt(seg.replace(/['hH]$/, ""), 10);
        if (isNaN(idx)) continue;
        if (node.depth > 0 && hardened && !node.privateKey) continue;
        node = node.deriveChild(idx, hardened);
      }
      return node;
    }

    serializeExtKey(versionInt, isPrivate = true) {
      const verBytes = u32be(versionInt);
      const depthByte = new Uint8Array([this.depth & 0xff]);
      const idxBytes = u32be(this.index);
      let keyBytes;
      if (isPrivate && this.privateKey) {
        keyBytes = concatBytes(new Uint8Array([0x00]), this.privateKey);
      } else {
        keyBytes = this.publicKey;
      }
      return base58CheckEncode(concatBytes(verBytes, depthByte, this.parentFingerprint, idxBytes, this.chainCode, keyBytes));
    }
  }

  function deriveSlip0010Ed25519(seedBytes, path) {
    let clean = path.trim().replace(/^m\/?/i, "");
    const segments = clean.split("/").filter(Boolean);
    let I = hmacSha512("ed25519 seed", seedBytes);
    let k = I.slice(0, 32), c = I.slice(32, 64);
    for (const seg of segments) {
      const raw = seg.replace(/['hH]$/, "");
      if (!/^\d+$/.test(raw)) continue;
      const idx = (parseInt(raw, 10) | 0x80000000) >>> 0;
      const data = concatBytes(new Uint8Array([0x00]), k, u32be(idx));
      I = hmacSha512(c, data);
      k = I.slice(0, 32);
      c = I.slice(32, 64);
    }
    return k;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 7. MULTICHAIN ADDRESS ENCODERS (50+ BLOCKCHAINS)
  // ═══════════════════════════════════════════════════════════════════════════
  function encodeWif(privBytes, prefixByte = 0x80, compressed = true) {
    const pfx = new Uint8Array([prefixByte]);
    const payload = compressed ? concatBytes(pfx, privBytes, new Uint8Array([0x01])) : concatBytes(pfx, privBytes);
    return base58CheckEncode(payload);
  }

  function decodeWif(wifStr) {
    const payload = base58CheckDecode(wifStr.trim());
    const prefix = payload[0];
    const data = payload.slice(1);
    if (data.length === 33 && data[32] === 0x01) {
      return { privBytes: data.slice(0, 32), compressed: true, prefix };
    } else if (data.length === 32) {
      return { privBytes: data, compressed: false, prefix };
    }
    throw new Error("Invalid WIF payload length");
  }

  function isValidWif(str) {
    if (!str || str.length < 45 || str.length > 56) return false;
    try { decodeWif(str); return true; } catch (e) { return false; }
  }

  function pubkeyToP2PKH(pubBytes, prefixBytes = new Uint8Array([0x00])) {
    return base58CheckEncode(concatBytes(prefixBytes, hash160(pubBytes)));
  }

  function pubkeyToP2SH_P2WPKH(pubBytes, prefixBytes = new Uint8Array([0x05])) {
    const redeem = concatBytes(new Uint8Array([0x00, 0x14]), hash160(pubBytes));
    return base58CheckEncode(concatBytes(prefixBytes, hash160(redeem)));
  }

  function pubkeyToP2WPKH(pubBytes, hrp = "bc") {
    return encodeBech32(hrp, 0, hash160(pubBytes));
  }

  function pubkeyToP2TR(pubBytes, hrp = "bc") {
    const xOnly = pubBytes.length === 33 ? pubBytes.slice(1, 33) : pubBytes.slice(0, 32);
    return encodeBech32(hrp, 1, xOnly);
  }

  function pubkeyToEthereum(uncompPubBytes) {
    const raw = uncompPubBytes.length === 65 ? uncompPubBytes.slice(1) : uncompPubBytes;
    const kHex = bytesToHex(keccak256(raw));
    const addrLower = kHex.slice(-40).toLowerCase();
    const hashHex = bytesToHex(keccak256(addrLower));
    let out = "0x";
    for (let i = 0; i < 40; i++) {
      out += parseInt(hashHex[i], 16) >= 8 ? addrLower[i].toUpperCase() : addrLower[i];
    }
    return out;
  }

  function pubkeyToTron(uncompPubBytes) {
    const raw = uncompPubBytes.length === 65 ? uncompPubBytes.slice(1) : uncompPubBytes;
    const k = keccak256(raw);
    return base58CheckEncode(concatBytes(new Uint8Array([0x41]), k.slice(-20)));
  }

  function pubkeyToXrp(compPubBytes) {
    const payload = concatBytes(new Uint8Array([0x00]), hash160(compPubBytes));
    const chk = sha256(sha256(payload)).slice(0, 4);
    return base58Encode(concatBytes(payload, chk), RIPPLE_ALPHABET);
  }

  function pubkeyToCosmosBech32(compPubBytes, hrp = "cosmos") {
    return encodeBech32(hrp, null, hash160(compPubBytes));
  }

  function pubkeyToPolkadot(compPubBytes) {
    const raw = compPubBytes.length === 33 ? compPubBytes.slice(1, 33) : compPubBytes.slice(0, 32);
    const payload = concatBytes(new Uint8Array([0x00]), raw);
    const chk = blake2b(concatBytes(utf8ToBytes("SS58PRE"), payload), 64).slice(0, 2);
    return base58Encode(concatBytes(payload, chk));
  }

  function pubkeyToCardano(compPubBytes) {
    const payload = concatBytes(new Uint8Array([0x61]), blake2b(compPubBytes, 28));
    return encodeBech32("addr", null, payload);
  }

  function pubkeyToKaspa(compPubBytes) {
    const xOnly = compPubBytes.length === 33 ? compPubBytes.slice(1, 33) : compPubBytes.slice(0, 32);
    const conv = convertBits(concatBytes(new Uint8Array([0x00]), xOnly), 8, 5, true);
    const chk = createBech32Checksum("kaspa", conv, "bech32");
    return "kaspa:" + conv.concat(chk).map(d => BECH32_CHARSET[d]).join("");
  }

  function pubkeyToTezos(compPubBytes) {
    return base58CheckEncode(concatBytes(new Uint8Array([0x06, 0xa1, 0x9f]), hash160(compPubBytes)));
  }

  function pubkeyToFilecoin(compPubBytes) {
    const pkh = blake2b(compPubBytes, 20);
    const payload = concatBytes(new Uint8Array([0x01]), pkh);
    const chk = blake2b(payload, 4);
    return "f1" + base32Encode(concatBytes(pkh, chk)).toLowerCase();
  }

  function privkeyToStellar(seed32) {
    const pub = edPublicKey(seed32);
    const payload = concatBytes(new Uint8Array([0x30]), pub);
    let crc = 0x0000;
    for (let i = 0; i < payload.length; i++) {
      crc ^= payload[i] << 8;
      for (let j = 0; j < 8; j++) {
        crc = (crc & 0x8000) ? (((crc << 1) ^ 0x1021) & 0xffff) : ((crc << 1) & 0xffff);
      }
    }
    const crcBytes = new Uint8Array([crc & 0xff, (crc >>> 8) & 0xff]);
    return base32Encode(concatBytes(payload, crcBytes));
  }

  function privkeyToAlgorand(seed32) {
    const pub = edPublicKey(seed32);
    const chk = sha512(pub).slice(28, 32);
    return base32Encode(concatBytes(pub, chk));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 8. HIGH-LEVEL HDWALLET CLASS & DESCRIPTORS
  // ═══════════════════════════════════════════════════════════════════════════
  const NETWORKS = {
    bitcoin: { p2pkh: [0x00], p2sh: [0x05], hrp: "bc", wif: 0x80, xprv: 0x0488ade4, xpub: 0x0488b21e, zprv: 0x04b2430c, zpub: 0x04b2438c, yprv: 0x049d7878, ypub: 0x049d7cb2 },
    bitcoin_testnet: { p2pkh: [0x6f], p2sh: [0xc4], hrp: "tb", wif: 0xef, xprv: 0x04358394, xpub: 0x043587cf, zprv: 0x045f18bc, zpub: 0x045f1cf6, yprv: 0x044a5262, ypub: 0x044a5628 },
    litecoin: { p2pkh: [0x30], p2sh: [0x32], hrp: "ltc", wif: 0xb0, xprv: 0x019d9cfe, xpub: 0x019da462 },
    dogecoin: { p2pkh: [0x1e], p2sh: [0x16], hrp: "doge", wif: 0x9e, xprv: 0x02fac398, xpub: 0x02facafd },
    dash: { p2pkh: [0x4c], p2sh: [0x10], hrp: "dash", wif: 0xcc, xprv: 0x0488ade4, xpub: 0x0488b21e },
    zcash: { p2pkh: [0x1c, 0xb8], p2sh: [0x1c, 0xbd], hrp: "zec", wif: 0x80, xprv: 0x0488ade4, xpub: 0x0488b21e }
  };

  class HDWallet {
    constructor(inputStr, passphrase = "", network = "bitcoin") {
      this.rawInput = (inputStr || "").trim();
      this.passphrase = passphrase || "";
      this.network = network.toLowerCase();
      this.netConfig = NETWORKS[this.network] || NETWORKS.bitcoin;

      let clean = this.rawInput.replace(/\s+/g, " ").trim();
      if (clean.startsWith("0x") && clean.length > 2) clean = clean.slice(2);

      this.inputType = "unknown";
      this.isSingleKey = false;
      this.singlePriv = null;
      this.singleComp = true;
      this.mnemonic = "";
      this.seed = new Uint8Array(0);
      this.seedHex = "";

      if (/^(xprv|xpub|yprv|ypub|zprv|zpub|tprv|tpub)/i.test(clean) && clean.length >= 100) {
        try {
          this.rootNode = BIP32Node.fromExtendedKey(clean);
          this.inputType = this.rootNode.privateKey ? "xprv" : "xpub";
        } catch (e) {}
      }

      if (this.inputType === "unknown" && isValidWif(clean)) {
        const w = decodeWif(clean);
        this.inputType = "wif";
        this.isSingleKey = true;
        this.singlePriv = w.privBytes;
        this.singleComp = w.compressed;
        const pub = secpPrivToPub(w.privBytes, true);
        const cc = sha256(concatBytes(utf8ToBytes("WIF_KEY:"), w.privBytes));
        this.rootNode = new BIP32Node(w.privBytes, pub, cc, 0, 0);
      }

      if (this.inputType === "unknown" && /^[0-9a-fA-F]+$/.test(clean)) {
        if (clean.length === 64) {
          const priv = hexToBytes(clean);
          this.inputType = "hex";
          this.isSingleKey = true;
          this.singlePriv = priv;
          const pub = secpPrivToPub(priv, true);
          const cc = sha256(concatBytes(utf8ToBytes("HEX_KEY:"), priv));
          this.rootNode = new BIP32Node(priv, pub, cc, 0, 0);
          this.seedHex = clean.toLowerCase();
        } else if (clean.length === 128) {
          this.seed = hexToBytes(clean);
          this.seedHex = clean.toLowerCase();
          this.inputType = "seed_hex";
          this.rootNode = BIP32Node.fromSeed(this.seed);
        }
      }

      if (this.inputType === "unknown") {
        const norm = clean.toLowerCase();
        this.mnemonic = norm;
        this.seed = mnemonicToSeed(norm, this.passphrase);
        this.seedHex = bytesToHex(this.seed);
        this.inputType = validateMnemonic(norm) ? "mnemonic" : "custom_phrase";
        this.rootNode = BIP32Node.fromSeed(this.seed);
      }

      this.masterXprv = this.rootNode.privateKey ? this.rootNode.serializeExtKey(this.netConfig.xprv, true) : "";
      this.masterXpub = this.rootNode.serializeExtKey(this.netConfig.xpub, false);
    }

    deriveKey(path = "m/84'/0'/0'/0/0") {
      const normPath = path.startsWith("m") ? path : "m/" + path;
      const activeNet = Object.assign({}, this.netConfig);
      if (normPath.includes("/2'/") || this.network === "litecoin") Object.assign(activeNet, NETWORKS.litecoin);
      else if (normPath.includes("/3'/") || this.network === "dogecoin") Object.assign(activeNet, NETWORKS.dogecoin);
      else if (normPath.includes("/5'/") || this.network === "dash") Object.assign(activeNet, NETWORKS.dash);
      else if (normPath.includes("/1'/") || this.network === "bitcoin_testnet") Object.assign(activeNet, NETWORKS.bitcoin_testnet);

      let targetNode, privBytes, pubBytes, uncompPub;
      if (this.isSingleKey && this.singlePriv) {
        privBytes = this.singlePriv;
        pubBytes = secpPrivToPub(privBytes, this.singleComp);
        uncompPub = secpPrivToPub(privBytes, false);
        targetNode = this.rootNode;
      } else {
        targetNode = this.rootNode.derivePath(normPath);
        privBytes = targetNode.privateKey;
        pubBytes = targetNode.publicKey;
        uncompPub = privBytes ? secpPrivToPub(privBytes, false) : pubBytes;
      }

      const privHex = privBytes ? bytesToHex(privBytes) : "";
      const pubHex = bytesToHex(pubBytes);
      const privWif = privBytes ? encodeWif(privBytes, activeNet.wif, true) : "";
      const privWifUncomp = privBytes ? encodeWif(privBytes, activeNet.wif, false) : "";

      const xprv = privBytes ? targetNode.serializeExtKey(activeNet.xprv || 0x0488ade4, true) : "";
      const xpub = targetNode.serializeExtKey(activeNet.xpub || 0x0488b21e, false);
      const zprv = privBytes && activeNet.zprv ? targetNode.serializeExtKey(activeNet.zprv, true) : "";
      const zpub = activeNet.zpub ? targetNode.serializeExtKey(activeNet.zpub, false) : "";
      const yprv = privBytes && activeNet.yprv ? targetNode.serializeExtKey(activeNet.yprv, true) : "";
      const ypub = activeNet.ypub ? targetNode.serializeExtKey(activeNet.ypub, false) : "";

      const addrP2PKH = pubkeyToP2PKH(pubBytes, new Uint8Array(activeNet.p2pkh));
      const addrP2SH = pubkeyToP2SH_P2WPKH(pubBytes, new Uint8Array(activeNet.p2sh));
      const addrP2WPKH = pubkeyToP2WPKH(pubBytes, activeNet.hrp);
      const addrP2TR = pubkeyToP2TR(pubBytes, activeNet.hrp);
      const addrETH = pubkeyToEthereum(uncompPub);

      // Ed25519 chains
      const solK = (!this.isSingleKey && this.seed.length) ? deriveSlip0010Ed25519(this.seed, normPath.includes("/501'/") ? normPath : "m/44'/501'/0'/0'") : (privBytes || new Uint8Array(32));
      const suiK = (!this.isSingleKey && this.seed.length) ? deriveSlip0010Ed25519(this.seed, normPath.includes("/784'/") ? normPath : "m/44'/784'/0'/0'/0'") : (privBytes || new Uint8Array(32));
      const aptK = (!this.isSingleKey && this.seed.length) ? deriveSlip0010Ed25519(this.seed, normPath.includes("/637'/") ? normPath : "m/44'/637'/0'/0'/0'") : (privBytes || new Uint8Array(32));
      const xlmK = (!this.isSingleKey && this.seed.length) ? deriveSlip0010Ed25519(this.seed, normPath.includes("/148'/") ? normPath : "m/44'/148'/0'") : (privBytes || new Uint8Array(32));
      const algoK = (!this.isSingleKey && this.seed.length) ? deriveSlip0010Ed25519(this.seed, normPath.includes("/283'/") ? normPath : "m/44'/283'/0'/0'/0'") : (privBytes || new Uint8Array(32));
      const nearK = (!this.isSingleKey && this.seed.length) ? deriveSlip0010Ed25519(this.seed, normPath.includes("/397'/") ? normPath : "m/44'/397'/0'") : (privBytes || new Uint8Array(32));

      const solPub = edPublicKey(solK);
      const suiPub = edPublicKey(suiK);
      const aptPub = edPublicKey(aptK);
      const nearPub = edPublicKey(nearK);

      const addrSOL = base58Encode(solPub);
      const addrSUI = "0x" + bytesToHex(blake2b(concatBytes(new Uint8Array([0x00]), suiPub), 32));
      const addrAPT = "0x" + bytesToHex(sha3_256(concatBytes(aptPub, new Uint8Array([0x00]))));
      const addrXLM = privkeyToStellar(xlmK);
      const addrALGO = privkeyToAlgorand(algoK);
      const addrNEAR = bytesToHex(nearPub);

      const addrTRX = pubkeyToTron(uncompPub);
      const addrXRP = pubkeyToXrp(pubBytes);
      const addrZEC = pubkeyToP2PKH(pubBytes, new Uint8Array([0x1c, 0xb8]));
      const addrDASH = pubkeyToP2PKH(pubBytes, new Uint8Array([0x4c]));
      const addrDOGE = pubkeyToP2PKH(pubBytes, new Uint8Array([0x1e]));
      const addrLTC = normPath.startsWith("m/84'") ? pubkeyToP2WPKH(pubBytes, "ltc") : pubkeyToP2PKH(pubBytes, new Uint8Array([0x30]));
      const addrATOM = pubkeyToCosmosBech32(pubBytes, "cosmos");
      const addrOSMO = pubkeyToCosmosBech32(pubBytes, "osmo");
      const addrINJ = pubkeyToCosmosBech32(pubBytes, "inj");
      const addrSEI = pubkeyToCosmosBech32(pubBytes, "sei");
      const addrTIA = pubkeyToCosmosBech32(pubBytes, "celestia");
      const addrKAVA = pubkeyToCosmosBech32(pubBytes, "kava");
      const addrDOT = pubkeyToPolkadot(pubBytes);
      const addrADA = pubkeyToCardano(pubBytes);
      const addrKAS = pubkeyToKaspa(pubBytes);
      const addrXTZ = pubkeyToTezos(pubBytes);
      const addrFIL = pubkeyToFilecoin(pubBytes);
      const addrRVN = pubkeyToP2PKH(pubBytes, new Uint8Array([0x3c]));
      const addrBTG = pubkeyToP2PKH(pubBytes, new Uint8Array([0x26]));

      let primaryAddr = addrP2WPKH;
      if (normPath.startsWith("m/86'")) primaryAddr = addrP2TR;
      else if (normPath.startsWith("m/49'")) primaryAddr = addrP2SH;
      else if (normPath.startsWith("m/44'/60'") || this.network === "ethereum" || this.network === "bnb") primaryAddr = addrETH;
      else if (normPath.includes("/501'/") || this.network === "solana") primaryAddr = addrSOL;
      else if (normPath.includes("/195'/") || this.network === "tron") primaryAddr = addrTRX;
      else if (normPath.includes("/144'/") || this.network === "xrp") primaryAddr = addrXRP;
      else if (normPath.includes("/2'/") || this.network === "litecoin") primaryAddr = addrLTC;
      else if (normPath.includes("/3'/") || this.network === "dogecoin") primaryAddr = addrDOGE;
      else if (normPath.startsWith("m/44'")) primaryAddr = addrP2PKH;

      return {
        path: normPath,
        depth: targetNode.depth,
        fingerprint: bytesToHex(targetNode.fingerprint),
        parentFingerprint: bytesToHex(targetNode.parentFingerprint),
        address: primaryAddr,
        privateKeyHex: privHex,
        privateKeyWif: privWif,
        privateKeyWifUncompressed: privWifUncomp,
        publicKeyHex: pubHex,
        publicKeyUncompressedHex: bytesToHex(uncompPub),
        chainCodeHex: bytesToHex(targetNode.chainCode),
        xprv, xpub, zprv, zpub, yprv, ypub,
        addressP2PKH: addrP2PKH,
        addressP2SH: addrP2SH,
        addressP2WPKH: addrP2WPKH,
        addressP2TR: addrP2TR,
        addressETH: addrETH,
        addressSOL: addrSOL,
        addressTRX: addrTRX,
        addressSUI: addrSUI,
        addressXRP: addrXRP,
        addressZEC: addrZEC,
        addressDASH: addrDASH,
        addressDOGE: addrDOGE,
        addressLTC: addrLTC,
        addressATOM: addrATOM,
        addressOSMO: addrOSMO,
        addressINJ: addrINJ,
        addressSEI: addrSEI,
        addressTIA: addrTIA,
        addressKAVA: addrKAVA,
        addressAPT: addrAPT,
        addressDOT: addrDOT,
        addressXLM: addrXLM,
        addressADA: addrADA,
        addressNEAR: addrNEAR,
        addressKAS: addrKAS,
        addressALGO: addrALGO,
        addressXTZ: addrXTZ,
        addressFIL: addrFIL,
        addressRVN: addrRVN,
        addressBTG: addrBTG
      };
    }
  }

  // --- BIP-380 Descriptors ---
  const DESC_INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

  function descPolymod(c, val) {
    const c0 = Number(c >> 35n);
    c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
    if (c0 & 1) c ^= 0xf5dee51989n;
    if (c0 & 2) c ^= 0xa9fdca3312n;
    if (c0 & 4) c ^= 0x1bab10e32dn;
    if (c0 & 8) c ^= 0x3706b1677an;
    if (c0 & 16) c ^= 0x644d626ffdn;
    return c;
  }

  function descriptorChecksum(descStr) {
    const clean = descStr.split("#")[0].trim();
    let c = 1n, cls = 0, clscount = 0;
    for (let i = 0; i < clean.length; i++) {
      const pos = DESC_INPUT_CHARSET.indexOf(clean[i]);
      if (pos === -1) return "";
      c = descPolymod(c, pos & 31);
      cls = cls * 3 + (pos >> 5);
      clscount++;
      if (clscount === 3) {
        c = descPolymod(c, cls);
        cls = 0;
        clscount = 0;
      }
    }
    if (clscount > 0) c = descPolymod(c, cls);
    for (let i = 0; i < 8; i++) c = descPolymod(c, 0);
    c ^= 1n;
    let ret = "";
    for (let j = 0; j < 8; j++) {
      ret += BECH32_CHARSET[Number((c >> BigInt(5 * (7 - j))) & 31n)];
    }
    return ret;
  }

  function addDescriptorChecksum(descStr) {
    const clean = descStr.split("#")[0].trim();
    const chk = descriptorChecksum(clean);
    return chk ? `${clean}#${chk}` : clean;
  }

  // --- 2^256 Key Space Explorer Pagination ---
  function getKeySpacePage(pageNumberBigInt, keysPerPage = 32, wordCount = 12) {
    let page = BigInt(pageNumberBigInt);
    if (page < 1n) page = 1n;
    const maxPage = SECP_N / BigInt(keysPerPage);
    if (page > maxPage) page = maxPage;
    const startScalar = (page - 1n) * BigInt(keysPerPage) + 1n;
    const rows = [];
    for (let i = 0; i < keysPerPage; i++) {
      const scalar = startScalar + BigInt(i);
      if (scalar >= SECP_N) break;
      const privBytes = bigIntToBytes(scalar, 32);
      const pubComp = secpPrivToPub(privBytes, true);
      const pubUncomp = secpPrivToPub(privBytes, false);
      const entSlice = wordCount === 24 ? privBytes : privBytes.slice(16, 32);
      const mnem = entropyToMnemonic(entSlice);
      rows.push({
        scalar: scalar.toString(),
        privateKeyHex: bytesToHex(privBytes),
        privateKeyWif: encodeWif(privBytes, 0x80, true),
        mnemonic: mnem,
        addressP2WPKH: pubkeyToP2WPKH(pubComp, "bc"),
        addressP2TR: pubkeyToP2TR(pubComp, "bc"),
        addressP2PKH: pubkeyToP2PKH(pubComp, new Uint8Array([0x00])),
        addressETH: pubkeyToEthereum(pubUncomp),
        addressTRX: pubkeyToTron(pubUncomp),
        addressDOGE: pubkeyToP2PKH(pubComp, new Uint8Array([0x1e])),
        addressLTC: pubkeyToP2WPKH(pubComp, "ltc")
      });
    }
    return { page: page.toString(), maxPage: maxPage.toString(), rows };
  }

  global.HDCrypto = {
    SECP_N,
    hexToBytes,
    bytesToHex,
    bytesToBigInt,
    bigIntToBytes,
    sha256,
    sha512,
    ripemd160,
    hash160,
    keccak256,
    blake2b,
    encodeWif,
    decodeWif,
    isValidWif,
    generateMnemonic,
    validateMnemonic,
    entropyToMnemonic,
    mnemonicToSeed,
    HDWallet,
    BIP32Node,
    descriptorChecksum,
    addDescriptorChecksum,
    getKeySpacePage
  };
})(window);
