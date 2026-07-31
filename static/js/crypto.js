// BlindBit — Client-Side Cryptography Module
// All encryption/decryption happens in the browser using Web Crypto API.

const BlindBitCrypto = {
  // Generate a random Master Key (32 bytes for AES-256)
  generateMasterKey: async () => {
    return await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  },

  // Generate a random File Key
  generateFileKey: async () => {
    return await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  },

  // Encrypt data with AES-256-GCM
  encrypt: async (key, plaintext) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    return { ciphertext: encrypted, iv };
  },

  // Decrypt data with AES-256-GCM
  decrypt: async (key, ciphertext, iv) => {
    try {
      return await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    } catch (e) {
      throw new Error('Decryption failed — data may be tampered with or key is wrong');
    }
  },

  // Wrap a key (for storing wrapped keys on server)
  wrapKey: async (wrappingKey, keyToWrap) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = await crypto.subtle.wrapKey('raw', keyToWrap, wrappingKey, { name: 'AES-GCM', iv });
    const rawWrapped = new Uint8Array(wrapped);
    const combined = new Uint8Array(iv.length + rawWrapped.length);
    combined.set(iv);
    combined.set(rawWrapped, iv.length);
    return btoa(String.fromCharCode(...combined));
  },

  // Unwrap a key
  unwrapKey: async (wrappingKey, wrappedBase64) => {
    const combined = Uint8Array.from(atob(wrappedBase64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const wrapped = combined.slice(12);
    return await crypto.subtle.unwrapKey('raw', wrapped, wrappingKey, { name: 'AES-GCM', iv }, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },

  // Encrypt a filename with a file key — returns base64(iv || ciphertext)
  encryptFilename: async (key, name) => {
    const enc = new TextEncoder();
    const { ciphertext, iv } = await BlindBitCrypto.encrypt(key, enc.encode(name));
    const ct = new Uint8Array(ciphertext);
    const combined = new Uint8Array(iv.length + ct.length);
    combined.set(iv);
    combined.set(ct, iv.length);
    return btoa(String.fromCharCode(...combined));
  },

  // Decrypt a filename (base64(iv || ciphertext)). Returns null when the
  // payload is not the current format (e.g. legacy plain-base64 names).
  decryptFilename: async (key, combinedB64) => {
    try {
      const combined = Uint8Array.from(atob(combinedB64), c => c.charCodeAt(0));
      const iv = combined.slice(0, 12);
      const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined.slice(12));
      return new TextDecoder().decode(decrypted);
    } catch (e) {
      return null;
    }
  },

  // Derive key from passphrase using PBKDF2 (Argonid not available in browser, PBKDF2 is fallback)
  // The derived master key must be extractable so it can be exported to sessionStorage.
  deriveKeyFromPassphrase: async (passphrase, salt) => {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt || crypto.getRandomValues(new Uint8Array(32)), iterations: 600000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  },

  // Utility: generate random bytes as hex
  randomHex: (len) => {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Generate a human-readable recovery code: 8 groups of 5 chars (A-Z, 2-9)
  generateRecoveryCode: () => {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789';
    const bytes = crypto.getRandomValues(new Uint8Array(40));
    const groups = [];
    for (let g = 0; g < 8; g++) {
      let s = '';
      for (let i = 0; i < 5; i++) s += alphabet[bytes[g * 5 + i] % alphabet.length];
      groups.push(s);
    }
    return groups.join('-');
  },

  // Utility: buffer to base64
  bufferToBase64: (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))),

  // Utility: base64 to Uint8Array
  base64ToBuffer: (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)),

  // Encrypt bytes with AES-256-GCM, returns base64(iv || ciphertext)
  encryptToB64: async (key, bytes) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes));
    const combined = new Uint8Array(iv.length + ct.length);
    combined.set(iv);
    combined.set(ct, iv.length);
    return btoa(String.fromCharCode(...combined));
  },

  // Decrypt base64(iv || ciphertext) to bytes
  decryptFromB64: async (key, combinedB64) => {
    const combined = Uint8Array.from(atob(combinedB64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, combined.slice(12)));
  },
};

// X25519 (RFC 7748) implemented in pure JS with BigInt — no dependencies.
// Shared secrets are derived with a fixed HKDF so both sides agree on the
// same AES-GCM wrapping key without any extra protocol state.
const BlindBitX25519 = {
  P: (1n << 255n) - 19n,
  A24: 121665n,

  decodeLittleEndian: (bytes) => {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
  },

  encodeLittleEndian: (n, len) => {
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
    return out;
  },

  modInverse: (a) => {
    const P = BlindBitX25519.P;
    let p = P, x = 0n, y = 1n;
    let b = ((a % P) + P) % P;
    while (b !== 1n) {
      const q = p / b;
      [p, b] = [b, p - q * b];
      [x, y] = [y, x - q * y];
    }
    return ((y % P) + P) % P;
  },

  // Montgomery ladder scalar multiplication (RFC 7748 §5)
  scalarmult: (scalarBytes, pointU) => {
    const P = BlindBitX25519.P;
    const k = scalarBytes.slice();
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    const x1 = BlindBitX25519.decodeLittleEndian(pointU) % P;
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n;
    let swap = 0n;

    for (let t = 254; t >= 0; t--) {
      const kt = BigInt((k[t >> 3] >> (t & 7)) & 1);
      swap ^= kt;
      if (swap === 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
      swap = kt;

      const A = (x2 + z2) % P;
      const AA = (A * A) % P;
      const B = (x2 - z2 + P) % P;
      const BB = (B * B) % P;
      const E = (AA - BB + P) % P;
      const C = (x3 + z3) % P;
      const D = (x3 - z3 + P) % P;
      const DA = (D * A) % P;
      const CB = (C * B) % P;
      x3 = ((DA + CB) * (DA + CB)) % P;
      z3 = (x1 * ((DA - CB + P) * (DA - CB + P) % P)) % P;
      x2 = (AA * BB) % P;
      z2 = (E * ((AA + BlindBitX25519.A24 * E) % P)) % P;
    }
    if (swap === 1n) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return BlindBitX25519.encodeLittleEndian((x2 * BlindBitX25519.modInverse(z2)) % P, 32);
  },

  hexToBytes: (hex) => {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  },

  bytesToHex: (bytes) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''),

  // Generate a random X25519 keypair. Keys are hex-encoded 32-byte strings.
  generateKeypair: async () => {
    const scalar = crypto.getRandomValues(new Uint8Array(32));
    const basepoint = new Uint8Array(32);
    basepoint[0] = 9;
    const publicKey = BlindBitX25519.scalarmult(scalar, basepoint);
    return {
      publicKey: BlindBitX25519.bytesToHex(publicKey),
      privateKey: BlindBitX25519.bytesToHex(scalar),
    };
  },

  // Compute the ECDH shared secret (32 raw bytes) from hex keys
  ecdh: async (privateKeyHex, publicKeyHex) => {
    const priv = BlindBitX25519.hexToBytes(privateKeyHex);
    const pub = BlindBitX25519.hexToBytes(publicKeyHex);
    return BlindBitX25519.scalarmult(priv, pub);
  },

  // Derive a per-share AES-GCM wrapping key from the ECDH shared secret via
  // HKDF-SHA256. The ephemeral public key is bound into the info so a secret
  // can never be reused across different exchange pairs.
  deriveWrappingKey: async (sharedSecret, ephemeralPublicKeyHex) => {
    const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const enc = new TextEncoder();
    return await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('BlindBit X25519 HKDF'), info: enc.encode('BlindBit share v1:' + ephemeralPublicKeyHex) },
      hkdfKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['wrapKey', 'unwrapKey']
    );
  },
};
