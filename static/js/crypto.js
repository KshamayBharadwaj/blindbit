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
    return await crypto.subtle.unwrapKey('raw', wrapped, wrappingKey, { name: 'AES-GCM', iv }, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
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
  deriveKeyFromPassphrase: async (passphrase, salt) => {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt || crypto.getRandomValues(new Uint8Array(32)), iterations: 600000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  },

  // Utility: generate random bytes as hex
  randomHex: (len) => {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  // Utility: buffer to base64
  bufferToBase64: (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer))),

  // Utility: base64 to Uint8Array
  base64ToBuffer: (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)),
};

// X25519 key exchange stub — real implementation requires @noble/curves or similar
// For Phase 1, we stub this out. The actual ECDH flow:
// 1. Generate ephemeral X25519 keypair
// 2. Compute sharedSecret = ecdh(ephemeralPriv, recipientPub)
// 3. Derive wrapping key via HKDF(sharedSecret)
// 4. Wrap File Key with wrapping key
// 5. Store ephemeralPub + wrapped key on server
const BlindBitX25519 = {
  generateKeypair: async () => {
    // Placeholder — returns random hex keys
    return {
      publicKey: BlindBitCrypto.randomHex(32),
      privateKey: BlindBitCrypto.randomHex(32),
    };
  },

  ecdh: async (privateKey, publicKey) => {
    // Placeholder — returns a derived shared secret
    return crypto.getRandomValues(new Uint8Array(32));
  },
};
