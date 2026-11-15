
/**
 * NetCollab Artifact Cryptography
 *
 * RSA-OAEP with SHA-256 for AES key wrapping.
 * AES-256-GCM for artifact encryption/decryption.
 */

const encoder = new TextEncoder();

// ------------------------------------------
// BASE64 HELPERS
// ------------------------------------------

function base64ToBytes(value) {
  const binary = window.atob(value);

  return Uint8Array.from(
    binary,
    (char) => char.charCodeAt(0)
  );
}

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + 0x8000)
    );
  }

  return window.btoa(binary);
}

function arrayBufferToPem(buffer, label) {
  const base64 = bytesToBase64(buffer);
  const lines = base64.match(/.{1,64}/g).join("\n");

  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem, label) {
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;

  if (!pem.includes(begin) || !pem.includes(end)) {
    throw new Error(`Invalid ${label} PEM format.`);
  }

  const base64 = pem
    .replace(begin, "")
    .replace(end, "")
    .replace(/\s/g, "");

  const bytes = base64ToBytes(base64);

  return bytes.buffer;
}

// ------------------------------------------
// RSA KEY GENERATION
// ------------------------------------------

export async function generateRSAKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// ------------------------------------------
// RSA KEY EXPORT
// ------------------------------------------

export async function exportPublicKeyPem(publicKey) {
  const der = await window.crypto.subtle.exportKey(
    "spki",
    publicKey
  );

  return arrayBufferToPem(der, "PUBLIC KEY");
}

export async function exportPrivateKeyPem(privateKey) {
  const der = await window.crypto.subtle.exportKey(
    "pkcs8",
    privateKey
  );

  return arrayBufferToPem(der, "PRIVATE KEY");
}

// ------------------------------------------
// RSA KEY IMPORT
// ------------------------------------------

export async function importPrivateKeyPem(pem) {
  const der = pemToArrayBuffer(pem, "PRIVATE KEY");

  return window.crypto.subtle.importKey(
    "pkcs8",
    der,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    false,
    ["decrypt"]
  );
}

export async function importPublicKeyPem(pem) {
  const der = pemToArrayBuffer(pem, "PUBLIC KEY");

  return window.crypto.subtle.importKey(
    "spki",
    der,
    {
      name: "RSA-OAEP",
      hash: "SHA-256",
    },
    false,
    ["encrypt"]
  );
}

// ------------------------------------------
// AES KEY GENERATION
// ------------------------------------------

export async function generateAESKey() {
  return window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"]
  );
}

// ------------------------------------------
// AES KEY EXPORT
// ------------------------------------------

async function exportRawAESKey(aesKey) {
  return window.crypto.subtle.exportKey("raw", aesKey);
}

// ------------------------------------------
// RSA AES KEY WRAPPING
// ------------------------------------------

/**
 * Wrap an AES key for a recipient using their RSA public key.
 * Returns Base64-encoded RSA-OAEP ciphertext.
 */
export async function wrapAESKey(aesKey, recipientPublicKey) {
  const rawAESKey = await exportRawAESKey(aesKey);

  const wrapped = await window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
    },
    recipientPublicKey,
    rawAESKey
  );

  return bytesToBase64(wrapped);
}

/**
 * Unwrap an AES key using the recipient's RSA private key.
 */
export async function unwrapAESKey(
  wrappedKey,
  privateKey,
  extractable = false
) {
  const encryptedKey = base64ToBytes(wrappedKey);

  const rawAESKey = await window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
    },
    privateKey,
    encryptedKey
  );

  return window.crypto.subtle.importKey(
    "raw",
    rawAESKey,
    {
      name: "AES-GCM",
    },
    extractable,
    ["decrypt", "encrypt"]
  );
}

// ------------------------------------------
// AES-GCM ENCRYPTION
// ------------------------------------------

export async function encryptArtifact(fileData, aesKey) {
  const nonce = window.crypto.getRandomValues(
    new Uint8Array(12)
  );

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      tagLength: 128,
    },
    aesKey,
    fileData
  );

  return {
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext),
  };
}

// ------------------------------------------
// AES-GCM DECRYPTION
// ------------------------------------------

export async function decryptArtifact(
  ciphertextBase64,
  nonceBase64,
  aesKey
) {
  const ciphertext = base64ToBytes(ciphertextBase64);
  const nonce = base64ToBytes(nonceBase64);

  return window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      tagLength: 128,
    },
    aesKey,
    ciphertext
  );
}

// ------------------------------------------
// SHA-256 INTEGRITY VERIFICATION
// ------------------------------------------

export async function calculateSHA256(fileData) {
  const hash = await window.crypto.subtle.digest(
    "SHA-256",
    fileData
  );

  return Array.from(new Uint8Array(hash))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
