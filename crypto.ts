/**
 * Cryptographic utilities for QR-TCP mesh protocol
 * Uses Web Crypto API with ECDH (P-256) + AES-GCM
 *
 * This module is framework-agnostic and can be used in any environment
 * that supports the Web Crypto API.
 */

export interface KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyRaw: string; // Base64 encoded
  deviceId: string; // First 8 chars of public key hash
}

export interface SerializedKeyPair {
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: JsonWebKey;
}

export interface KeyStorage {
  get(key: string): string | null;
  set(key: string, value: string): void;
  remove(key: string): void;
}

// Default storage key
const DEFAULT_STORAGE_KEY = 'qrtcp-keypair';

/**
 * Generate a new ECDH keypair
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true, // extractable
    ['deriveKey', 'deriveBits']
  );

  const publicKeyRaw = await exportPublicKey(keyPair.publicKey);
  const deviceId = await deriveDeviceId(publicKeyRaw);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyRaw,
    deviceId,
  };
}

/**
 * Serialize a keypair for storage
 */
export async function serializeKeyPair(keyPair: KeyPair): Promise<SerializedKeyPair> {
  const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  return { privateKeyJwk, publicKeyJwk };
}

/**
 * Deserialize a keypair from storage
 */
export async function deserializeKeyPair(serialized: SerializedKeyPair): Promise<KeyPair> {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    serialized.privateKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );

  const publicKey = await crypto.subtle.importKey(
    'jwk',
    serialized.publicKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );

  const publicKeyRaw = await exportPublicKey(publicKey);
  const deviceId = await deriveDeviceId(publicKeyRaw);

  return { publicKey, privateKey, publicKeyRaw, deviceId };
}

/**
 * Get or create a keypair, optionally using storage for persistence
 */
export async function getOrCreateKeyPair(
  storage?: KeyStorage,
  storageKey: string = DEFAULT_STORAGE_KEY
): Promise<KeyPair> {
  // Try to load from storage if provided
  if (storage) {
    const stored = storage.get(storageKey);
    if (stored) {
      try {
        const serialized = JSON.parse(stored) as SerializedKeyPair;
        return await deserializeKeyPair(serialized);
      } catch (e) {
        console.warn('Failed to load stored keypair, generating new one:', e);
      }
    }
  }

  // Generate new keypair
  const keyPair = await generateKeyPair();

  // Store if storage provided
  if (storage) {
    const serialized = await serializeKeyPair(keyPair);
    storage.set(storageKey, JSON.stringify(serialized));
  }

  return keyPair;
}

/**
 * Export public key to base64 string
 */
async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(raw);
}

/**
 * Import public key from base64 string
 */
export async function importPublicKey(base64: string): Promise<CryptoKey> {
  const raw = base64ToArrayBuffer(base64);
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    []
  );
}

/**
 * Derive device ID from public key (first 8 hex chars of SHA-256 hash)
 */
async function deriveDeviceId(publicKeyRaw: string): Promise<string> {
  const data = new TextEncoder().encode(publicKeyRaw);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hashArray = new Uint8Array(hash);
  // Use UPPERCASE hex for QR alphanumeric mode efficiency
  return Array.from(hashArray.slice(0, 4))
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('');
}

/**
 * Get device ID from a public key string
 */
export async function deviceIdFromPublicKey(publicKeyRaw: string): Promise<string> {
  return deriveDeviceId(publicKeyRaw);
}

/**
 * Derive shared secret from our private key and peer's public key
 */
export async function deriveSharedKey(
  privateKey: CryptoKey,
  peerPublicKeyRaw: string
): Promise<CryptoKey> {
  const peerPublicKey = await importPublicKey(peerPublicKeyRaw);

  return crypto.subtle.deriveKey(
    {
      name: 'ECDH',
      public: peerPublicKey,
    },
    privateKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt plaintext with AES-GCM
 */
export async function encrypt(
  key: CryptoKey,
  plaintext: string
): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plaintext);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
  };
}

/**
 * Decrypt ciphertext with AES-GCM
 */
export async function decrypt(
  key: CryptoKey,
  ciphertext: string,
  iv: string
): Promise<string> {
  const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
  const ivBuffer = base64ToArrayBuffer(iv);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivBuffer },
    key,
    ciphertextBuffer
  );

  return new TextDecoder().decode(plaintext);
}

// Utility functions
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
