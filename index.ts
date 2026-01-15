/**
 * QR-QUIC Library v3
 *
 * Ultra-compact QUIC-inspired protocol for QR code communication.
 *
 * Key features:
 * - Minimal beacons (~15 bytes) for discovery
 * - 0-RTT messaging with cached keys
 * - SACK acknowledgments
 * - Pipe-delimited format instead of JSON
 */

// Crypto exports
export {
  type KeyPair,
  type SerializedKeyPair,
  type KeyStorage,
  generateKeyPair,
  serializeKeyPair,
  deserializeKeyPair,
  getOrCreateKeyPair,
  importPublicKey,
  deviceIdFromPublicKey,
  deriveSharedKey,
  encrypt,
  decrypt,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from './crypto';

// Protocol exports
export {
  PROTOCOL_VERSION,
  PROTOCOL_PREFIX,
  BROADCAST_ADDR,
  PACKET_TYPES,
  MESSAGE_TYPES,
  type PacketType,
  type MessageType,
  type AckRange,
  type QRPacket,
  type ChatPayload,
  type OfferPayload,
  encodePacket,
  decodePacket,
  isForUs,
  addToAckRanges,
  isAcked,
  getMissing,
  getHighestAcked,
  createBeaconPacket,
  createInitialPacket,
  createDataPacket,
  createAckPacket,
  createChatPacket,
  parseChatPayload,
} from './protocol';

// Scanner exports
export {
  type ScanResult,
  type QRScannerOptions,
  type VideoConstraints,
  QRScanner,
  estimateQRCapacity,
  fitsInQR,
} from './scanner';

// Mesh exports
export {
  type SentPacket,
  type Peer,
  type PacketLogEntry,
  type ChatMessage,
  type MeshEvent,
  type MeshEventHandler,
  type MeshConfig,
  MeshState,
} from './mesh';

/**
 * Create a localStorage-compatible KeyStorage adapter
 */
export function createLocalStorageAdapter(): import('./crypto').KeyStorage {
  return {
    get: (key: string) => localStorage.getItem(key),
    set: (key: string, value: string) => localStorage.setItem(key, value),
    remove: (key: string) => localStorage.removeItem(key),
  };
}

/**
 * Create an in-memory KeyStorage adapter
 */
export function createMemoryStorageAdapter(): import('./crypto').KeyStorage {
  const store = new Map<string, string>();
  return {
    get: (key: string) => store.get(key) ?? null,
    set: (key: string, value: string) => store.set(key, value),
    remove: (key: string) => store.delete(key),
  };
}

// Web Component export
export { QRTCPDemoElement, registerQRTCPElement } from './component';
