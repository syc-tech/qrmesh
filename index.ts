/**
 * QR-QUIC Library
 *
 * A QUIC-inspired protocol for peer-to-peer communication over QR codes.
 * Supports mesh discovery, encrypted messaging, and connection upgrades.
 *
 * Key features:
 * - 0-RTT: No handshake needed, send encrypted data immediately
 * - SACK: Selective acknowledgments for efficient delivery tracking
 * - Parallel transmission: Multiple packets in flight simultaneously
 *
 * @example
 * ```typescript
 * import { getOrCreateKeyPair, MeshState, QRScanner, encodePacket, decodePacket } from '@/lib/qrmesh';
 *
 * // Create identity
 * const keyPair = await getOrCreateKeyPair(localStorage);
 *
 * // Create mesh
 * const mesh = new MeshState(keyPair, { deviceName: 'My Device' });
 *
 * // Subscribe to events
 * mesh.subscribe((event) => {
 *   console.log(event.type, event);
 * });
 *
 * // Get packet to display as QR
 * const packet = mesh.getNextOutgoingPacket();
 * const qrData = encodePacket(packet);
 *
 * // Process received QR data
 * const received = decodePacket(scannedData);
 * if (received) {
 *   mesh.processPacket(received);
 * }
 * ```
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
  BROADCAST_ADDR,
  PACKET_TYPES,
  MESSAGE_TYPES,
  type PacketType,
  type MessageType,
  type AckRange,
  type QRPacket,
  type InitialPayload,
  type AnnouncePayload,
  type OfferPayload,
  type RoutePayload,
  type ChatPayload,
  createPacket,
  encodePacket,
  decodePacket,
  isForUs,
  addToAckRanges,
  isAcked,
  getMissing,
  getHighestAcked,
  createInitialPacket,
  createDataPacket,
  createAckPacket,
  createAnnouncePacket,
  createChatPacket,
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
 * Create an in-memory KeyStorage adapter (for testing or non-persistent use)
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
