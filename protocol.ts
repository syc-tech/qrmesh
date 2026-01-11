/**
 * QR-TCP Protocol - Packet encoding, decoding, and CRC
 *
 * This module defines the packet structure and provides utilities
 * for creating, encoding, and decoding protocol packets.
 */

export const PROTOCOL_VERSION = 1;
export const BROADCAST_ADDR = '*';

// Packet flags
export const FLAGS = {
  SYN: 'SYN',
  ACK: 'ACK',
  FIN: 'FIN',
  DATA: 'DATA',
  SYNACK: 'SYN|ACK',
} as const;

// Message types for DATA packets
export const MESSAGE_TYPES = {
  ANNOUNCE: 'ANNOUNCE',
  DISCOVER: 'DISCOVER',
  OFFER: 'OFFER',
  ROUTE: 'ROUTE',
  CHAT: 'CHAT',
} as const;

export type Flag = (typeof FLAGS)[keyof typeof FLAGS];
export type MessageType = (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

/**
 * Core packet structure
 */
export interface QRPacket {
  v: number; // Protocol version
  src: string; // Source device ID (8 chars)
  dst: string; // Destination ID or '*' for broadcast
  seq: number; // Sequence number
  ack: number; // Acknowledgment number
  flags: string; // SYN|ACK|FIN|DATA
  type?: MessageType; // Message type for DATA packets
  payload?: unknown; // Message payload
  crc: string; // CRC16 checksum
}

/**
 * Payload for ANNOUNCE messages
 */
export interface AnnouncePayload {
  publicKey: string; // Base64 encoded public key
  name?: string; // Optional device name
}

/**
 * Payload for OFFER messages (connection upgrade)
 */
export interface OfferPayload {
  wsUrl?: string; // WebSocket URL
  webrtcSdp?: string; // WebRTC SDP offer
  ipPort?: string; // IP:port for direct connection
}

/**
 * Payload for ROUTE messages (mesh routing)
 */
export interface RoutePayload {
  reachable: string[]; // List of device IDs this node can reach
  hops: Record<string, number>; // Device ID -> hop count
}

/**
 * Payload for CHAT messages
 */
export interface ChatPayload {
  encrypted?: boolean;
  ciphertext?: string;
  iv?: string;
  plaintext?: string; // Only for unencrypted messages
}

/**
 * Calculate CRC16 (CCITT) for packet integrity
 */
function crc16(str: string): string {
  let crc = 0xffff;
  for (let i = 0; i < str.length; i++) {
    crc ^= str.charCodeAt(i) << 8;
    for (let j = 0; j < 8; j++) {
      if (crc & 0x8000) {
        crc = (crc << 1) ^ 0x1021;
      } else {
        crc <<= 1;
      }
    }
    crc &= 0xffff;
  }
  return crc.toString(16).padStart(4, '0');
}

/**
 * Create a packet with CRC
 */
export function createPacket(params: Omit<QRPacket, 'v' | 'crc'>): QRPacket {
  const packet: QRPacket = {
    v: PROTOCOL_VERSION,
    src: params.src,
    dst: params.dst,
    seq: params.seq,
    ack: params.ack,
    flags: params.flags,
    crc: '',
  };

  if (params.type) packet.type = params.type;
  if (params.payload !== undefined) packet.payload = params.payload;

  // Calculate CRC over all fields except crc itself
  const crcData = JSON.stringify({ ...packet, crc: undefined });
  packet.crc = crc16(crcData);

  return packet;
}

/**
 * Encode packet to JSON string for QR code
 */
export function encodePacket(packet: QRPacket): string {
  return JSON.stringify(packet);
}

/**
 * Decode packet from JSON string, verify CRC
 */
export function decodePacket(data: string): QRPacket | null {
  try {
    const packet = JSON.parse(data) as QRPacket;

    // Version check
    if (packet.v !== PROTOCOL_VERSION) {
      console.warn('Protocol version mismatch:', packet.v, 'expected:', PROTOCOL_VERSION);
      return null;
    }

    // Verify CRC
    const receivedCrc = packet.crc;
    const crcData = JSON.stringify({ ...packet, crc: undefined });
    const expectedCrc = crc16(crcData);

    if (receivedCrc !== expectedCrc) {
      console.warn('CRC mismatch:', receivedCrc, 'expected:', expectedCrc);
      return null;
    }

    return packet;
  } catch (e) {
    console.warn('Failed to decode packet:', e);
    return null;
  }
}

/**
 * Check if packet has specific flag
 */
export function hasFlag(packet: QRPacket, flag: string): boolean {
  return packet.flags.includes(flag);
}

/**
 * Check if packet is for us (or broadcast)
 */
export function isForUs(packet: QRPacket, ourId: string): boolean {
  return packet.dst === ourId || packet.dst === BROADCAST_ADDR;
}

// Packet factory functions

export function createSynPacket(
  src: string,
  dst: string,
  seq: number,
  payload?: AnnouncePayload
): QRPacket {
  return createPacket({
    src,
    dst,
    seq,
    ack: 0,
    flags: FLAGS.SYN,
    type: MESSAGE_TYPES.ANNOUNCE,
    payload,
  });
}

export function createSynAckPacket(
  src: string,
  dst: string,
  seq: number,
  ack: number,
  payload?: AnnouncePayload
): QRPacket {
  return createPacket({
    src,
    dst,
    seq,
    ack,
    flags: FLAGS.SYNACK,
    type: MESSAGE_TYPES.ANNOUNCE,
    payload,
  });
}

export function createAckPacket(
  src: string,
  dst: string,
  seq: number,
  ack: number
): QRPacket {
  return createPacket({
    src,
    dst,
    seq,
    ack,
    flags: FLAGS.ACK,
  });
}

export function createDataPacket(
  src: string,
  dst: string,
  seq: number,
  ack: number,
  type: MessageType,
  payload: unknown
): QRPacket {
  return createPacket({
    src,
    dst,
    seq,
    ack,
    flags: FLAGS.DATA,
    type,
    payload,
  });
}

export function createAnnouncePacket(
  src: string,
  seq: number,
  publicKey: string,
  name?: string
): QRPacket {
  return createPacket({
    src,
    dst: BROADCAST_ADDR,
    seq,
    ack: 0,
    flags: FLAGS.DATA,
    type: MESSAGE_TYPES.ANNOUNCE,
    payload: { publicKey, name } as AnnouncePayload,
  });
}

export function createFinPacket(
  src: string,
  dst: string,
  seq: number,
  ack: number
): QRPacket {
  return createPacket({
    src,
    dst,
    seq,
    ack,
    flags: FLAGS.FIN,
  });
}
