/**
 * QR-QUIC Protocol - QUIC-inspired packet format for QR transmission
 *
 * Key differences from TCP-style:
 * - No connection handshake (0-RTT with cached keys)
 * - Packet numbers instead of sequence numbers (monotonic, never reused)
 * - SACK-style ACK ranges for efficient acknowledgment
 * - Connectionless feel - each packet is self-contained
 */

export const PROTOCOL_VERSION = 2;
export const BROADCAST_ADDR = '*';

// Packet types (replacing TCP-style flags)
export const PACKET_TYPES = {
  INITIAL: 'I',   // First contact - includes public key
  DATA: 'D',      // Regular data packet
  ACK: 'A',       // Pure acknowledgment
} as const;

// Message types for DATA packets
export const MESSAGE_TYPES = {
  ANNOUNCE: 'ANN',
  CHAT: 'CHT',
  OFFER: 'OFR',
  ROUTE: 'RTE',
} as const;

export type PacketType = (typeof PACKET_TYPES)[keyof typeof PACKET_TYPES];
export type MessageType = (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

// ACK range: [start, end] inclusive
// e.g., [[1,5], [7,9]] means "received packets 1-5 and 7-9, missing 6"
export type AckRange = [number, number];

/**
 * Core packet structure (QUIC-style)
 */
export interface QRPacket {
  v: number;          // Protocol version
  src: string;        // Source device ID (8 chars)
  dst: string;        // Destination ID or '*' for broadcast
  pn: number;         // Packet number (monotonic, never reused)
  t: PacketType;      // Packet type
  acks?: AckRange[];  // SACK ranges of received packet numbers
  mt?: MessageType;   // Message type (for DATA packets)
  p?: unknown;        // Payload
  crc: string;        // CRC16 checksum
}

/**
 * Payload for INITIAL packets (key exchange)
 */
export interface InitialPayload {
  key: string;        // Base64 encoded public key
  name?: string;      // Optional device name
}

/**
 * Payload for ANNOUNCE messages
 */
export interface AnnouncePayload {
  key: string;        // Base64 encoded public key
  name?: string;      // Optional device name
}

/**
 * Payload for OFFER messages (connection upgrade)
 */
export interface OfferPayload {
  wsUrl?: string;     // WebSocket URL
  webrtcSdp?: string; // WebRTC SDP offer
  ipPort?: string;    // IP:port for direct connection
}

/**
 * Payload for ROUTE messages (mesh routing)
 */
export interface RoutePayload {
  reachable: string[];              // List of device IDs this node can reach
  hops: Record<string, number>;     // Device ID -> hop count
}

/**
 * Payload for CHAT messages
 */
export interface ChatPayload {
  enc?: boolean;      // Encrypted?
  ct?: string;        // Ciphertext
  iv?: string;        // IV
  pt?: string;        // Plaintext (only for unencrypted)
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
    pn: params.pn,
    t: params.t,
    crc: '',
  };

  if (params.acks && params.acks.length > 0) packet.acks = params.acks;
  if (params.mt) packet.mt = params.mt;
  if (params.p !== undefined) packet.p = params.p;

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
 * Check if packet is for us (or broadcast)
 */
export function isForUs(packet: QRPacket, ourId: string): boolean {
  return packet.dst === ourId || packet.dst === BROADCAST_ADDR;
}

// SACK utilities

/**
 * Add a packet number to ACK ranges, merging adjacent ranges
 */
export function addToAckRanges(ranges: AckRange[], pn: number): AckRange[] {
  if (ranges.length === 0) {
    return [[pn, pn]];
  }

  const newRanges: AckRange[] = [];
  let inserted = false;

  for (const [start, end] of ranges) {
    if (inserted) {
      // Check if we can merge with previous
      const prev = newRanges[newRanges.length - 1];
      if (prev && start <= prev[1] + 1) {
        prev[1] = Math.max(prev[1], end);
      } else {
        newRanges.push([start, end]);
      }
    } else if (pn < start - 1) {
      // Insert before this range
      newRanges.push([pn, pn]);
      newRanges.push([start, end]);
      inserted = true;
    } else if (pn <= end + 1) {
      // Merge with this range
      newRanges.push([Math.min(start, pn), Math.max(end, pn)]);
      inserted = true;
    } else {
      newRanges.push([start, end]);
    }
  }

  if (!inserted) {
    newRanges.push([pn, pn]);
  }

  // Merge any adjacent ranges that resulted from insertion
  const merged: AckRange[] = [];
  for (const range of newRanges) {
    const prev = merged[merged.length - 1];
    if (prev && range[0] <= prev[1] + 1) {
      prev[1] = Math.max(prev[1], range[1]);
    } else {
      merged.push(range);
    }
  }

  return merged;
}

/**
 * Check if a packet number is acknowledged by the ranges
 */
export function isAcked(ranges: AckRange[], pn: number): boolean {
  for (const [start, end] of ranges) {
    if (pn >= start && pn <= end) return true;
    if (pn < start) return false; // Ranges are sorted
  }
  return false;
}

/**
 * Get missing packet numbers from ranges (up to highest received)
 */
export function getMissing(ranges: AckRange[], _maxPn?: number): number[] {
  if (ranges.length === 0) return [];

  const missing: number[] = [];

  let expected = ranges[0][0];
  for (const [start, end] of ranges) {
    for (let i = expected; i < start; i++) {
      missing.push(i);
    }
    expected = end + 1;
  }

  return missing;
}

/**
 * Get the highest acknowledged packet number
 */
export function getHighestAcked(ranges: AckRange[]): number {
  if (ranges.length === 0) return -1;
  return ranges[ranges.length - 1][1];
}

// Packet factory functions

export function createInitialPacket(
  src: string,
  dst: string,
  pn: number,
  publicKey: string,
  name?: string,
  acks?: AckRange[]
): QRPacket {
  return createPacket({
    src,
    dst,
    pn,
    t: PACKET_TYPES.INITIAL,
    acks,
    p: { key: publicKey, name } as InitialPayload,
  });
}

export function createDataPacket(
  src: string,
  dst: string,
  pn: number,
  messageType: MessageType,
  payload: unknown,
  acks?: AckRange[]
): QRPacket {
  return createPacket({
    src,
    dst,
    pn,
    t: PACKET_TYPES.DATA,
    mt: messageType,
    p: payload,
    acks,
  });
}

export function createAckPacket(
  src: string,
  dst: string,
  pn: number,
  acks: AckRange[]
): QRPacket {
  return createPacket({
    src,
    dst,
    pn,
    t: PACKET_TYPES.ACK,
    acks,
  });
}

export function createAnnouncePacket(
  src: string,
  pn: number,
  publicKey: string,
  name?: string
): QRPacket {
  return createPacket({
    src,
    dst: BROADCAST_ADDR,
    pn,
    t: PACKET_TYPES.DATA,
    mt: MESSAGE_TYPES.ANNOUNCE,
    p: { key: publicKey, name } as AnnouncePayload,
  });
}

export function createChatPacket(
  src: string,
  dst: string,
  pn: number,
  payload: ChatPayload,
  acks?: AckRange[]
): QRPacket {
  return createPacket({
    src,
    dst,
    pn,
    t: PACKET_TYPES.DATA,
    mt: MESSAGE_TYPES.CHAT,
    p: payload,
    acks,
  });
}
