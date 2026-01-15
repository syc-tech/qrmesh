/**
 * QR-QUIC Protocol v3 - Ultra-compact format for QR transmission
 *
 * Uses pipe-delimited format instead of JSON for minimal size:
 * - Beacon: Q3|B|{id}|{name}  (~20 bytes)
 * - Initial: Q3|I|{src}|{dst}|{pn}|{key}|{name}|{acks}
 * - Data: Q3|D|{src}|{dst}|{pn}|{mt}|{payload}|{acks}
 * - Ack: Q3|A|{src}|{dst}|{pn}|{acks}
 */

export const PROTOCOL_VERSION = 3;
export const PROTOCOL_PREFIX = 'Q3';
export const BROADCAST_ADDR = '*';

// Packet types (single char)
export const PACKET_TYPES = {
  BEACON: 'B',    // Minimal presence broadcast (no key)
  INITIAL: 'I',   // Key exchange
  DATA: 'D',      // Regular data
  ACK: 'A',       // Pure acknowledgment
} as const;

// Message types for DATA packets
export const MESSAGE_TYPES = {
  CHAT: 'C',
  OFFER: 'O',
} as const;

export type PacketType = (typeof PACKET_TYPES)[keyof typeof PACKET_TYPES];
export type MessageType = (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

// ACK range: [start, end] inclusive
export type AckRange = [number, number];

/**
 * Parsed packet structure
 */
export interface QRPacket {
  v: number;
  t: PacketType;
  src: string;
  dst: string;
  pn: number;
  mt?: MessageType;
  key?: string;       // Public key (INITIAL only)
  name?: string;      // Device name
  payload?: string;   // Message payload (already JSON for complex data)
  acks?: AckRange[];
}

/**
 * Chat payload (embedded as JSON in payload field)
 */
export interface ChatPayload {
  e?: boolean;   // encrypted?
  c?: string;    // ciphertext
  i?: string;    // iv
  p?: string;    // plaintext
}

/**
 * Offer payload
 */
export interface OfferPayload {
  ws?: string;   // WebSocket URL
  rtc?: string;  // WebRTC SDP
  ip?: string;   // IP:port
}

/**
 * Encode ACK ranges compactly: "1-5,7,9-12"
 */
function encodeAcks(acks: AckRange[]): string {
  if (!acks || acks.length === 0) return '';
  return acks.map(([start, end]) =>
    start === end ? String(start) : `${start}-${end}`
  ).join(',');
}

/**
 * Decode ACK ranges from compact format
 */
function decodeAcks(str: string): AckRange[] {
  if (!str) return [];
  return str.split(',').map(part => {
    if (part.includes('-')) {
      const [start, end] = part.split('-').map(Number);
      return [start, end] as AckRange;
    }
    const n = Number(part);
    return [n, n] as AckRange;
  });
}

/**
 * Encode packet to compact string
 */
export function encodePacket(packet: QRPacket): string {
  const parts: string[] = [PROTOCOL_PREFIX];

  switch (packet.t) {
    case PACKET_TYPES.BEACON:
      // Q3|B|{id}|{name}
      parts.push('B', packet.src, packet.name || '');
      break;

    case PACKET_TYPES.INITIAL:
      // Q3|I|{src}|{dst}|{pn}|{key}|{name}|{acks}
      parts.push('I', packet.src, packet.dst, String(packet.pn),
        packet.key || '', packet.name || '', encodeAcks(packet.acks || []));
      break;

    case PACKET_TYPES.DATA:
      // Q3|D|{src}|{dst}|{pn}|{mt}|{payload}|{acks}
      parts.push('D', packet.src, packet.dst, String(packet.pn),
        packet.mt || '', packet.payload || '', encodeAcks(packet.acks || []));
      break;

    case PACKET_TYPES.ACK:
      // Q3|A|{src}|{dst}|{pn}|{acks}
      parts.push('A', packet.src, packet.dst, String(packet.pn),
        encodeAcks(packet.acks || []));
      break;
  }

  return parts.join('|');
}

/**
 * Decode packet from compact string
 */
export function decodePacket(data: string): QRPacket | null {
  try {
    if (!data.startsWith(PROTOCOL_PREFIX + '|')) {
      return null;
    }

    const parts = data.split('|');
    const type = parts[1] as PacketType;

    switch (type) {
      case PACKET_TYPES.BEACON:
        // Q3|B|{id}|{name}
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.BEACON,
          src: parts[2],
          dst: BROADCAST_ADDR,
          pn: 0,
          name: parts[3] || undefined,
        };

      case PACKET_TYPES.INITIAL:
        // Q3|I|{src}|{dst}|{pn}|{key}|{name}|{acks}
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.INITIAL,
          src: parts[2],
          dst: parts[3],
          pn: Number(parts[4]),
          key: parts[5] || undefined,
          name: parts[6] || undefined,
          acks: decodeAcks(parts[7]),
        };

      case PACKET_TYPES.DATA:
        // Q3|D|{src}|{dst}|{pn}|{mt}|{payload}|{acks}
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.DATA,
          src: parts[2],
          dst: parts[3],
          pn: Number(parts[4]),
          mt: (parts[5] as MessageType) || undefined,
          payload: parts[6] || undefined,
          acks: decodeAcks(parts[7]),
        };

      case PACKET_TYPES.ACK:
        // Q3|A|{src}|{dst}|{pn}|{acks}
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.ACK,
          src: parts[2],
          dst: parts[3],
          pn: Number(parts[4]),
          acks: decodeAcks(parts[5]),
        };

      default:
        return null;
    }
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
      const prev = newRanges[newRanges.length - 1];
      if (prev && start <= prev[1] + 1) {
        prev[1] = Math.max(prev[1], end);
      } else {
        newRanges.push([start, end]);
      }
    } else if (pn < start - 1) {
      newRanges.push([pn, pn]);
      newRanges.push([start, end]);
      inserted = true;
    } else if (pn <= end + 1) {
      newRanges.push([Math.min(start, pn), Math.max(end, pn)]);
      inserted = true;
    } else {
      newRanges.push([start, end]);
    }
  }

  if (!inserted) {
    newRanges.push([pn, pn]);
  }

  // Merge adjacent
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
 * Check if a packet number is acknowledged
 */
export function isAcked(ranges: AckRange[], pn: number): boolean {
  for (const [start, end] of ranges) {
    if (pn >= start && pn <= end) return true;
    if (pn < start) return false;
  }
  return false;
}

/**
 * Get missing packet numbers from ranges
 */
export function getMissing(ranges: AckRange[]): number[] {
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
 * Get highest acknowledged packet number
 */
export function getHighestAcked(ranges: AckRange[]): number {
  if (ranges.length === 0) return -1;
  return ranges[ranges.length - 1][1];
}

// Packet factory functions

export function createBeaconPacket(src: string, name?: string): QRPacket {
  return {
    v: PROTOCOL_VERSION,
    t: PACKET_TYPES.BEACON,
    src,
    dst: BROADCAST_ADDR,
    pn: 0,
    name,
  };
}

export function createInitialPacket(
  src: string,
  dst: string,
  pn: number,
  publicKey: string,
  name?: string,
  acks?: AckRange[]
): QRPacket {
  return {
    v: PROTOCOL_VERSION,
    t: PACKET_TYPES.INITIAL,
    src,
    dst,
    pn,
    key: publicKey,
    name,
    acks,
  };
}

export function createDataPacket(
  src: string,
  dst: string,
  pn: number,
  messageType: MessageType,
  payload: string,
  acks?: AckRange[]
): QRPacket {
  return {
    v: PROTOCOL_VERSION,
    t: PACKET_TYPES.DATA,
    src,
    dst,
    pn,
    mt: messageType,
    payload,
    acks,
  };
}

export function createAckPacket(
  src: string,
  dst: string,
  pn: number,
  acks: AckRange[]
): QRPacket {
  return {
    v: PROTOCOL_VERSION,
    t: PACKET_TYPES.ACK,
    src,
    dst,
    pn,
    acks,
  };
}

export function createChatPacket(
  src: string,
  dst: string,
  pn: number,
  chatPayload: ChatPayload,
  acks?: AckRange[]
): QRPacket {
  return createDataPacket(src, dst, pn, MESSAGE_TYPES.CHAT, JSON.stringify(chatPayload), acks);
}

/**
 * Parse chat payload from packet
 */
export function parseChatPayload(packet: QRPacket): ChatPayload | null {
  if (!packet.payload) return null;
  try {
    return JSON.parse(packet.payload) as ChatPayload;
  } catch {
    return null;
  }
}
