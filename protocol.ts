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
export const PROTOCOL_PREFIX = 'Q';
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
  switch (packet.t) {
    case PACKET_TYPES.BEACON:
      // Just the 8-char uppercase device ID - smallest possible!
      return packet.src;

    case PACKET_TYPES.INITIAL:
      // I{src}{dst}{pn}|{key}|{name}|{acks}
      return `I${packet.src}${packet.dst}${packet.pn}|${packet.key || ''}|${packet.name || ''}|${encodeAcks(packet.acks || [])}`;

    case PACKET_TYPES.DATA:
      // D{src}{dst}{pn}{mt}|{payload}|{acks}
      return `D${packet.src}${packet.dst}${packet.pn}${packet.mt || ''}|${packet.payload || ''}|${encodeAcks(packet.acks || [])}`;

    case PACKET_TYPES.ACK:
      // A{src}{dst}{pn}|{acks}
      return `A${packet.src}${packet.dst}${packet.pn}|${encodeAcks(packet.acks || [])}`;

    default:
      return '';
  }
}

/**
 * Decode packet from compact string
 */
export function decodePacket(data: string): QRPacket | null {
  try {
    // Beacon: just 8 uppercase hex chars (no prefix)
    if (/^[0-9A-F]{8}$/.test(data)) {
      return {
        v: PROTOCOL_VERSION,
        t: PACKET_TYPES.BEACON,
        src: data,
        dst: BROADCAST_ADDR,
        pn: 0,
      };
    }

    const type = data[0] as PacketType;

    switch (type) {
      case PACKET_TYPES.INITIAL: {
        // I{src:8}{dst:8}{pn}|{key}|{name}|{acks}
        const src = data.slice(1, 9);
        const dst = data.slice(9, 17);
        const rest = data.slice(17);
        const pnEnd = rest.indexOf('|');
        const pn = Number(rest.slice(0, pnEnd));
        const parts = rest.slice(pnEnd + 1).split('|');
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.INITIAL,
          src,
          dst,
          pn,
          key: parts[0] || undefined,
          name: parts[1] || undefined,
          acks: decodeAcks(parts[2]),
        };
      }

      case PACKET_TYPES.DATA: {
        // D{src:8}{dst:8}{pn}{mt:1}|{payload}|{acks}
        const src = data.slice(1, 9);
        const dst = data.slice(9, 17);
        const rest = data.slice(17);
        const pipeIdx = rest.indexOf('|');
        const pnAndMt = rest.slice(0, pipeIdx);
        // mt is single char at end if present
        const mt = pnAndMt.match(/[A-Z]$/) ? pnAndMt.slice(-1) as MessageType : undefined;
        const pn = Number(mt ? pnAndMt.slice(0, -1) : pnAndMt);
        const parts = rest.slice(pipeIdx + 1).split('|');
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.DATA,
          src,
          dst,
          pn,
          mt,
          payload: parts[0] || undefined,
          acks: decodeAcks(parts[1]),
        };
      }

      case PACKET_TYPES.ACK: {
        // A{src:8}{dst:8}{pn}|{acks}
        const src = data.slice(1, 9);
        const dst = data.slice(9, 17);
        const rest = data.slice(17);
        const pipeIdx = rest.indexOf('|');
        const pn = Number(rest.slice(0, pipeIdx));
        const acks = decodeAcks(rest.slice(pipeIdx + 1));
        return {
          v: PROTOCOL_VERSION,
          t: PACKET_TYPES.ACK,
          src,
          dst,
          pn,
          acks,
        };
      }

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

// ============================================================
// CHUNKING - Split large packets into 8-char chunks for reliable QR scanning
// ============================================================

const MAX_CHUNK_SIZE = 8;
const CHUNK_DATA_SIZE = 4; // F + stream + index + flags + 4 data chars = 8

/**
 * Encode a number to base36 char (0-9, A-Z)
 */
function toBase36(n: number): string {
  if (n < 10) return String(n);
  return String.fromCharCode(55 + n); // A=65, so 10 -> 'A'
}

/**
 * Decode base36 char to number
 */
function fromBase36(c: string): number {
  const code = c.charCodeAt(0);
  if (code >= 48 && code <= 57) return code - 48; // 0-9
  if (code >= 65 && code <= 90) return code - 55; // A-Z
  return 0;
}

/**
 * Split an encoded packet into 8-char chunks
 * Returns array of chunk strings, or just the original if <= 8 chars
 */
export function chunkPacket(encoded: string, streamId: number = 0): string[] {
  // If already 8 chars or less, return as-is (beacon format)
  if (encoded.length <= MAX_CHUNK_SIZE) {
    return [encoded];
  }

  const chunks: string[] = [];
  const totalChunks = Math.ceil(encoded.length / CHUNK_DATA_SIZE);
  const streamChar = toBase36(streamId % 36);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_DATA_SIZE;
    const data = encoded.slice(start, start + CHUNK_DATA_SIZE).padEnd(CHUNK_DATA_SIZE, ' ');
    const isLast = i === totalChunks - 1;
    const indexChar = toBase36(i);
    const flagChar = isLast ? 'L' : 'M'; // L=last, M=more

    chunks.push(`F${streamChar}${indexChar}${flagChar}${data}`);
  }

  return chunks;
}

/**
 * Check if a string is a chunk (starts with 'F')
 */
export function isChunk(data: string): boolean {
  return data.length === 8 && data[0] === 'F';
}

/**
 * Parse chunk metadata
 */
export function parseChunk(data: string): { streamId: number; index: number; isLast: boolean; data: string } | null {
  if (!isChunk(data)) return null;
  return {
    streamId: fromBase36(data[1]),
    index: fromBase36(data[2]),
    isLast: data[3] === 'L',
    data: data.slice(4).trimEnd(),
  };
}

/**
 * Chunk assembler - collects chunks and reassembles packets
 */
export class ChunkAssembler {
  private streams: Map<number, Map<number, string>> = new Map();
  private streamComplete: Map<number, number> = new Map(); // streamId -> lastIndex

  /**
   * Add a chunk. Returns assembled packet if complete, null otherwise.
   */
  addChunk(data: string): string | null {
    const chunk = parseChunk(data);
    if (!chunk) return null;

    // Get or create stream buffer
    let stream = this.streams.get(chunk.streamId);
    if (!stream) {
      stream = new Map();
      this.streams.set(chunk.streamId, stream);
    }

    // Store chunk data
    stream.set(chunk.index, chunk.data);

    // Track if this is the last chunk
    if (chunk.isLast) {
      this.streamComplete.set(chunk.streamId, chunk.index);
    }

    // Check if stream is complete
    const lastIndex = this.streamComplete.get(chunk.streamId);
    if (lastIndex !== undefined) {
      // Check if we have all chunks 0..lastIndex
      let complete = true;
      for (let i = 0; i <= lastIndex; i++) {
        if (!stream.has(i)) {
          complete = false;
          break;
        }
      }

      if (complete) {
        // Assemble packet
        let assembled = '';
        for (let i = 0; i <= lastIndex; i++) {
          assembled += stream.get(i);
        }
        // Clear this stream
        this.streams.delete(chunk.streamId);
        this.streamComplete.delete(chunk.streamId);
        return assembled.trimEnd();
      }
    }

    return null;
  }

  /**
   * Clear all pending chunks
   */
  clear(): void {
    this.streams.clear();
    this.streamComplete.clear();
  }
}
