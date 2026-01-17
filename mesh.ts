/**
 * Mesh State - QUIC-style peer management with ultra-compact packets
 *
 * Protocol v3 uses minimal beacons for discovery, only exchanging
 * full public keys when actually communicating.
 */

import { KeyPair, deriveSharedKey, decrypt } from './crypto';
import {
  QRPacket,
  AckRange,
  OfferPayload,
  createBeaconPacket,
  createInitialPacket,
  createDataPacket,
  createAckPacket,
  parseChatPayload,
  isForUs,
  addToAckRanges,
  PACKET_TYPES,
  MESSAGE_TYPES,
} from './protocol';

/**
 * Sent packet tracking
 */
export interface SentPacket {
  packet: QRPacket;
  timestamp: number;
  retries: number;
  status: 'pending' | 'acked' | 'failed';
}

/**
 * Peer information
 */
export interface Peer {
  id: string;
  publicKey?: string;         // Only set after INITIAL exchange
  name?: string;
  sharedKey?: CryptoKey;
  lastSeen: number;
  receivedPns: AckRange[];
  ackedByPeer: AckRange[];
  nextPn: number;
  sentPackets: Map<number, SentPacket>;
  offer?: OfferPayload;
}

/**
 * Log entry
 */
export interface PacketLogEntry {
  timestamp: number;
  direction: 'sent' | 'received';
  packet: QRPacket;
  status?: 'pending' | 'acked' | 'failed';
}

/**
 * Chat message
 */
export interface ChatMessage {
  peerId: string;
  direction: 'sent' | 'received';
  text: string;
  timestamp: number;
  encrypted: boolean;
  pn?: number;
}

/**
 * Event types
 */
export type MeshEvent =
  | { type: 'peer_discovered'; peer: Peer }
  | { type: 'peer_updated'; peer: Peer }
  | { type: 'packet_sent'; packet: QRPacket }
  | { type: 'packet_received'; packet: QRPacket }
  | { type: 'packet_acked'; pn: number; peerId: string }
  | { type: 'packet_failed'; pn: number; peerId: string }
  | { type: 'chat_message'; message: ChatMessage }
  | { type: 'offer_received'; peerId: string; offer: OfferPayload }
  | { type: 'error'; message: string };

export type MeshEventHandler = (event: MeshEvent) => void;

/**
 * Config
 */
export interface MeshConfig {
  deviceName?: string;
  retryTimeout?: number;
  maxRetries?: number;
  maxLogSize?: number;
}

/**
 * Mesh state manager
 */
export class MeshState {
  private keyPair: KeyPair;
  private peers: Map<string, Peer> = new Map();
  private packetLog: PacketLogEntry[] = [];
  private chatHistory: ChatMessage[] = [];
  private eventHandlers: Set<MeshEventHandler> = new Set();
  private globalPn: number = 0;
  private cachedBeacon: QRPacket | null = null;
  private deviceName?: string;
  private retryTimeout: number;
  private maxRetries: number;
  private maxLogSize: number;

  constructor(keyPair: KeyPair, config: MeshConfig = {}) {
    this.keyPair = keyPair;
    this.deviceName = config.deviceName;
    this.retryTimeout = config.retryTimeout ?? 3000;
    this.maxRetries = config.maxRetries ?? 3;
    this.maxLogSize = config.maxLogSize ?? 100;
  }

  get deviceId(): string {
    return this.keyPair.deviceId;
  }

  get publicKey(): string {
    return this.keyPair.publicKeyRaw;
  }

  subscribe(handler: MeshEventHandler): () => void {
    this.eventHandlers.add(handler);
    return () => this.eventHandlers.delete(handler);
  }

  private emit(event: MeshEvent): void {
    this.eventHandlers.forEach((handler) => handler(event));
  }

  getPeers(): Peer[] {
    return Array.from(this.peers.values());
  }

  getPeer(peerId: string): Peer | undefined {
    return this.peers.get(peerId);
  }

  getActivePeers(): Peer[] {
    return this.getPeers().filter((p) => p.sharedKey !== undefined);
  }

  getPacketLog(): PacketLogEntry[] {
    return [...this.packetLog];
  }

  getChatHistory(peerId?: string): ChatMessage[] {
    if (peerId) {
      return this.chatHistory.filter((m) => m.peerId === peerId);
    }
    return [...this.chatHistory];
  }

  getDeliveryStatus(peerId: string): { pending: number[]; acked: number[]; failed: number[] } {
    const peer = this.peers.get(peerId);
    if (!peer) return { pending: [], acked: [], failed: [] };

    const pending: number[] = [];
    const acked: number[] = [];
    const failed: number[] = [];

    for (const [pn, sent] of peer.sentPackets) {
      if (sent.status === 'pending') pending.push(pn);
      else if (sent.status === 'acked') acked.push(pn);
      else if (sent.status === 'failed') failed.push(pn);
    }

    return { pending, acked, failed };
  }

  private getNextPn(): number {
    return this.globalPn++;
  }

  /**
   * Get packets to display - returns minimal beacon by default
   */
  getOutgoingPackets(maxPackets: number = 3): QRPacket[] {
    const packets: QRPacket[] = [];
    const now = Date.now();

    // Priority 1: Packets needing retransmission
    for (const peer of this.peers.values()) {
      for (const [, sent] of peer.sentPackets) {
        if (sent.status === 'pending' && now - sent.timestamp > this.retryTimeout) {
          if (sent.retries < this.maxRetries) {
            packets.push(sent.packet);
            if (packets.length >= maxPackets) return packets;
          }
        }
      }
    }

    // Priority 2: Fresh pending packets
    for (const peer of this.peers.values()) {
      for (const [, sent] of peer.sentPackets) {
        if (sent.status === 'pending' && now - sent.timestamp <= this.retryTimeout) {
          packets.push(sent.packet);
          if (packets.length >= maxPackets) return packets;
        }
      }
    }

    // Default: minimal beacon
    if (packets.length === 0) {
      packets.push(this.createBeacon());
    }

    return packets;
  }

  getNextOutgoingPacket(): QRPacket | null {
    const packets = this.getOutgoingPackets(1);
    return packets[0] || null;
  }

  /**
   * Create minimal beacon (just ID + name, no key!)
   */
  createBeacon(): QRPacket {
    if (!this.cachedBeacon) {
      this.cachedBeacon = createBeaconPacket(this.deviceId, this.deviceName);
    }
    return this.cachedBeacon;
  }

  invalidateBeacon(): void {
    this.cachedBeacon = null;
  }

  /**
   * Send chat - sends plaintext for now (encryption disabled for QR size)
   */
  async sendChat(peerId: string, text: string): Promise<number> {
    let peer = this.peers.get(peerId);

    if (!peer) {
      this.emit({ type: 'error', message: `Unknown peer: ${peerId}` });
      return -1;
    }

    const pn = this.getNextPn();
    const acks = peer.receivedPns.length > 0 ? peer.receivedPns : undefined;

    // Send raw text as payload (no JSON wrapper) for minimal QR size
    const packet = createDataPacket(this.deviceId, peerId, pn, MESSAGE_TYPES.CHAT, text, acks);
    this.trackSentPacket(peer, packet);
    this.emit({ type: 'packet_sent', packet });

    const message: ChatMessage = {
      peerId,
      direction: 'sent',
      text,
      timestamp: Date.now(),
      encrypted: false,
      pn,
    };
    this.chatHistory.push(message);
    this.emit({ type: 'chat_message', message });

    return pn;
  }

  sendOffer(peerId: string, offer: OfferPayload): number {
    const peer = this.peers.get(peerId);
    if (!peer) {
      this.emit({ type: 'error', message: `Unknown peer: ${peerId}` });
      return -1;
    }

    const pn = this.getNextPn();
    const acks = peer.receivedPns.length > 0 ? peer.receivedPns : undefined;
    const packet = createDataPacket(
      this.deviceId,
      peerId,
      pn,
      MESSAGE_TYPES.OFFER,
      JSON.stringify(offer),
      acks
    );

    this.trackSentPacket(peer, packet);
    this.emit({ type: 'packet_sent', packet });

    return pn;
  }

  sendAck(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (!peer || peer.receivedPns.length === 0) return;

    const pn = this.getNextPn();
    const packet = createAckPacket(this.deviceId, peerId, pn, peer.receivedPns);
    this.logPacket(packet, 'sent');
    this.emit({ type: 'packet_sent', packet });
  }

  /**
   * Process received packet
   */
  async processPacket(packet: QRPacket): Promise<void> {
    if (packet.src === this.deviceId) return;
    if (!isForUs(packet, this.deviceId)) return;

    this.logPacket(packet, 'received');
    this.emit({ type: 'packet_received', packet });

    let peer = this.peers.get(packet.src);
    const isNewPeer = !peer;

    // Create peer if needed (for INITIAL packets that have key)
    if (!peer) {
      if (packet.t === PACKET_TYPES.INITIAL && packet.key) {
        peer = this.createPeer(packet.src, packet.key, packet.name);
      } else {
        return; // Can't process without peer
      }
    }

    peer.lastSeen = Date.now();

    // Track received pn (except for beacons which always have pn=0)
    if (packet.t !== PACKET_TYPES.BEACON) {
      peer.receivedPns = addToAckRanges(peer.receivedPns, packet.pn);
    }

    // Process ACKs
    if (packet.acks && packet.acks.length > 0) {
      this.processAcks(peer, packet.acks);
    }

    // Handle by type
    switch (packet.t) {
      case PACKET_TYPES.BEACON:
        // Beacon just updates lastSeen, maybe name
        if (packet.name) peer.name = packet.name;
        if (isNewPeer) {
          this.emit({ type: 'peer_discovered', peer });
        }
        break;

      case PACKET_TYPES.INITIAL:
        await this.handleInitial(peer, packet, isNewPeer);
        break;

      case PACKET_TYPES.DATA:
        // Queue ACK first, so updateQR will see it when chat_message is emitted
        this.queueAck(peer);
        await this.handleData(peer, packet);
        break;

      case PACKET_TYPES.ACK:
        // Already processed above
        break;
    }
  }

  /**
   * Queue an ACK packet to be displayed
   */
  private queueAck(peer: Peer): void {
    // Check if we already have a pending ACK for this peer
    const hasAck = Array.from(peer.sentPackets.values())
      .some(s => s.packet.t === PACKET_TYPES.ACK && s.status === 'pending');

    if (!hasAck && peer.receivedPns.length > 0) {
      const pn = this.getNextPn();
      const ackPacket = createAckPacket(this.deviceId, peer.id, pn, peer.receivedPns);
      this.trackSentPacket(peer, ackPacket);
    }
  }

  /**
   * Process beacon (discovery only, no key)
   * Automatically sends INITIAL to start key exchange
   */
  processBeacon(packet: QRPacket): void {
    if (packet.src === this.deviceId) return;
    if (packet.t !== PACKET_TYPES.BEACON) return;

    let peer = this.peers.get(packet.src);
    if (!peer) {
      // Create peer without key - will get key on INITIAL
      peer = this.createPeer(packet.src, undefined, packet.name);
      this.emit({ type: 'peer_discovered', peer });
    } else {
      peer.lastSeen = Date.now();
      if (packet.name) peer.name = packet.name;
      this.emit({ type: 'peer_updated', peer });
    }

    // Don't auto-send INITIAL - it's too large for reliable QR scanning
    // Key exchange will happen when first message is sent (if needed)
  }

  markPacketDisplayed(packet: QRPacket): void {
    const peer = this.peers.get(packet.dst);
    if (!peer) return;

    const sent = peer.sentPackets.get(packet.pn);
    if (sent && sent.status === 'pending') {
      sent.timestamp = Date.now();
      sent.retries++;
    }
  }

  checkRetries(): void {
    const now = Date.now();

    for (const peer of this.peers.values()) {
      for (const [pn, sent] of peer.sentPackets) {
        if (sent.status !== 'pending') continue;

        if (now - sent.timestamp > this.retryTimeout && sent.retries >= this.maxRetries) {
          sent.status = 'failed';
          this.emit({ type: 'packet_failed', pn, peerId: peer.id });

          this.packetLog.forEach((entry) => {
            if (entry.packet.pn === pn && entry.packet.dst === peer.id) {
              entry.status = 'failed';
            }
          });
        }
      }
    }
  }

  // Private handlers

  private async handleInitial(peer: Peer, packet: QRPacket, isNewPeer: boolean): Promise<void> {
    if (packet.key && !peer.sharedKey) {
      peer.publicKey = packet.key;
      try {
        peer.sharedKey = await deriveSharedKey(this.keyPair.privateKey, packet.key);
      } catch (e) {
        console.error('Failed to derive shared key:', e);
      }
    }

    if (packet.name) peer.name = packet.name;

    if (isNewPeer) {
      this.emit({ type: 'peer_discovered', peer });
    } else {
      this.emit({ type: 'peer_updated', peer });
    }

    // Respond with our INITIAL
    if (peer.sharedKey) {
      const pn = this.getNextPn();
      const response = createInitialPacket(
        this.deviceId,
        peer.id,
        pn,
        this.publicKey,
        this.deviceName,
        peer.receivedPns
      );
      this.trackSentPacket(peer, response);
      this.emit({ type: 'packet_sent', packet: response });
    }
  }

  private async handleData(peer: Peer, packet: QRPacket): Promise<void> {
    switch (packet.mt) {
      case MESSAGE_TYPES.CHAT:
        await this.handleChat(peer, packet);
        break;
      case MESSAGE_TYPES.OFFER:
        if (packet.payload) {
          try {
            const offer = JSON.parse(packet.payload) as OfferPayload;
            peer.offer = offer;
            this.emit({ type: 'offer_received', peerId: peer.id, offer });
          } catch { }
        }
        break;
    }
  }

  private async handleChat(peer: Peer, packet: QRPacket): Promise<void> {
    if (!packet.payload) return;

    let text: string;

    // Try to parse as JSON (old format), otherwise treat as raw text (new compact format)
    const payload = parseChatPayload(packet);
    if (payload) {
      if (payload.e && payload.c && payload.i && peer.sharedKey) {
        try {
          text = await decrypt(peer.sharedKey, payload.c, payload.i);
        } catch (e) {
          console.error('Decrypt failed:', e);
          text = '[Decryption failed]';
        }
      } else if (payload.p) {
        text = payload.p;
      } else {
        text = '[Invalid message]';
      }
    } else {
      // Raw text payload (compact format)
      text = packet.payload;
    }

    const message: ChatMessage = {
      peerId: peer.id,
      direction: 'received',
      text,
      timestamp: Date.now(),
      encrypted: !!(payload && payload.e),
      pn: packet.pn,
    };

    this.chatHistory.push(message);
    this.emit({ type: 'chat_message', message });
  }

  private processAcks(peer: Peer, acks: AckRange[]): void {
    for (const [start, end] of acks) {
      for (let pn = start; pn <= end; pn++) {
        const sent = peer.sentPackets.get(pn);
        if (sent && sent.status === 'pending') {
          sent.status = 'acked';
          this.emit({ type: 'packet_acked', pn, peerId: peer.id });

          this.packetLog.forEach((entry) => {
            if (entry.packet.pn === pn && entry.packet.dst === peer.id) {
              entry.status = 'acked';
            }
          });
        }
      }
    }
    peer.ackedByPeer = acks;
  }

  private createPeer(id: string, publicKey?: string, name?: string): Peer {
    const peer: Peer = {
      id,
      publicKey,
      name,
      lastSeen: Date.now(),
      receivedPns: [],
      ackedByPeer: [],
      nextPn: 0,
      sentPackets: new Map(),
    };
    this.peers.set(id, peer);
    return peer;
  }

  private trackSentPacket(peer: Peer, packet: QRPacket): void {
    peer.sentPackets.set(packet.pn, {
      packet,
      timestamp: Date.now(),
      retries: 0,
      status: 'pending',
    });
    this.logPacket(packet, 'sent', 'pending');
  }

  private logPacket(
    packet: QRPacket,
    direction: 'sent' | 'received',
    status?: 'pending' | 'acked' | 'failed'
  ): void {
    this.packetLog.push({
      timestamp: Date.now(),
      direction,
      packet,
      status,
    });

    if (this.packetLog.length > this.maxLogSize) {
      this.packetLog = this.packetLog.slice(-this.maxLogSize);
    }
  }
}

export type { AckRange } from './protocol';
