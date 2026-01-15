/**
 * Mesh State - QUIC-style peer management and packet handling
 *
 * Key differences from TCP-style:
 * - No connection state machine (no handshake)
 * - SACK-style acknowledgments with ranges
 * - Parallel packet transmission (don't wait for ACKs)
 * - 0-RTT: Send encrypted data immediately if we have peer's key
 */

import { KeyPair, deriveSharedKey, encrypt, decrypt } from './crypto';
import {
  QRPacket,
  AckRange,
  createInitialPacket,
  createDataPacket,
  createAckPacket,
  createAnnouncePacket,
  createChatPacket,
  isForUs,
  addToAckRanges,
  PACKET_TYPES,
  MESSAGE_TYPES,
  InitialPayload,
  AnnouncePayload,
  ChatPayload,
  OfferPayload,
} from './protocol';

/**
 * Sent packet tracking for delivery status
 */
export interface SentPacket {
  packet: QRPacket;
  timestamp: number;
  retries: number;
  status: 'pending' | 'acked' | 'failed';
}

/**
 * Peer information (simplified from TCP-style)
 */
export interface Peer {
  id: string;
  publicKey: string;
  name?: string;
  sharedKey?: CryptoKey;      // Derived shared key for encryption
  lastSeen: number;
  // SACK tracking
  receivedPns: AckRange[];    // Packet numbers we've received from this peer
  ackedByPeer: AckRange[];    // What this peer has acked from us
  // Outgoing
  nextPn: number;             // Next packet number to use when sending
  sentPackets: Map<number, SentPacket>; // pn -> sent packet info
  offer?: OfferPayload;
}

/**
 * Log entry for packet history
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
  pn?: number;  // Packet number for tracking delivery
}

/**
 * Event types emitted by the mesh
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
 * Configuration options for MeshState
 */
export interface MeshConfig {
  deviceName?: string;
  retryTimeout?: number;  // ms before retrying unacked packet
  maxRetries?: number;    // max retry attempts
  maxLogSize?: number;    // max packet log entries
}

/**
 * Mesh state manager (QUIC-style)
 */
export class MeshState {
  private keyPair: KeyPair;
  private peers: Map<string, Peer> = new Map();
  private packetLog: PacketLogEntry[] = [];
  private chatHistory: ChatMessage[] = [];
  private eventHandlers: Set<MeshEventHandler> = new Set();
  private globalPn: number = 0;  // Global packet number counter
  private cachedAnnounce: QRPacket | null = null;
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

  /**
   * Get this device's ID
   */
  get deviceId(): string {
    return this.keyPair.deviceId;
  }

  /**
   * Get this device's public key
   */
  get publicKey(): string {
    return this.keyPair.publicKeyRaw;
  }

  /**
   * Subscribe to mesh events
   */
  subscribe(handler: MeshEventHandler): () => void {
    this.eventHandlers.add(handler);
    return () => this.eventHandlers.delete(handler);
  }

  private emit(event: MeshEvent): void {
    this.eventHandlers.forEach((handler) => handler(event));
  }

  /**
   * Get all known peers
   */
  getPeers(): Peer[] {
    return Array.from(this.peers.values());
  }

  /**
   * Get a specific peer by ID
   */
  getPeer(peerId: string): Peer | undefined {
    return this.peers.get(peerId);
  }

  /**
   * Get peers we can communicate with (have shared key)
   */
  getActivePeers(): Peer[] {
    return this.getPeers().filter((p) => p.sharedKey !== undefined);
  }

  /**
   * Get packet log
   */
  getPacketLog(): PacketLogEntry[] {
    return [...this.packetLog];
  }

  /**
   * Get chat history, optionally filtered by peer
   */
  getChatHistory(peerId?: string): ChatMessage[] {
    if (peerId) {
      return this.chatHistory.filter((m) => m.peerId === peerId);
    }
    return [...this.chatHistory];
  }

  /**
   * Get delivery status for all pending packets to a peer
   */
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

  /**
   * Get next packet number (monotonically increasing)
   */
  private getNextPn(): number {
    return this.globalPn++;
  }

  /**
   * Get packets to display as QR codes
   *
   * Returns multiple packets that can be shown in sequence
   * Priority: packets needing retransmission > new data > announce
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

    // Priority 2: Fresh pending packets (not yet due for retry)
    for (const peer of this.peers.values()) {
      for (const [, sent] of peer.sentPackets) {
        if (sent.status === 'pending' && now - sent.timestamp <= this.retryTimeout) {
          packets.push(sent.packet);
          if (packets.length >= maxPackets) return packets;
        }
      }
    }

    // Default: broadcast announce
    if (packets.length === 0) {
      packets.push(this.createAnnounce());
    }

    return packets;
  }

  /**
   * Get next single packet (for compatibility)
   */
  getNextOutgoingPacket(): QRPacket | null {
    const packets = this.getOutgoingPackets(1);
    return packets[0] || null;
  }

  /**
   * Create an announce packet (cached to avoid QR flickering)
   */
  createAnnounce(): QRPacket {
    if (!this.cachedAnnounce) {
      this.cachedAnnounce = createAnnouncePacket(
        this.deviceId,
        this.getNextPn(),
        this.publicKey,
        this.deviceName
      );
    }
    return this.cachedAnnounce;
  }

  /**
   * Invalidate cached announce (call when something changes)
   */
  invalidateAnnounce(): void {
    this.cachedAnnounce = null;
  }

  /**
   * Send a chat message to a peer (0-RTT if we have their key)
   */
  async sendChat(peerId: string, text: string): Promise<number> {
    let peer = this.peers.get(peerId);

    if (!peer) {
      this.emit({ type: 'error', message: `Unknown peer: ${peerId}` });
      return -1;
    }

    const pn = this.getNextPn();
    let payload: ChatPayload;

    // Include our ACK ranges so peer knows what we've received
    const acks = peer.receivedPns.length > 0 ? peer.receivedPns : undefined;

    if (peer.sharedKey) {
      // Encrypted (0-RTT - we have their key)
      const { ciphertext, iv } = await encrypt(peer.sharedKey, text);
      payload = { enc: true, ct: ciphertext, iv };
    } else {
      // Need to send INITIAL with our key first
      const initialPn = this.getNextPn();
      const initialPacket = createInitialPacket(
        this.deviceId,
        peerId,
        initialPn,
        this.publicKey,
        this.deviceName,
        acks
      );

      this.trackSentPacket(peer, initialPacket);
      this.emit({ type: 'packet_sent', packet: initialPacket });

      // Send plaintext for now (will be encrypted after key exchange)
      payload = { enc: false, pt: text };
    }

    const packet = createChatPacket(
      this.deviceId,
      peerId,
      pn,
      payload,
      acks
    );

    this.trackSentPacket(peer, packet);
    this.emit({ type: 'packet_sent', packet });

    const message: ChatMessage = {
      peerId,
      direction: 'sent',
      text,
      timestamp: Date.now(),
      encrypted: !!peer.sharedKey,
      pn,
    };
    this.chatHistory.push(message);
    this.emit({ type: 'chat_message', message });

    return pn;
  }

  /**
   * Send connection upgrade offer to a peer
   */
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
      offer,
      acks
    );

    this.trackSentPacket(peer, packet);
    this.emit({ type: 'packet_sent', packet });

    return pn;
  }

  /**
   * Send a pure ACK packet (useful when we have nothing else to send)
   */
  sendAck(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (!peer || peer.receivedPns.length === 0) return;

    const pn = this.getNextPn();
    const packet = createAckPacket(
      this.deviceId,
      peerId,
      pn,
      peer.receivedPns
    );

    // ACK packets don't need tracking (they're fire-and-forget)
    this.logPacket(packet, 'sent');
    this.emit({ type: 'packet_sent', packet });
  }

  /**
   * Process a received packet
   */
  async processPacket(packet: QRPacket): Promise<void> {
    // Ignore our own packets
    if (packet.src === this.deviceId) {
      return;
    }

    // Check if packet is for us
    if (!isForUs(packet, this.deviceId)) {
      return;
    }

    this.logPacket(packet, 'received');
    this.emit({ type: 'packet_received', packet });

    // Get or create peer
    let peer = this.peers.get(packet.src);
    const isNewPeer = !peer;

    if (!peer) {
      // Extract public key from packet if available
      let publicKey = '';
      if (packet.t === PACKET_TYPES.INITIAL) {
        const payload = packet.p as InitialPayload;
        publicKey = payload?.key || '';
      }
      if (!publicKey) {
        // Can't create peer without public key
        return;
      }
      peer = this.createPeer(packet.src, publicKey);
    }

    peer.lastSeen = Date.now();

    // Track received packet number
    peer.receivedPns = addToAckRanges(peer.receivedPns, packet.pn);

    // Process ACKs from peer (if any)
    if (packet.acks && packet.acks.length > 0) {
      this.processAcks(peer, packet.acks);
    }

    // Handle based on packet type
    switch (packet.t) {
      case PACKET_TYPES.INITIAL:
        await this.handleInitial(peer, packet, isNewPeer);
        break;
      case PACKET_TYPES.DATA:
        await this.handleData(peer, packet);
        break;
      case PACKET_TYPES.ACK:
        // Already processed acks above
        break;
    }
  }

  /**
   * Process a broadcast announce packet
   */
  processAnnounce(packet: QRPacket): void {
    if (packet.src === this.deviceId) return;
    if (packet.mt !== MESSAGE_TYPES.ANNOUNCE) return;

    const payload = packet.p as AnnouncePayload;
    if (!payload?.key) return;

    let peer = this.peers.get(packet.src);
    if (!peer) {
      peer = this.createPeer(packet.src, payload.key, payload.name);
      this.emit({ type: 'peer_discovered', peer });
    } else {
      peer.lastSeen = Date.now();
      if (payload.name) peer.name = payload.name;
      this.emit({ type: 'peer_updated', peer });
    }
  }

  /**
   * Mark a packet as displayed (for retry timing)
   */
  markPacketDisplayed(packet: QRPacket): void {
    const peer = this.peers.get(packet.dst);
    if (!peer) return;

    const sent = peer.sentPackets.get(packet.pn);
    if (sent && sent.status === 'pending') {
      sent.timestamp = Date.now();
      sent.retries++;
    }
  }

  /**
   * Check for packets that have exceeded max retries
   */
  checkRetries(): void {
    const now = Date.now();

    for (const peer of this.peers.values()) {
      for (const [pn, sent] of peer.sentPackets) {
        if (sent.status !== 'pending') continue;

        if (now - sent.timestamp > this.retryTimeout && sent.retries >= this.maxRetries) {
          sent.status = 'failed';
          this.emit({ type: 'packet_failed', pn, peerId: peer.id });

          // Update log
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
    const payload = packet.p as InitialPayload;

    if (payload?.key && !peer.sharedKey) {
      try {
        peer.sharedKey = await deriveSharedKey(this.keyPair.privateKey, payload.key);
      } catch (e) {
        console.error('Failed to derive shared key:', e);
      }
    }

    if (payload?.name) {
      peer.name = payload.name;
    }

    if (isNewPeer) {
      this.emit({ type: 'peer_discovered', peer });
    } else {
      this.emit({ type: 'peer_updated', peer });
    }

    // Send our INITIAL back (0-RTT key exchange)
    if (!peer.sharedKey) return;

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

  private async handleData(peer: Peer, packet: QRPacket): Promise<void> {
    switch (packet.mt) {
      case MESSAGE_TYPES.CHAT:
        await this.handleChatMessage(peer, packet.p as ChatPayload, packet.pn);
        break;
      case MESSAGE_TYPES.OFFER:
        this.handleOffer(peer, packet.p as OfferPayload);
        break;
      case MESSAGE_TYPES.ANNOUNCE:
        const announcePayload = packet.p as AnnouncePayload;
        if (announcePayload?.name) {
          peer.name = announcePayload.name;
        }
        if (announcePayload?.key && !peer.sharedKey) {
          try {
            peer.sharedKey = await deriveSharedKey(this.keyPair.privateKey, announcePayload.key);
          } catch (e) {
            console.error('Failed to derive shared key:', e);
          }
        }
        break;
    }
  }

  private async handleChatMessage(peer: Peer, payload: ChatPayload, pn: number): Promise<void> {
    let text: string;

    if (payload.enc && payload.ct && payload.iv && peer.sharedKey) {
      try {
        text = await decrypt(peer.sharedKey, payload.ct, payload.iv);
      } catch (e) {
        console.error('Failed to decrypt message:', e);
        text = '[Decryption failed]';
      }
    } else if (payload.pt) {
      text = payload.pt;
    } else {
      text = '[Invalid message]';
    }

    const message: ChatMessage = {
      peerId: peer.id,
      direction: 'received',
      text,
      timestamp: Date.now(),
      encrypted: !!payload.enc,
      pn,
    };

    this.chatHistory.push(message);
    this.emit({ type: 'chat_message', message });
  }

  private handleOffer(peer: Peer, offer: OfferPayload): void {
    peer.offer = offer;
    this.emit({ type: 'offer_received', peerId: peer.id, offer });
  }

  private processAcks(peer: Peer, acks: AckRange[]): void {
    // Update our knowledge of what peer has received
    for (const [start, end] of acks) {
      for (let pn = start; pn <= end; pn++) {
        const sent = peer.sentPackets.get(pn);
        if (sent && sent.status === 'pending') {
          sent.status = 'acked';
          this.emit({ type: 'packet_acked', pn, peerId: peer.id });

          // Update log
          this.packetLog.forEach((entry) => {
            if (entry.packet.pn === pn && entry.packet.dst === peer.id) {
              entry.status = 'acked';
            }
          });
        }
      }
    }

    // Update peer's acked ranges
    peer.ackedByPeer = acks;
  }

  private createPeer(id: string, publicKey: string, name?: string): Peer {
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

// Re-export types that consumers might need
export type { AckRange } from './protocol';
