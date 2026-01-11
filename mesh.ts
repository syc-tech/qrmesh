/**
 * Mesh State - Connection state machine and peer management
 *
 * This module manages the TCP-like connection state machine,
 * peer tracking, and message handling for the QR-TCP protocol.
 */

import { KeyPair, deriveSharedKey, encrypt, decrypt } from './crypto';
import {
  QRPacket,
  createSynPacket,
  createSynAckPacket,
  createAckPacket,
  createDataPacket,
  createAnnouncePacket,
  createFinPacket,
  hasFlag,
  isForUs,
  MESSAGE_TYPES,
  AnnouncePayload,
  ChatPayload,
  OfferPayload,
} from './protocol';

/**
 * Connection states (TCP-like)
 */
export enum ConnectionState {
  DISCONNECTED = 'DISCONNECTED',
  SYN_SENT = 'SYN_SENT',
  SYN_RECEIVED = 'SYN_RECEIVED',
  ESTABLISHED = 'ESTABLISHED',
  FIN_WAIT = 'FIN_WAIT',
  CLOSED = 'CLOSED',
}

/**
 * Peer information
 */
export interface Peer {
  id: string;
  publicKey: string;
  name?: string;
  state: ConnectionState;
  lastSeen: number;
  sendSeq: number;
  recvSeq: number;
  sharedKey?: CryptoKey;
  pendingPackets: QRPacket[];
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
}

/**
 * Event types emitted by the mesh
 */
export type MeshEvent =
  | { type: 'peer_discovered'; peer: Peer }
  | { type: 'peer_connected'; peer: Peer }
  | { type: 'peer_disconnected'; peer: Peer }
  | { type: 'packet_sent'; packet: QRPacket }
  | { type: 'packet_received'; packet: QRPacket }
  | { type: 'chat_message'; message: ChatMessage }
  | { type: 'offer_received'; peerId: string; offer: OfferPayload }
  | { type: 'error'; message: string };

export type MeshEventHandler = (event: MeshEvent) => void;

/**
 * Configuration options for MeshState
 */
export interface MeshConfig {
  deviceName?: string;
  retryTimeout?: number; // ms before retrying unacked packet
  maxRetries?: number; // max retry attempts
  maxLogSize?: number; // max packet log entries
}

/**
 * Mesh state manager
 *
 * Manages peer connections, packet handling, and the TCP-like
 * state machine for each connection.
 */
export class MeshState {
  private keyPair: KeyPair;
  private peers: Map<string, Peer> = new Map();
  private packetLog: PacketLogEntry[] = [];
  private chatHistory: ChatMessage[] = [];
  private eventHandlers: Set<MeshEventHandler> = new Set();
  private outgoingQueue: QRPacket[] = [];
  private announceSeq: number = 0;
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
   * Get connected peers only
   */
  getConnectedPeers(): Peer[] {
    return this.getPeers().filter((p) => p.state === ConnectionState.ESTABLISHED);
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
   * Get next packet to display as QR code
   *
   * Priority: pending packets needing ACK > queued packets > announce
   */
  getNextOutgoingPacket(): QRPacket | null {
    // Priority 1: pending packets with retries
    for (const peer of this.peers.values()) {
      if (peer.pendingPackets.length > 0) {
        return peer.pendingPackets[0];
      }
    }

    // Priority 2: queued outgoing packets
    if (this.outgoingQueue.length > 0) {
      return this.outgoingQueue[0];
    }

    // Default: broadcast announce
    return this.createAnnounce();
  }

  /**
   * Create an announce packet
   */
  createAnnounce(): QRPacket {
    return createAnnouncePacket(
      this.deviceId,
      this.announceSeq++,
      this.publicKey,
      this.deviceName
    );
  }

  /**
   * Initiate connection to a peer
   */
  connect(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (!peer) {
      this.emit({ type: 'error', message: `Unknown peer: ${peerId}` });
      return;
    }

    if (peer.state !== ConnectionState.DISCONNECTED) {
      return;
    }

    const packet = createSynPacket(this.deviceId, peerId, peer.sendSeq++, {
      publicKey: this.publicKey,
      name: this.deviceName,
    });

    peer.state = ConnectionState.SYN_SENT;
    peer.pendingPackets.push(packet);
    this.logPacket(packet, 'sent', 'pending');
    this.emit({ type: 'packet_sent', packet });
  }

  /**
   * Send a chat message to a connected peer
   */
  async sendChat(peerId: string, text: string): Promise<void> {
    const peer = this.peers.get(peerId);
    if (!peer || peer.state !== ConnectionState.ESTABLISHED) {
      this.emit({ type: 'error', message: 'Peer not connected' });
      return;
    }

    let payload: ChatPayload;

    if (peer.sharedKey) {
      const { ciphertext, iv } = await encrypt(peer.sharedKey, text);
      payload = { encrypted: true, ciphertext, iv };
    } else {
      payload = { encrypted: false, plaintext: text };
    }

    const packet = createDataPacket(
      this.deviceId,
      peerId,
      peer.sendSeq++,
      peer.recvSeq,
      MESSAGE_TYPES.CHAT,
      payload
    );

    peer.pendingPackets.push(packet);
    this.logPacket(packet, 'sent', 'pending');
    this.emit({ type: 'packet_sent', packet });

    const message: ChatMessage = {
      peerId,
      direction: 'sent',
      text,
      timestamp: Date.now(),
      encrypted: !!peer.sharedKey,
    };
    this.chatHistory.push(message);
    this.emit({ type: 'chat_message', message });
  }

  /**
   * Send connection upgrade offer to a peer
   */
  sendOffer(peerId: string, offer: OfferPayload): void {
    const peer = this.peers.get(peerId);
    if (!peer || peer.state !== ConnectionState.ESTABLISHED) {
      this.emit({ type: 'error', message: 'Peer not connected' });
      return;
    }

    const packet = createDataPacket(
      this.deviceId,
      peerId,
      peer.sendSeq++,
      peer.recvSeq,
      MESSAGE_TYPES.OFFER,
      offer
    );

    peer.pendingPackets.push(packet);
    this.logPacket(packet, 'sent', 'pending');
    this.emit({ type: 'packet_sent', packet });
  }

  /**
   * Disconnect from a peer
   */
  disconnect(peerId: string): void {
    const peer = this.peers.get(peerId);
    if (!peer || peer.state !== ConnectionState.ESTABLISHED) {
      return;
    }

    const packet = createFinPacket(
      this.deviceId,
      peerId,
      peer.sendSeq++,
      peer.recvSeq
    );

    peer.state = ConnectionState.FIN_WAIT;
    peer.pendingPackets.push(packet);
    this.logPacket(packet, 'sent', 'pending');
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

    // Handle based on packet type
    if (hasFlag(packet, 'SYN') && !hasFlag(packet, 'ACK')) {
      await this.handleSyn(packet);
    } else if (hasFlag(packet, 'SYN') && hasFlag(packet, 'ACK')) {
      await this.handleSynAck(packet);
    } else if (hasFlag(packet, 'ACK') && !hasFlag(packet, 'SYN') && !hasFlag(packet, 'FIN')) {
      this.handleAck(packet);
    } else if (hasFlag(packet, 'FIN')) {
      this.handleFin(packet);
    } else if (hasFlag(packet, 'DATA')) {
      await this.handleData(packet);
    }
  }

  /**
   * Process a broadcast announce packet
   */
  processAnnounce(packet: QRPacket): void {
    if (packet.src === this.deviceId) return;
    if (packet.type !== MESSAGE_TYPES.ANNOUNCE) return;

    const payload = packet.payload as AnnouncePayload;
    if (!payload?.publicKey) return;

    let peer = this.peers.get(packet.src);
    if (!peer) {
      peer = this.createPeer(packet.src, payload.publicKey, payload.name);
      this.emit({ type: 'peer_discovered', peer });
    } else {
      peer.lastSeen = Date.now();
      if (payload.name) peer.name = payload.name;
    }
  }

  /**
   * Mark a packet as displayed (for queue management)
   */
  markPacketDisplayed(packet: QRPacket): void {
    const queueIndex = this.outgoingQueue.findIndex(
      (p) => p.src === packet.src && p.seq === packet.seq
    );
    if (queueIndex !== -1) {
      this.outgoingQueue.splice(queueIndex, 1);
    }
  }

  /**
   * Check for packets that need retransmission
   */
  checkRetries(): void {
    const now = Date.now();
    for (const peer of this.peers.values()) {
      peer.pendingPackets = peer.pendingPackets.filter((packet) => {
        const logEntry = this.packetLog.find(
          (e) =>
            e.direction === 'sent' &&
            e.packet.src === packet.src &&
            e.packet.seq === packet.seq
        );
        if (!logEntry) return true;

        if (now - logEntry.timestamp > this.retryTimeout) {
          const retryCount = this.packetLog.filter(
            (e) =>
              e.direction === 'sent' &&
              e.packet.src === packet.src &&
              e.packet.seq === packet.seq
          ).length;

          if (retryCount >= this.maxRetries) {
            logEntry.status = 'failed';
            return false;
          }

          this.logPacket(packet, 'sent', 'pending');
          return true;
        }
        return true;
      });
    }
  }

  // Private handlers

  private async handleSyn(packet: QRPacket): Promise<void> {
    const payload = packet.payload as AnnouncePayload | undefined;
    let peer = this.peers.get(packet.src);

    if (!peer && payload?.publicKey) {
      peer = this.createPeer(packet.src, payload.publicKey, payload.name);
      this.emit({ type: 'peer_discovered', peer });
    }

    if (!peer) return;

    peer.lastSeen = Date.now();
    peer.recvSeq = packet.seq + 1;

    if (payload?.publicKey && !peer.sharedKey) {
      try {
        peer.sharedKey = await deriveSharedKey(this.keyPair.privateKey, payload.publicKey);
      } catch (e) {
        console.error('Failed to derive shared key:', e);
      }
    }

    const response = createSynAckPacket(
      this.deviceId,
      packet.src,
      peer.sendSeq++,
      peer.recvSeq,
      { publicKey: this.publicKey, name: this.deviceName }
    );

    peer.state = ConnectionState.SYN_RECEIVED;
    peer.pendingPackets.push(response);
    this.logPacket(response, 'sent', 'pending');
    this.emit({ type: 'packet_sent', packet: response });
  }

  private async handleSynAck(packet: QRPacket): Promise<void> {
    const peer = this.peers.get(packet.src);
    if (!peer || peer.state !== ConnectionState.SYN_SENT) {
      return;
    }

    const payload = packet.payload as AnnouncePayload | undefined;

    peer.lastSeen = Date.now();
    peer.recvSeq = packet.seq + 1;

    if (payload?.publicKey && !peer.sharedKey) {
      try {
        peer.sharedKey = await deriveSharedKey(this.keyPair.privateKey, payload.publicKey);
      } catch (e) {
        console.error('Failed to derive shared key:', e);
      }
    }

    peer.pendingPackets = peer.pendingPackets.filter(
      (p) => !(hasFlag(p, 'SYN') && !hasFlag(p, 'ACK'))
    );

    const response = createAckPacket(
      this.deviceId,
      packet.src,
      peer.sendSeq++,
      peer.recvSeq
    );

    peer.state = ConnectionState.ESTABLISHED;
    this.outgoingQueue.push(response);
    this.logPacket(response, 'sent');
    this.emit({ type: 'packet_sent', packet: response });
    this.emit({ type: 'peer_connected', peer });
  }

  private handleAck(packet: QRPacket): void {
    const peer = this.peers.get(packet.src);
    if (!peer) return;

    peer.lastSeen = Date.now();
    peer.pendingPackets = peer.pendingPackets.filter((p) => p.seq >= packet.ack);

    this.packetLog.forEach((entry) => {
      if (
        entry.direction === 'sent' &&
        entry.packet.dst === packet.src &&
        entry.packet.seq < packet.ack
      ) {
        entry.status = 'acked';
      }
    });

    if (peer.state === ConnectionState.SYN_RECEIVED) {
      peer.state = ConnectionState.ESTABLISHED;
      this.emit({ type: 'peer_connected', peer });
    }
  }

  private handleFin(packet: QRPacket): void {
    const peer = this.peers.get(packet.src);
    if (!peer) return;

    peer.lastSeen = Date.now();

    const response = createAckPacket(
      this.deviceId,
      packet.src,
      peer.sendSeq++,
      packet.seq + 1
    );

    peer.state = ConnectionState.CLOSED;
    this.outgoingQueue.push(response);
    this.logPacket(response, 'sent');
    this.emit({ type: 'packet_sent', packet: response });
    this.emit({ type: 'peer_disconnected', peer });
  }

  private async handleData(packet: QRPacket): Promise<void> {
    const peer = this.peers.get(packet.src);
    if (!peer || peer.state !== ConnectionState.ESTABLISHED) {
      return;
    }

    peer.lastSeen = Date.now();
    peer.recvSeq = packet.seq + 1;

    const ack = createAckPacket(
      this.deviceId,
      packet.src,
      peer.sendSeq,
      peer.recvSeq
    );
    this.outgoingQueue.push(ack);
    this.logPacket(ack, 'sent');

    switch (packet.type) {
      case MESSAGE_TYPES.CHAT:
        await this.handleChatMessage(peer, packet.payload as ChatPayload);
        break;
      case MESSAGE_TYPES.OFFER:
        this.handleOffer(peer, packet.payload as OfferPayload);
        break;
      case MESSAGE_TYPES.ANNOUNCE:
        const announcePayload = packet.payload as AnnouncePayload;
        if (announcePayload.name) {
          peer.name = announcePayload.name;
        }
        break;
    }
  }

  private async handleChatMessage(peer: Peer, payload: ChatPayload): Promise<void> {
    let text: string;

    if (payload.encrypted && payload.ciphertext && payload.iv && peer.sharedKey) {
      try {
        text = await decrypt(peer.sharedKey, payload.ciphertext, payload.iv);
      } catch (e) {
        console.error('Failed to decrypt message:', e);
        text = '[Decryption failed]';
      }
    } else if (payload.plaintext) {
      text = payload.plaintext;
    } else {
      text = '[Invalid message]';
    }

    const message: ChatMessage = {
      peerId: peer.id,
      direction: 'received',
      text,
      timestamp: Date.now(),
      encrypted: !!payload.encrypted,
    };

    this.chatHistory.push(message);
    this.emit({ type: 'chat_message', message });
  }

  private handleOffer(peer: Peer, offer: OfferPayload): void {
    peer.offer = offer;
    this.emit({ type: 'offer_received', peerId: peer.id, offer });
  }

  private createPeer(id: string, publicKey: string, name?: string): Peer {
    const peer: Peer = {
      id,
      publicKey,
      name,
      state: ConnectionState.DISCONNECTED,
      lastSeen: Date.now(),
      sendSeq: 0,
      recvSeq: 0,
      pendingPackets: [],
    };
    this.peers.set(id, peer);
    return peer;
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
