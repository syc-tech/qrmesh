/**
 * QR-QUIC Demo Web Component
 *
 * A framework-agnostic custom element that provides the full QR-QUIC demo UI.
 * Usage: <qrtcp-demo></qrtcp-demo>
 *
 * Can be used in any framework (React, Vue, Angular, Svelte) or plain HTML.
 */

import QRCode from 'qrcode';
import { getOrCreateKeyPair, type KeyPair, type KeyStorage } from './crypto';
import { encodePacket, decodePacket, PACKET_TYPES, type QRPacket } from './protocol';
import { QRScanner } from './scanner';
import { MeshState, type MeshEvent, type Peer } from './mesh';

// Styles for the component (scoped via Shadow DOM)
const styles = `
  :host {
    display: block;
    font-family: system-ui, -apple-system, sans-serif;
    color: #e2e8f0;
  }

  * {
    box-sizing: border-box;
  }

  .container {
    max-width: 56rem;
    margin: 0 auto;
    padding: 1rem;
  }

  h1 {
    font-size: 1.5rem;
    font-weight: bold;
    margin-bottom: 1rem;
  }

  h2 {
    font-size: 1.125rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }

  .card {
    background: #1e293b;
    border-radius: 0.5rem;
    padding: 1rem;
    margin-bottom: 1rem;
  }

  .grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1rem;
  }

  @media (min-width: 768px) {
    .grid {
      grid-template-columns: 1fr 1fr;
    }
  }

  .qr-container {
    display: flex;
    justify-content: center;
    background: white;
    padding: 1rem;
    border-radius: 0.5rem;
  }

  .qr-container canvas {
    max-width: 400px;
    max-height: 400px;
  }

  .video-container {
    position: relative;
    background: black;
    border-radius: 0.5rem;
    overflow: hidden;
  }

  video {
    width: 100%;
    height: 200px;
    object-fit: cover;
  }

  .video-error {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(0,0,0,0.8);
    color: #f87171;
    text-align: center;
    padding: 1rem;
  }

  .status-bar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 0.5rem;
  }

  .text-muted {
    color: #94a3b8;
    font-size: 0.875rem;
  }

  .text-xs {
    font-size: 0.75rem;
  }

  .text-center {
    text-align: center;
  }

  button {
    background: #2563eb;
    color: white;
    border: none;
    padding: 0.25rem 0.75rem;
    border-radius: 0.25rem;
    cursor: pointer;
    font-size: 0.875rem;
  }

  button:hover {
    background: #1d4ed8;
  }

  button:disabled {
    background: #4b5563;
    cursor: not-allowed;
  }

  button.success {
    background: #16a34a;
  }

  button.success:hover {
    background: #15803d;
  }

  input[type="text"] {
    background: #334155;
    border: none;
    padding: 0.5rem 0.75rem;
    border-radius: 0.25rem;
    color: #e2e8f0;
    font-size: 0.875rem;
  }

  input[type="text"]:focus {
    outline: 2px solid #3b82f6;
  }

  .device-info {
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .device-id {
    font-family: monospace;
    color: #4ade80;
  }

  .peer-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.5rem;
    background: rgba(51, 65, 85, 0.5);
    border-radius: 0.25rem;
    margin-bottom: 0.5rem;
  }

  .peer-item.selected {
    background: #334155;
  }

  .peer-id {
    font-family: monospace;
    color: #60a5fa;
  }

  .peer-name {
    color: #cbd5e1;
    margin-left: 0.5rem;
  }

  .state-active { color: #4ade80; }
  .state-discovered { color: #facc15; }
  .state-error { color: #f87171; }

  .peer-actions {
    display: flex;
    gap: 0.5rem;
  }

  .delivery-status {
    display: flex;
    gap: 0.25rem;
    align-items: center;
    font-size: 0.75rem;
    margin-left: 0.5rem;
  }

  .delivery-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
  }

  .delivery-dot.pending { background: #f59e0b; }
  .delivery-dot.acked { background: #10b981; }
  .delivery-dot.failed { background: #ef4444; }

  .chat-container {
    background: #0f172a;
    border-radius: 0.25rem;
    padding: 0.5rem;
    height: 10rem;
    overflow-y: auto;
    margin-bottom: 0.5rem;
  }

  .chat-message {
    font-size: 0.875rem;
    margin-bottom: 0.25rem;
  }

  .chat-message.sent {
    text-align: right;
  }

  .chat-message.received {
    text-align: left;
  }

  .chat-bubble {
    display: inline-block;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
  }

  .chat-bubble.sent {
    background: #2563eb;
  }

  .chat-bubble.received {
    background: #334155;
  }

  .chat-bubble.pending {
    background: #1e3a5f;
    border: 1px dashed #3b82f6;
  }

  .encrypted-badge {
    color: #4ade80;
    font-size: 0.75rem;
    margin-left: 0.25rem;
  }

  .status-icon {
    font-size: 0.75rem;
    margin-left: 0.25rem;
  }

  .status-icon.pending { color: #f59e0b; }
  .status-icon.acked { color: #10b981; }
  .status-icon.failed { color: #ef4444; }

  .chat-input {
    display: flex;
    gap: 0.5rem;
  }

  .chat-input input {
    flex: 1;
  }

  .log-container {
    background: #0f172a;
    border-radius: 0.25rem;
    padding: 0.5rem;
    height: 12rem;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.75rem;
  }

  .log-entry {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 0.25rem;
  }

  .log-time { color: #64748b; }
  .log-sent { color: #60a5fa; }
  .log-received { color: #4ade80; }
  .log-target { color: #cbd5e1; }
  .log-packet { color: #facc15; }
  .log-acked { color: #4ade80; }
  .log-failed { color: #f87171; }
  .log-pending { color: #64748b; }

  .info-list {
    list-style: disc;
    padding-left: 1.5rem;
    color: #94a3b8;
    font-size: 0.875rem;
  }

  .info-list li {
    margin-bottom: 0.25rem;
  }

  .hidden {
    display: none;
  }
`;

/**
 * QR-QUIC Demo Custom Element
 */
export class QRTCPDemoElement extends HTMLElement {
  private shadow: ShadowRoot;
  private keyPair: KeyPair | null = null;
  private mesh: MeshState | null = null;
  private scanner: QRScanner | null = null;
  private retryInterval: ReturnType<typeof setInterval> | null = null;
  private selectedPeer: string | null = null;
  private deviceName: string = '';
  private lastDisplayedPacket: string | null = null;

  // DOM elements
  private qrCanvas: HTMLCanvasElement | null = null;
  private videoEl: HTMLVideoElement | null = null;
  private peerList: HTMLElement | null = null;
  private packetLog: HTMLElement | null = null;
  private chatSection: HTMLElement | null = null;
  private chatMessages: HTMLElement | null = null;
  private chatInput: HTMLInputElement | null = null;
  private scanStatus: HTMLElement | null = null;
  private cameraError: HTMLElement | null = null;
  private startCameraBtn: HTMLButtonElement | null = null;
  private deviceIdEl: HTMLElement | null = null;
  private deviceNameInput: HTMLInputElement | null = null;

  constructor() {
    super();
    this.shadow = this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
    this.init();
  }

  disconnectedCallback() {
    this.cleanup();
  }

  private cleanup() {
    if (this.retryInterval) clearInterval(this.retryInterval);
    this.scanner?.stop();
  }

  private async init() {
    try {
      // Create storage adapter
      const storage: KeyStorage = {
        get: (key) => localStorage.getItem(key),
        set: (key, value) => localStorage.setItem(key, value),
        remove: (key) => localStorage.removeItem(key),
      };

      this.keyPair = await getOrCreateKeyPair(storage);
      this.deviceName = localStorage.getItem('qrtcp-device-name') || '';

      if (this.deviceIdEl) {
        this.deviceIdEl.textContent = this.keyPair.deviceId;
      }
      if (this.deviceNameInput) {
        this.deviceNameInput.value = this.deviceName;
      }

      this.mesh = new MeshState(this.keyPair, { deviceName: this.deviceName || undefined });
      this.mesh.subscribe((event) => this.handleMeshEvent(event));

      // Show initial beacon (static)
      this.updateQR();

      // Only check retries periodically, update QR only when needed
      this.retryInterval = setInterval(() => {
        this.mesh?.checkRetries();
        if (this.hasPendingPackets()) {
          this.updateQR();
        }
      }, 1000);

      this.updateScanStatus('Beacon ready');
    } catch (e) {
      console.error('Init failed:', e);
      this.updateScanStatus('Initialization failed');
    }
  }

  private handleMeshEvent(event: MeshEvent) {
    switch (event.type) {
      case 'peer_discovered':
      case 'peer_updated':
        this.renderPeerList();
        break;
      case 'packet_sent':
      case 'packet_received':
        this.renderPacketLog();
        break;
      case 'packet_acked':
      case 'packet_failed':
        this.renderPacketLog();
        this.renderChatMessages();
        break;
      case 'chat_message':
        this.renderChatMessages();
        break;
      case 'error':
        console.error('Mesh error:', event.message);
        break;
    }
  }

  private async updateQR() {
    if (!this.mesh || !this.qrCanvas) return;

    const packet = this.mesh.getNextOutgoingPacket();
    if (packet) {
      const data = encodePacket(packet);

      // Only redraw if changed
      if (data === this.lastDisplayedPacket) return;
      this.lastDisplayedPacket = data;

      try {
        await QRCode.toCanvas(this.qrCanvas, data, {
          width: 400,
          margin: 1,
          errorCorrectionLevel: 'L',
        });
        this.mesh.markPacketDisplayed(packet);
      } catch (e) {
        console.error('QR generation failed:', e);
      }
    }
  }

  private hasPendingPackets(): boolean {
    if (!this.mesh) return false;
    for (const peer of this.mesh.getPeers()) {
      const status = this.mesh.getDeliveryStatus(peer.id);
      if (status.pending.length > 0) return true;
    }
    return false;
  }

  private async startCamera() {
    if (!this.videoEl || this.scanner) return;

    try {
      this.hideCameraError();
      this.updateScanStatus('Starting camera...');

      this.scanner = new QRScanner({
        onScan: (result) => this.handleScan(result.data),
        onError: (error) => {
          console.error('Scanner error:', error);
          this.showCameraError(error.message);
        },
        scanInterval: 100,
      });

      await this.scanner.start(this.videoEl);
      this.updateScanStatus('Scanning...');
      if (this.startCameraBtn) {
        this.startCameraBtn.classList.add('hidden');
      }
    } catch (e) {
      const error = e as Error;
      this.showCameraError(error.message);
      this.updateScanStatus('Camera failed');
    }
  }

  private handleScan(data: string) {
    if (!this.mesh) return;

    const packet = decodePacket(data);
    if (!packet) return;

    // Process based on packet type
    if (packet.t === PACKET_TYPES.BEACON) {
      this.mesh.processBeacon(packet);
    } else {
      this.mesh.processPacket(packet);
    }

    this.updateScanStatus(`Scanned: ${packet.src.slice(0, 4)}...`);

    // Update QR after scan (may need to respond)
    this.updateQR();
  }

  private updateScanStatus(text: string) {
    if (this.scanStatus) {
      this.scanStatus.textContent = text;
    }
  }

  private showCameraError(message: string) {
    if (this.cameraError) {
      this.cameraError.textContent = message;
      this.cameraError.classList.remove('hidden');
    }
  }

  private hideCameraError() {
    if (this.cameraError) {
      this.cameraError.classList.add('hidden');
    }
  }

  private selectPeer(peerId: string) {
    this.selectedPeer = peerId;
    this.renderPeerList();
    this.renderChatSection();
    this.renderChatMessages();
  }

  private async sendMessage() {
    if (!this.selectedPeer || !this.chatInput || !this.mesh) return;
    const text = this.chatInput.value.trim();
    if (!text) return;

    await this.mesh.sendChat(this.selectedPeer, text);
    this.chatInput.value = '';
  }

  private saveDeviceName() {
    if (this.deviceNameInput) {
      this.deviceName = this.deviceNameInput.value;
      localStorage.setItem('qrtcp-device-name', this.deviceName);
    }
  }

  private getPeerState(peer: Peer): string {
    if (peer.sharedKey) return 'active';
    return 'discovered';
  }

  private getStateClass(peer: Peer): string {
    if (peer.sharedKey) return 'state-active';
    return 'state-discovered';
  }

  private renderPeerList() {
    if (!this.peerList || !this.mesh) return;

    const peers = this.mesh.getPeers();
    if (peers.length === 0) {
      this.peerList.innerHTML = '<p class="text-muted">No peers discovered yet. Point cameras at each other.</p>';
      return;
    }

    this.peerList.innerHTML = peers.map((peer) => {
      const status = this.mesh!.getDeliveryStatus(peer.id);
      const state = this.getPeerState(peer);

      return `
        <div class="peer-item ${this.selectedPeer === peer.id ? 'selected' : ''}" data-peer-id="${peer.id}">
          <div>
            <span class="peer-id">${peer.id}</span>
            ${peer.name ? `<span class="peer-name">"${peer.name}"</span>` : ''}
            <span class="${this.getStateClass(peer)}" style="margin-left: 0.5rem; font-size: 0.875rem;">
              ${state}
            </span>
            ${status.pending.length > 0 || status.acked.length > 0 ? `
              <span class="delivery-status">
                ${status.pending.length > 0 ? `<span class="delivery-dot pending" title="${status.pending.length} pending"></span>` : ''}
                ${status.acked.length > 0 ? `<span class="delivery-dot acked" title="${status.acked.length} delivered"></span>` : ''}
                ${status.failed.length > 0 ? `<span class="delivery-dot failed" title="${status.failed.length} failed"></span>` : ''}
              </span>
            ` : ''}
          </div>
          <div class="peer-actions">
            <button data-action="chat" data-peer="${peer.id}">Chat</button>
          </div>
        </div>
      `;
    }).join('');
  }

  private renderChatSection() {
    if (!this.chatSection) return;
    if (this.selectedPeer) {
      this.chatSection.classList.remove('hidden');
      const header = this.chatSection.querySelector('h2 code');
      if (header) header.textContent = this.selectedPeer;
    } else {
      this.chatSection.classList.add('hidden');
    }
  }

  private renderChatMessages() {
    if (!this.chatMessages || !this.mesh || !this.selectedPeer) return;

    const messages = this.mesh.getChatHistory(this.selectedPeer);
    const peer = this.mesh.getPeer(this.selectedPeer);

    if (messages.length === 0) {
      this.chatMessages.innerHTML = '<p class="text-muted text-center">No messages yet</p>';
      return;
    }

    this.chatMessages.innerHTML = messages.map((msg) => {
      // Get delivery status for sent messages
      let statusIcon = '';
      let bubbleClass: string = msg.direction;

      if (msg.direction === 'sent' && msg.pn !== undefined && peer) {
        const sent = peer.sentPackets.get(msg.pn);
        if (sent) {
          if (sent.status === 'pending') {
            statusIcon = '<span class="status-icon pending">...</span>';
            bubbleClass = 'pending';
          } else if (sent.status === 'acked') {
            statusIcon = '<span class="status-icon acked">OK</span>';
          } else if (sent.status === 'failed') {
            statusIcon = '<span class="status-icon failed">!</span>';
          }
        }
      }

      return `
        <div class="chat-message ${msg.direction}">
          <span class="chat-bubble ${bubbleClass}">
            ${this.escapeHtml(msg.text)}
            ${msg.encrypted ? '<span class="encrypted-badge">e</span>' : ''}
            ${statusIcon}
          </span>
        </div>
      `;
    }).join('');

    this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
  }

  private renderPacketLog() {
    if (!this.packetLog || !this.mesh) return;

    const log = this.mesh.getPacketLog();
    if (log.length === 0) {
      this.packetLog.innerHTML = '<p class="text-muted text-center">No packets yet</p>';
      return;
    }

    this.packetLog.innerHTML = log.slice(-30).reverse().map((entry) => {
      const time = new Date(entry.timestamp).toLocaleTimeString();
      const arrow = entry.direction === 'sent' ? '>' : '<';
      const arrowClass = entry.direction === 'sent' ? 'log-sent' : 'log-received';
      const target = entry.direction === 'sent'
        ? `to ${entry.packet.dst}`
        : `from ${entry.packet.src}`;
      const packetInfo = this.formatPacket(entry.packet);
      const statusClass = entry.status === 'acked' ? 'log-acked'
        : entry.status === 'failed' ? 'log-failed' : 'log-pending';

      return `
        <div class="log-entry">
          <span class="log-time">${time}</span>
          <span class="${arrowClass}">${arrow}</span>
          <span class="log-target">${target}</span>
          <span class="log-packet">${packetInfo}</span>
          ${entry.status ? `<span class="${statusClass}">[${entry.status}]</span>` : ''}
        </div>
      `;
    }).join('');
  }

  private formatPacket(packet: QRPacket): string {
    const parts: string[] = [packet.t];
    if (packet.mt) parts.push(packet.mt);
    const acksInfo = packet.acks && packet.acks.length > 0 ? ` acks=${packet.acks.map(([s,e]) => s===e ? s : `${s}-${e}`).join(',')}` : '';
    return `${parts.join(' ')} pn=${packet.pn}${acksInfo}`;
  }

  private escapeHtml(text: string): string {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  private render() {
    this.shadow.innerHTML = `
      <style>${styles}</style>
      <div class="container">
        <h1>QUIC over QR Code - Mesh Chat</h1>

        <!-- Device Info -->
        <div class="card">
          <div class="device-info">
            <div>
              <span class="text-muted">Your ID: </span>
              <code class="device-id" id="device-id">...</code>
            </div>
            <div>
              <input type="text" id="device-name" placeholder="Device name (optional)" />
            </div>
          </div>
        </div>

        <!-- QR + Camera Grid -->
        <div class="grid">
          <!-- QR Code Display -->
          <div class="card">
            <h2>Outgoing Packet</h2>
            <div class="qr-container">
              <canvas id="qr-canvas" width="280" height="280"></canvas>
            </div>
            <p class="text-xs text-muted text-center" style="margin-top: 0.5rem;">
              Point other device's camera at this QR code
            </p>
          </div>

          <!-- Camera Feed -->
          <div class="card">
            <h2>Camera Scanner</h2>
            <div class="video-container">
              <video id="video" playsinline muted></video>
              <div class="video-error hidden" id="camera-error"></div>
            </div>
            <div class="status-bar">
              <span class="text-muted" id="scan-status">Initializing...</span>
              <button id="start-camera">Start Camera</button>
            </div>
          </div>
        </div>

        <!-- Discovered Peers -->
        <div class="card">
          <h2>Discovered Peers</h2>
          <div id="peer-list">
            <p class="text-muted">No peers discovered yet. Point cameras at each other.</p>
          </div>
        </div>

        <!-- Chat Section -->
        <div class="card hidden" id="chat-section">
          <h2>Chat with <code style="color: #60a5fa;"></code></h2>
          <div class="chat-container" id="chat-messages">
            <p class="text-muted text-center">No messages yet</p>
          </div>
          <div class="chat-input">
            <input type="text" id="chat-input" placeholder="Type a message..." />
            <button id="send-btn">Send</button>
          </div>
        </div>

        <!-- Packet Log -->
        <div class="card">
          <h2>Packet Log</h2>
          <div class="log-container" id="packet-log">
            <p class="text-muted text-center">No packets yet</p>
          </div>
        </div>

        <!-- Protocol Info -->
        <div class="card">
          <h2>How it works</h2>
          <ul class="info-list">
            <li>QUIC-inspired protocol: no handshake, 0-RTT encrypted messaging</li>
            <li>SACK acknowledgments: efficient delivery tracking with ranges</li>
            <li>Parallel transmission: multiple packets can be in flight</li>
            <li>Each device generates an ECDH keypair for encryption</li>
            <li>Messages are encrypted with AES-GCM once keys are exchanged</li>
          </ul>
        </div>
      </div>
    `;

    // Cache DOM references
    this.qrCanvas = this.shadow.getElementById('qr-canvas') as HTMLCanvasElement;
    this.videoEl = this.shadow.getElementById('video') as HTMLVideoElement;
    this.peerList = this.shadow.getElementById('peer-list');
    this.packetLog = this.shadow.getElementById('packet-log');
    this.chatSection = this.shadow.getElementById('chat-section');
    this.chatMessages = this.shadow.getElementById('chat-messages');
    this.chatInput = this.shadow.getElementById('chat-input') as HTMLInputElement;
    this.scanStatus = this.shadow.getElementById('scan-status');
    this.cameraError = this.shadow.getElementById('camera-error');
    this.startCameraBtn = this.shadow.getElementById('start-camera') as HTMLButtonElement;
    this.deviceIdEl = this.shadow.getElementById('device-id');
    this.deviceNameInput = this.shadow.getElementById('device-name') as HTMLInputElement;

    // Event listeners
    this.startCameraBtn?.addEventListener('click', () => this.startCamera());

    this.deviceNameInput?.addEventListener('blur', () => this.saveDeviceName());

    this.shadow.getElementById('send-btn')?.addEventListener('click', () => this.sendMessage());

    this.chatInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.sendMessage();
    });

    // Delegate peer list clicks
    this.peerList?.addEventListener('click', (e) => {
      const target = e.target as HTMLElement;
      const action = target.dataset.action;
      const peerId = target.dataset.peer;

      if (action === 'chat' && peerId) {
        this.selectPeer(peerId);
      }
    });
  }
}

// Register the custom element
export function registerQRTCPElement(tagName: string = 'qrtcp-demo') {
  if (!customElements.get(tagName)) {
    customElements.define(tagName, QRTCPDemoElement);
  }
}

// Auto-register with default tag name
if (typeof window !== 'undefined') {
  registerQRTCPElement();
}
