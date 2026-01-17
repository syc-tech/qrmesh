/**
 * QR Mesh Chat Demo
 *
 * A focused chat demo that shows message queueing and transfer via QR codes.
 * Uses QUIC-inspired protocol for 0-RTT messaging.
 */

import QRCode from 'qrcode';
import { getOrCreateKeyPair, type KeyPair, type KeyStorage } from '../crypto';
import { encodePacket, decodePacket, PACKET_TYPES } from '../protocol';
import { QRScanner, getScannerMode } from '../scanner';
import { MeshState, type MeshEvent } from '../mesh';

const styles = `
  :host {
    display: block;
    font-family: system-ui, -apple-system, sans-serif;
    color: #e2e8f0;
    background: #0f172a;
    min-height: 100vh;
  }

  * {
    box-sizing: border-box;
  }

  .container {
    max-width: 800px;
    margin: 0 auto;
    padding: 1rem;
  }

  h1 {
    font-size: 1.5rem;
    font-weight: bold;
    margin-bottom: 0.5rem;
    color: #f8fafc;
  }

  .subtitle {
    color: #94a3b8;
    margin-bottom: 1.5rem;
  }

  .panels {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    margin-bottom: 1rem;
  }

  @media (max-width: 640px) {
    .panels {
      grid-template-columns: 1fr;
    }
  }

  .panel {
    background: #1e293b;
    border-radius: 0.75rem;
    padding: 1rem;
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 0.75rem;
  }

  .panel-title {
    font-weight: 600;
    font-size: 0.875rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .qr-area {
    background: white;
    border-radius: 0.5rem;
    padding: 0.5rem;
    display: flex;
    justify-content: center;
    align-items: center;
    min-height: 420px;
  }

  .qr-area canvas {
    max-width: 400px;
    max-height: 400px;
  }

  .camera-area {
    background: #000;
    border-radius: 0.5rem;
    overflow: hidden;
    min-height: 300px;
    position: relative;
  }

  .camera-area video {
    width: 100%;
    height: 300px;
    object-fit: contain;
  }

  .camera-overlay {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    background: rgba(0,0,0,0.7);
    color: #94a3b8;
    text-align: center;
    padding: 1rem;
  }

  .camera-overlay.error {
    color: #f87171;
  }

  .camera-overlay.hidden {
    display: none;
  }

  button {
    background: #3b82f6;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 0.375rem;
    cursor: pointer;
    font-size: 0.875rem;
    font-weight: 500;
    transition: background 0.15s;
  }

  button:hover {
    background: #2563eb;
  }

  button:disabled {
    background: #475569;
    cursor: not-allowed;
  }

  button.secondary {
    background: #475569;
  }

  button.secondary:hover {
    background: #64748b;
  }

  button.success {
    background: #10b981;
  }

  button.success:hover {
    background: #059669;
  }

  .status-bar {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.75rem;
    font-size: 0.75rem;
    color: #64748b;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #64748b;
  }

  .status-dot.active {
    background: #10b981;
    animation: pulse 2s infinite;
  }

  .status-dot.connecting {
    background: #f59e0b;
    animation: pulse 1s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .status-dot.flash {
    background: #22c55e !important;
    transform: scale(1.5);
    transition: transform 0.1s;
  }

  .device-info {
    background: #1e293b;
    border-radius: 0.75rem;
    padding: 1rem;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 1rem;
    flex-wrap: wrap;
  }

  .device-id {
    font-family: monospace;
    color: #10b981;
    background: #0f172a;
    padding: 0.25rem 0.5rem;
    border-radius: 0.25rem;
  }

  .peer-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    background: #0f172a;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    font-size: 0.875rem;
  }

  .peer-badge .dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }

  .peer-badge .dot.active {
    background: #10b981;
  }

  .peer-badge .dot.discovered {
    background: #f59e0b;
  }

  .peer-badge .dot.inactive {
    background: #64748b;
  }

  .chat-section {
    background: #1e293b;
    border-radius: 0.75rem;
    overflow: hidden;
  }

  .chat-header {
    padding: 1rem;
    border-bottom: 1px solid #334155;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .chat-header h2 {
    font-size: 1rem;
    font-weight: 600;
  }

  .message-queue-badge {
    background: #3b82f6;
    color: white;
    font-size: 0.75rem;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
  }

  .delivery-badge {
    font-size: 0.75rem;
    padding: 0.125rem 0.5rem;
    border-radius: 9999px;
  }

  .delivery-badge.pending {
    background: #f59e0b;
    color: black;
  }

  .delivery-badge.acked {
    background: #10b981;
    color: white;
  }

  .chat-messages {
    height: 300px;
    overflow-y: auto;
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .chat-empty {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #64748b;
    text-align: center;
  }

  .message {
    max-width: 80%;
    animation: slideIn 0.2s ease-out;
  }

  @keyframes slideIn {
    from {
      opacity: 0;
      transform: translateY(10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  .message.sent {
    align-self: flex-end;
  }

  .message.received {
    align-self: flex-start;
  }

  .message.queued {
    opacity: 0.7;
  }

  .message-bubble {
    padding: 0.5rem 0.75rem;
    border-radius: 1rem;
    font-size: 0.9rem;
    line-height: 1.4;
  }

  .message.sent .message-bubble {
    background: #3b82f6;
    border-bottom-right-radius: 0.25rem;
  }

  .message.received .message-bubble {
    background: #334155;
    border-bottom-left-radius: 0.25rem;
  }

  .message.queued .message-bubble {
    background: #1e3a5f;
    border: 1px dashed #3b82f6;
  }

  .message-meta {
    font-size: 0.7rem;
    color: #64748b;
    margin-top: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.25rem;
  }

  .message.sent .message-meta {
    justify-content: flex-end;
  }

  .message-status {
    font-size: 0.75rem;
  }

  .message-status.queued { color: #f59e0b; }
  .message-status.pending { color: #f59e0b; }
  .message-status.acked { color: #10b981; }
  .message-status.failed { color: #ef4444; }

  .chat-input-area {
    padding: 1rem;
    border-top: 1px solid #334155;
    display: flex;
    gap: 0.5rem;
  }

  .chat-input-area input {
    flex: 1;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 0.5rem;
    padding: 0.625rem 0.875rem;
    color: #e2e8f0;
    font-size: 0.9rem;
  }

  .chat-input-area input:focus {
    outline: none;
    border-color: #3b82f6;
  }

  .chat-input-area input::placeholder {
    color: #64748b;
  }

  .instructions {
    background: #1e293b;
    border-radius: 0.75rem;
    padding: 1rem;
    margin-top: 1rem;
  }

  .instructions h3 {
    font-size: 0.875rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
  }

  .instructions ol {
    color: #94a3b8;
    font-size: 0.875rem;
    padding-left: 1.25rem;
    margin: 0;
  }

  .instructions li {
    margin-bottom: 0.25rem;
  }

  .hidden {
    display: none !important;
  }
`;

interface QueuedMessage {
  id: string;
  text: string;
  timestamp: number;
  pn?: number;  // Packet number once sent
  status: 'queued' | 'pending' | 'acked' | 'failed';
}

export class QRMeshChatElement extends HTMLElement {
  private shadow: ShadowRoot;
  private keyPair: KeyPair | null = null;
  private mesh: MeshState | null = null;
  private scanner: QRScanner | null = null;
  private activePeerId: string | null = null;
  private messageQueue: QueuedMessage[] = [];
  private sentMessages: Array<{ text: string; timestamp: number; pn?: number }> = [];
  private receivedMessages: Array<{ text: string; timestamp: number }> = [];
  private lastDisplayedPacket: string | null = null;
  private scanFlashTimeout: ReturnType<typeof setTimeout> | null = null;

  // DOM refs
  private qrCanvas: HTMLCanvasElement | null = null;
  private videoEl: HTMLVideoElement | null = null;
  private cameraOverlay: HTMLElement | null = null;
  private deviceIdEl: HTMLElement | null = null;
  private peerBadge: HTMLElement | null = null;
  private chatMessages: HTMLElement | null = null;
  private chatInput: HTMLInputElement | null = null;
  private queueBadge: HTMLElement | null = null;
  private deliveryBadge: HTMLElement | null = null;
  private statusDot: HTMLElement | null = null;
  private statusText: HTMLElement | null = null;

  constructor() {
    super();
    this.shadow = this.attachShadow({ mode: 'open' });
  }

  connectedCallback() {
    this.render();
    this.init();
  }

  disconnectedCallback() {
    if (this.scanFlashTimeout) clearTimeout(this.scanFlashTimeout);
    this.scanner?.stop();
  }

  private async init() {
    try {
      const storage: KeyStorage = {
        get: (key) => localStorage.getItem(key),
        set: (key, value) => localStorage.setItem(key, value),
        remove: (key) => localStorage.removeItem(key),
      };

      this.keyPair = await getOrCreateKeyPair(storage);
      if (this.deviceIdEl) {
        this.deviceIdEl.textContent = this.keyPair.deviceId;
      }

      this.mesh = new MeshState(this.keyPair, { deviceName: 'Chat Demo' });
      this.mesh.subscribe((event) => this.handleMeshEvent(event));

      // Show initial beacon QR (static - only changes on scan)
      this.updateQR();

      this.updateStatus('Beacon ready', 'idle');
    } catch (e) {
      console.error('Init failed:', e);
      this.updateStatus('Init failed', 'error');
    }
  }

  private handleMeshEvent(event: MeshEvent) {
    switch (event.type) {
      case 'peer_discovered':
        this.updatePeerBadge(event.peer.id, 'discovered');
        this.updateStatus('Peer found!', 'connected');
        break;
      case 'peer_updated':
        this.updatePeerBadge(event.peer.id, 'discovered');
        break;
      case 'packet_acked':
        // Update message status
        const ackedMsg = this.messageQueue.find(m => m.pn === event.pn);
        if (ackedMsg) {
          ackedMsg.status = 'acked';
          this.sentMessages.push({
            text: ackedMsg.text,
            timestamp: ackedMsg.timestamp,
            pn: ackedMsg.pn,
          });
          this.messageQueue = this.messageQueue.filter(m => m.id !== ackedMsg.id);
          this.updateQueueBadge();
          this.renderMessages();
          // Update QR to show next pending message (or beacon if done)
          this.updateQR();
        }
        this.updateDeliveryStatus();
        break;
      case 'packet_failed':
        const failedMsg = this.messageQueue.find(m => m.pn === event.pn);
        if (failedMsg) {
          failedMsg.status = 'failed';
          this.renderMessages();
        }
        break;
      case 'chat_message':
        if (event.message.direction === 'received') {
          this.receivedMessages.push({
            text: event.message.text,
            timestamp: event.message.timestamp,
          });
          this.renderMessages();
          // Update QR to show ACK packet
          this.updateQR();
        }
        break;
    }
  }

  private async processMessageQueue() {
    if (!this.mesh || !this.activePeerId) return;

    const peer = this.mesh.getPeer(this.activePeerId);
    if (!peer) return;

    for (const msg of this.messageQueue) {
      if (msg.status === 'queued') {
        msg.status = 'pending';
        const pn = await this.mesh.sendChat(this.activePeerId, msg.text);
        msg.pn = pn;
        this.renderMessages();
      }
    }

    // Update QR to show outgoing message
    this.updateQR();
  }

  private async updateQR() {
    if (!this.mesh || !this.qrCanvas) return;

    const packet = this.mesh.getNextOutgoingPacket();
    if (packet) {
      const encoded = encodePacket(packet);

      // Only redraw if packet changed
      if (encoded === this.lastDisplayedPacket) return;
      this.lastDisplayedPacket = encoded;

      try {
        await QRCode.toCanvas(this.qrCanvas, encoded, {
          width: 500,
          margin: 4,
          errorCorrectionLevel: 'M',
          color: { dark: '#000', light: '#fff' },
        });
        this.mesh.markPacketDisplayed(packet);
      } catch (e) {
        console.error('QR error:', e);
      }
    }
  }

  private async startCamera() {
    if (!this.videoEl || this.scanner) return;

    try {
      this.updateCameraOverlay('Starting camera...', false);

      this.scanner = new QRScanner({
        onScan: (result) => this.handleScan(result.data),
        onError: (error) => {
          this.updateCameraOverlay(error.message, true);
        },
        scanInterval: 100,
      });

      await this.scanner.start(this.videoEl);
      this.hideCameraOverlay();
      this.updateStatus('Scanning', 'scanning');

      // Update scan debug display every 500ms
      this.startScanDebugUpdates();
    } catch (e) {
      this.updateCameraOverlay((e as Error).message, true);
    }
  }

  private scanDebugInterval: ReturnType<typeof setInterval> | null = null;

  private startScanDebugUpdates() {
    if (this.scanDebugInterval) return;

    const scanCountEl = this.shadow.getElementById('scan-count');
    const scanResultEl = this.shadow.getElementById('scan-result');
    const scanModeEl = this.shadow.getElementById('scan-mode');

    // Set scanner mode once
    if (scanModeEl) scanModeEl.textContent = getScannerMode();

    this.scanDebugInterval = setInterval(() => {
      if (this.scanner) {
        if (scanCountEl) scanCountEl.textContent = String(this.scanner.scanCount);
        if (scanResultEl) scanResultEl.textContent = this.scanner.lastScanResult;
      }
    }, 500);
  }

  private handleScan(data: string) {
    if (!this.mesh) return;

    const packet = decodePacket(data);
    if (!packet) return;

    // Flash the status to indicate scan
    this.flashScanIndicator();

    if (packet.t === PACKET_TYPES.BEACON) {
      this.mesh.processBeacon(packet);
      // Auto-select peer when discovered
      const peers = this.mesh.getPeers();
      if (peers.length > 0 && !this.activePeerId) {
        this.activePeerId = peers[0].id;
        this.updatePeerBadge(peers[0].id, peers[0].sharedKey ? 'active' : 'discovered');
      }
    } else {
      this.mesh.processPacket(packet);
    }
  }

  private flashScanIndicator() {
    if (this.statusDot) {
      this.statusDot.classList.add('flash');
      if (this.scanFlashTimeout) clearTimeout(this.scanFlashTimeout);
      this.scanFlashTimeout = setTimeout(() => {
        this.statusDot?.classList.remove('flash');
      }, 300);
    }
    this.updateStatus('Scanned!', 'scanning');
  }


  private queueMessage(text: string) {
    const msg: QueuedMessage = {
      id: Math.random().toString(36).slice(2),
      text,
      timestamp: Date.now(),
      status: 'queued',
    };
    this.messageQueue.push(msg);
    this.updateQueueBadge();
    this.renderMessages();

    // If we have an active peer, start sending immediately
    if (this.activePeerId) {
      this.processMessageQueue();
    }
  }

  private updateStatus(text: string, state: 'idle' | 'scanning' | 'connecting' | 'connected' | 'error') {
    if (this.statusText) this.statusText.textContent = text;
    if (this.statusDot) {
      this.statusDot.className = 'status-dot';
      if (state === 'connected' || state === 'scanning') {
        this.statusDot.classList.add('active');
      } else if (state === 'connecting') {
        this.statusDot.classList.add('connecting');
      }
    }
  }

  private updatePeerBadge(peerId: string | null, state: 'discovered' | 'active' | 'inactive') {
    if (!this.peerBadge) return;

    if (!peerId) {
      this.peerBadge.classList.add('hidden');
      return;
    }

    this.peerBadge.classList.remove('hidden');
    const dot = this.peerBadge.querySelector('.dot');
    const idSpan = this.peerBadge.querySelector('.peer-id');

    if (dot) {
      dot.className = 'dot ' + state;
    }
    if (idSpan) {
      idSpan.textContent = peerId;
    }
  }

  private updateQueueBadge() {
    if (!this.queueBadge) return;
    const count = this.messageQueue.filter(m => m.status === 'queued' || m.status === 'pending').length;
    if (count > 0) {
      this.queueBadge.textContent = `${count} pending`;
      this.queueBadge.classList.remove('hidden');
    } else {
      this.queueBadge.classList.add('hidden');
    }
  }

  private updateDeliveryStatus() {
    if (!this.deliveryBadge || !this.mesh || !this.activePeerId) return;

    const status = this.mesh.getDeliveryStatus(this.activePeerId);
    if (status.pending.length > 0) {
      this.deliveryBadge.textContent = `${status.pending.length} in flight`;
      this.deliveryBadge.className = 'delivery-badge pending';
      this.deliveryBadge.classList.remove('hidden');
    } else if (status.acked.length > 0) {
      this.deliveryBadge.textContent = `${status.acked.length} delivered`;
      this.deliveryBadge.className = 'delivery-badge acked';
      this.deliveryBadge.classList.remove('hidden');
    } else {
      this.deliveryBadge.classList.add('hidden');
    }
  }

  private updateCameraOverlay(text: string, isError: boolean) {
    if (!this.cameraOverlay) return;
    this.cameraOverlay.innerHTML = `<p>${text}</p>${!isError ? '' : '<button class="secondary" style="margin-top:0.5rem">Retry</button>'}`;
    this.cameraOverlay.className = 'camera-overlay' + (isError ? ' error' : '');

    const btn = this.cameraOverlay.querySelector('button');
    btn?.addEventListener('click', () => this.startCamera());
  }

  private hideCameraOverlay() {
    if (this.cameraOverlay) {
      this.cameraOverlay.classList.add('hidden');
    }
  }

  private renderMessages() {
    if (!this.chatMessages) return;

    // Get delivery status for sent messages
    const peerStatus = this.mesh && this.activePeerId
      ? this.mesh.getDeliveryStatus(this.activePeerId)
      : { pending: [], acked: [], failed: [] };

    // Combine all messages and sort by timestamp
    const allMessages: Array<{
      text: string;
      timestamp: number;
      type: 'sent' | 'received' | 'queued';
      status?: string;
      pn?: number;
    }> = [
      ...this.sentMessages.map(m => ({
        ...m,
        type: 'sent' as const,
        status: m.pn && peerStatus.acked.includes(m.pn) ? 'acked' : 'sent',
      })),
      ...this.receivedMessages.map(m => ({ ...m, type: 'received' as const })),
      ...this.messageQueue.map(m => ({
        text: m.text,
        timestamp: m.timestamp,
        type: 'queued' as const,
        status: m.status,
        pn: m.pn,
      })),
    ].sort((a, b) => a.timestamp - b.timestamp);

    if (allMessages.length === 0) {
      this.chatMessages.innerHTML = `
        <div class="chat-empty">
          <div>
            <p>No messages yet</p>
            <p style="font-size: 0.75rem; margin-top: 0.25rem;">Type a message below - it sends immediately (0-RTT)</p>
          </div>
        </div>
      `;
      return;
    }

    this.chatMessages.innerHTML = allMessages.map(msg => {
      const time = new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      let statusIcon = '';

      if (msg.type === 'queued') {
        if (msg.status === 'queued') statusIcon = '...';
        else if (msg.status === 'pending') statusIcon = '...';
        else if (msg.status === 'acked') statusIcon = 'OK';
        else if (msg.status === 'failed') statusIcon = '!';
      } else if (msg.type === 'sent') {
        statusIcon = 'OK';
      }

      const msgClass = msg.type === 'queued' ? (msg.status === 'pending' ? 'sent' : 'queued') : msg.type;

      return `
        <div class="message ${msgClass}">
          <div class="message-bubble">${this.escapeHtml(msg.text)}</div>
          <div class="message-meta">
            <span>${time}</span>
            ${statusIcon ? `<span class="message-status ${msg.status || msg.type}">${statusIcon}</span>` : ''}
          </div>
        </div>
      `;
    }).join('');

    this.chatMessages.scrollTop = this.chatMessages.scrollHeight;
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
        <h1>QR Mesh Chat</h1>
        <p class="subtitle">QUIC-style 0-RTT messaging over QR codes</p>

        <div class="device-info">
          <span style="color: #64748b;">Your ID:</span>
          <span class="device-id" id="device-id">...</span>
          <div class="peer-badge hidden" id="peer-badge">
            <span class="dot inactive"></span>
            <span class="peer-id"></span>
          </div>
        </div>

        <div class="manual-connect" style="margin: 0.5rem 0; display: flex; gap: 0.5rem; align-items: center;">
          <input type="text" id="peer-id-input" placeholder="Enter peer ID (8 chars)"
                 style="flex:1; padding:0.4rem; border-radius:0.25rem; border:1px solid #334155; background:#1e293b; color:#e2e8f0; font-family:monospace; text-transform:uppercase;"
                 maxlength="8" />
          <button id="manual-connect-btn" class="secondary" style="padding:0.4rem 0.75rem;">Connect</button>
        </div>

        <div class="panels">
          <div class="panel">
            <div class="panel-header">
              <span class="panel-title">Your QR Code</span>
            </div>
            <div class="qr-area">
              <canvas id="qr-canvas" width="280" height="280"></canvas>
            </div>
            <div class="status-bar">
              <span class="status-dot" id="status-dot"></span>
              <span id="status-text">Initializing...</span>
            </div>
          </div>

          <div class="panel">
            <div class="panel-header">
              <span class="panel-title">Scan Partner's QR</span>
              <button id="start-camera">Start Camera</button>
            </div>
            <div class="camera-area">
              <video id="video" playsinline muted></video>
              <div class="camera-overlay" id="camera-overlay">
                <p>Click "Start Camera" to begin scanning</p>
              </div>
            </div>
            <div class="scan-debug" id="scan-debug" style="font-size: 0.7rem; color: #64748b; padding: 0.25rem 0.5rem; background: #1e293b; border-radius: 0 0 0.5rem 0.5rem;">
              Scans: <span id="scan-count">0</span> |
              Last: <span id="scan-result">waiting...</span> |
              Mode: <span id="scan-mode">?</span>
            </div>
          </div>
        </div>

        <div class="chat-section">
          <div class="chat-header">
            <h2>Messages</h2>
            <div style="display: flex; gap: 0.5rem;">
              <span class="delivery-badge hidden" id="delivery-badge"></span>
              <span class="message-queue-badge hidden" id="queue-badge">0 pending</span>
            </div>
          </div>
          <div class="chat-messages" id="chat-messages">
            <div class="chat-empty">
              <div>
                <p>No messages yet</p>
                <p style="font-size: 0.75rem; margin-top: 0.25rem;">Type a message below - it sends immediately (0-RTT)</p>
              </div>
            </div>
          </div>
          <div class="chat-input-area">
            <input type="text" id="chat-input" placeholder="Type a message..." />
            <button id="send-btn">Send</button>
          </div>
        </div>

        <div class="instructions">
          <h3>How it works:</h3>
          <ol>
            <li>Open this page on two devices</li>
            <li>Click "Start Camera" on both devices</li>
            <li>Point cameras at each other's QR codes</li>
            <li>Start chatting - messages send immediately with 0-RTT!</li>
            <li>Watch the delivery status update as packets are acknowledged</li>
          </ol>
        </div>
      </div>
    `;

    // Cache refs
    this.qrCanvas = this.shadow.getElementById('qr-canvas') as HTMLCanvasElement;
    this.videoEl = this.shadow.getElementById('video') as HTMLVideoElement;
    this.cameraOverlay = this.shadow.getElementById('camera-overlay');
    this.deviceIdEl = this.shadow.getElementById('device-id');
    this.peerBadge = this.shadow.getElementById('peer-badge');
    this.chatMessages = this.shadow.getElementById('chat-messages');
    this.chatInput = this.shadow.getElementById('chat-input') as HTMLInputElement;
    this.queueBadge = this.shadow.getElementById('queue-badge');
    this.deliveryBadge = this.shadow.getElementById('delivery-badge');
    this.statusDot = this.shadow.getElementById('status-dot');
    this.statusText = this.shadow.getElementById('status-text');

    // Event listeners
    this.shadow.getElementById('start-camera')?.addEventListener('click', () => {
      this.startCamera();
      (this.shadow.getElementById('start-camera') as HTMLButtonElement).disabled = true;
    });

    this.shadow.getElementById('send-btn')?.addEventListener('click', () => {
      const text = this.chatInput?.value.trim();
      if (text) {
        this.queueMessage(text);
        if (this.chatInput) this.chatInput.value = '';
      }
    });

    this.chatInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const text = this.chatInput?.value.trim();
        if (text) {
          this.queueMessage(text);
          if (this.chatInput) this.chatInput.value = '';
        }
      }
    });

    // Manual connect
    const peerIdInput = this.shadow.getElementById('peer-id-input') as HTMLInputElement;
    this.shadow.getElementById('manual-connect-btn')?.addEventListener('click', () => {
      const peerId = peerIdInput?.value.trim().toUpperCase();
      if (peerId && peerId.length === 8 && /^[0-9A-F]+$/.test(peerId)) {
        this.manualConnect(peerId);
        peerIdInput.value = '';
      } else {
        this.updateStatus('Invalid ID (need 8 hex chars)', 'error');
      }
    });

    peerIdInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const peerId = peerIdInput.value.trim().toUpperCase();
        if (peerId && peerId.length === 8 && /^[0-9A-F]+$/.test(peerId)) {
          this.manualConnect(peerId);
          peerIdInput.value = '';
        }
      }
    });
  }

  private manualConnect(peerId: string) {
    if (!this.mesh) return;
    // Create a fake beacon packet to discover the peer
    const fakeBeacon = { t: 'B' as const, src: peerId, dst: '*', pn: 0, v: 3 };
    this.mesh.processBeacon(fakeBeacon as any);
    this.activePeerId = peerId;
    this.updatePeerBadge(peerId, 'discovered');
    this.updateStatus('Connected to ' + peerId, 'connected');
  }
}

export function registerQRMeshChatElement(tagName: string = 'qrmesh-chat') {
  if (!customElements.get(tagName)) {
    customElements.define(tagName, QRMeshChatElement);
  }
}

if (typeof window !== 'undefined') {
  registerQRMeshChatElement();
}
