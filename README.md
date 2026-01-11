# QR Mesh

A TCP-like protocol for peer-to-peer communication over QR codes. Enables mesh discovery, encrypted messaging, and connection upgrades between devices using only camera and display.

## Features

- **TCP-like Protocol**: SYN/ACK handshake, sequence numbers, retransmission
- **End-to-End Encryption**: ECDH key exchange + AES-GCM encryption
- **Mesh Discovery**: Automatic peer discovery via broadcast announcements
- **Connection Upgrade**: Exchange WebSocket/WebRTC details to switch to faster transport
- **Framework Agnostic**: Works with React, Vue, Angular, Svelte, or plain HTML
- **Web Component**: Drop-in `<qrtcp-demo>` element for quick demos

## Installation

```bash
npm install @syc-tech/qrmesh jsqr qrcode
```

## Usage

### Web Component (easiest)

```html
<script type="module">
  import '@syc-tech/qrmesh';
</script>

<qrtcp-demo></qrtcp-demo>
```

### Programmatic API

```typescript
import {
  getOrCreateKeyPair,
  createLocalStorageAdapter,
  MeshState,
  QRScanner,
  encodePacket,
  decodePacket,
} from '@syc-tech/qrmesh';

// Create identity (persisted to localStorage)
const storage = createLocalStorageAdapter();
const keyPair = await getOrCreateKeyPair(storage);

// Create mesh state manager
const mesh = new MeshState(keyPair, { deviceName: 'My Device' });

// Subscribe to events
mesh.subscribe((event) => {
  switch (event.type) {
    case 'peer_discovered':
      console.log('Found peer:', event.peer.id);
      break;
    case 'peer_connected':
      console.log('Connected to:', event.peer.id);
      break;
    case 'chat_message':
      console.log('Message:', event.message.text);
      break;
  }
});

// Get packet to display as QR code
const packet = mesh.getNextOutgoingPacket();
const qrData = encodePacket(packet);
// Render qrData to QR code using your preferred library

// Process scanned QR data
const received = decodePacket(scannedData);
if (received) {
  if (received.dst === '*') {
    mesh.processAnnounce(received);
  } else {
    mesh.processPacket(received);
  }
}

// Connect to discovered peer
mesh.connect(peerId);

// Send encrypted message
await mesh.sendChat(peerId, 'Hello!');
```

### QR Scanner

```typescript
import { QRScanner } from '@syc-tech/qrmesh';

const scanner = new QRScanner({
  onScan: (result) => {
    console.log('Scanned:', result.data);
  },
  onError: (error) => {
    console.error('Scanner error:', error);
  },
});

// Start scanning (requires video element)
await scanner.start(videoElement);

// Stop scanning
scanner.stop();
```

## Protocol Overview

```
┌─────────────────────────────┐
│  Application Layer          │  ANNOUNCE, OFFER, CHAT, ROUTE
├─────────────────────────────┤
│  Transport Layer            │  Reliability (seq/ack), connection state
├─────────────────────────────┤
│  Link Layer                 │  Addressing, framing, CRC
├─────────────────────────────┤
│  Physical Layer             │  QR code display + camera scan
└─────────────────────────────┘
```

### Connection Flow

```
Device A                    Device B
   │                           │
   │◄──── ANNOUNCE ────────────│  (B broadcasts presence)
   │                           │
   │────── SYN ───────────────►│  (A initiates connection)
   │                           │
   │◄───── SYN+ACK ───────────│  (B acknowledges + sends key)
   │                           │
   │────── ACK ───────────────►│  (Connection established)
   │                           │
   │◄────► Encrypted DATA ◄───►│  (Chat messages)
```

## API Reference

### Crypto

- `getOrCreateKeyPair(storage?)` - Generate or load ECDH keypair
- `deriveSharedKey(privateKey, peerPublicKey)` - Derive shared AES key
- `encrypt(key, plaintext)` - AES-GCM encrypt
- `decrypt(key, ciphertext, iv)` - AES-GCM decrypt

### Protocol

- `encodePacket(packet)` - Serialize packet to JSON
- `decodePacket(data)` - Parse and verify packet CRC
- `createSynPacket()`, `createAckPacket()`, etc. - Packet factories

### Mesh

- `MeshState` - Connection state machine and peer management
- `ConnectionState` - Enum: DISCONNECTED, SYN_SENT, ESTABLISHED, etc.

### Scanner

- `QRScanner` - Camera-based QR code scanner using jsQR

### Component

- `QRTCPDemoElement` - Web Component for demo UI
- `registerQRTCPElement(tagName?)` - Register custom element

## License

MIT
