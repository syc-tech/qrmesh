# QR Mesh - Future Work

## Unified Transport Component

Create a single vanilla JS web component that abstracts the transport layer and supports multiple mechanisms for peer-to-peer communication.

### Transport Mechanisms

1. **QR Code** (current)
   - Visual scanning via camera
   - Chunked packets for reliable transfer

2. **Audio**
   - Encode packets as audio tones/signals
   - Use Web Audio API for generation and detection
   - Could use frequency-shift keying (FSK) or similar modulation
   - Works when devices are nearby but can't see each other

3. **Copy-Paste**
   - Manual fallback when camera/audio unavailable
   - Display encoded packet as text for user to copy
   - Input field to paste received packets
   - Good for debugging and accessibility

### WebRTC Upgrade Path

- Once peers discover each other via any transport, offer to upgrade to WebRTC
- Use initial transport to exchange WebRTC signaling (SDP offer/answer, ICE candidates)
- Fall back to original transport if WebRTC fails
- Seamless transition - messages continue flowing

### Component API

```js
// Single unified component
<mesh-transport
  mode="qr|audio|clipboard|auto"
  enable-webrtc-upgrade="true"
></mesh-transport>

// Events emitted
mesh.addEventListener('peer-discovered', (e) => { e.detail.peerId });
mesh.addEventListener('message', (e) => { e.detail.from, e.detail.text });
mesh.addEventListener('transport-changed', (e) => { e.detail.from, e.detail.to });
mesh.addEventListener('connected', (e) => { e.detail.peerId, e.detail.transport });

// Methods
mesh.send(peerId, message);
mesh.broadcast(message);
mesh.setTransport('audio');
mesh.upgradeToWebRTC(peerId);
```

### Architecture

- Core protocol layer (current mesh.ts/protocol.ts) stays the same
- Transport layer becomes pluggable
- Each transport implements: `send(packet)`, `onReceive(callback)`, `start()`, `stop()`
- Component manages transport switching and WebRTC negotiation
