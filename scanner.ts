/**
 * QR Scanner - Physical layer for QR code scanning
 *
 * This module handles camera access and QR code decoding using jsQR.
 * It's browser-specific but framework-agnostic.
 */

import jsQR from 'jsqr';

export interface ScanResult {
  data: string;
  timestamp: number;
}

export interface QRScannerOptions {
  onScan: (result: ScanResult) => void;
  onError?: (error: Error) => void;
  scanInterval?: number; // ms between scans
  debounceMs?: number; // don't report same QR within this time
}

export interface VideoConstraints {
  facingMode?: 'user' | 'environment';
  width?: { ideal: number };
  height?: { ideal: number };
}

/**
 * QR Scanner class - handles camera access and QR decoding
 */
export class QRScanner {
  private video: HTMLVideoElement | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private ctx: CanvasRenderingContext2D | null = null;
  private stream: MediaStream | null = null;
  private scanInterval: number;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private onScan: (result: ScanResult) => void;
  private onError?: (error: Error) => void;
  private lastScannedData: string | null = null;
  private lastScanTime: number = 0;
  private debounceMs: number;
  private running: boolean = false;

  constructor(options: QRScannerOptions) {
    this.onScan = options.onScan;
    this.onError = options.onError;
    this.scanInterval = options.scanInterval ?? 100;
    this.debounceMs = options.debounceMs ?? 500;
  }

  /**
   * Start scanning using a video element
   */
  async start(
    videoElement: HTMLVideoElement,
    constraints?: VideoConstraints
  ): Promise<void> {
    if (this.running) {
      throw new Error('Scanner is already running');
    }

    this.video = videoElement;
    this.canvas = document.createElement('canvas');
    this.ctx = this.canvas.getContext('2d', { willReadFrequently: true });

    const videoConstraints = {
      facingMode: constraints?.facingMode ?? 'user',
      width: constraints?.width ?? { ideal: 1280 },
      height: constraints?.height ?? { ideal: 720 },
    };

    try {
      this.stream = await navigator.mediaDevices.getUserMedia({
        video: videoConstraints,
      });

      this.video.srcObject = this.stream;
      await this.video.play();

      // Set canvas size to match video
      this.canvas.width = this.video.videoWidth || 640;
      this.canvas.height = this.video.videoHeight || 480;

      // Start scanning loop
      this.running = true;
      console.log('[SCANNER] v2 Started, video size:', this.video.videoWidth, 'x', this.video.videoHeight);
      this.intervalId = setInterval(() => this.scan(), this.scanInterval);
    } catch (error) {
      this.onError?.(error as Error);
      throw error;
    }
  }

  /**
   * Stop scanning and release camera
   */
  stop(): void {
    this.running = false;

    if (this.intervalId !== null) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }

    if (this.stream) {
      this.stream.getTracks().forEach((track) => track.stop());
      this.stream = null;
    }

    if (this.video) {
      this.video.srcObject = null;
      this.video = null;
    }

    this.canvas = null;
    this.ctx = null;
  }

  /**
   * Check if scanner is currently running
   */
  isRunning(): boolean {
    return this.running;
  }

  private scanCount = 0;

  /**
   * Perform a single scan
   */
  private scan(): void {
    this.scanCount++;

    // Log every 50 scans
    if (this.scanCount % 50 === 1) {
      console.log('[SCANNER] Scan #' + this.scanCount,
        'video:', !!this.video,
        'canvas:', !!this.canvas,
        'ctx:', !!this.ctx,
        'readyState:', this.video?.readyState,
        'HAVE_ENOUGH_DATA:', this.video?.HAVE_ENOUGH_DATA);
    }

    if (!this.video || !this.canvas || !this.ctx) {
      if (this.scanCount % 50 === 1) console.log('[SCANNER] Early return: missing video/canvas/ctx');
      return;
    }
    if (this.video.readyState !== this.video.HAVE_ENOUGH_DATA) {
      if (this.scanCount % 50 === 1) console.log('[SCANNER] Early return: video not ready');
      return;
    }

    // Update canvas size if video size changed
    if (
      this.canvas.width !== this.video.videoWidth ||
      this.canvas.height !== this.video.videoHeight
    ) {
      this.canvas.width = this.video.videoWidth;
      this.canvas.height = this.video.videoHeight;
    }

    // Draw video frame to canvas
    this.ctx.drawImage(this.video, 0, 0);

    // Get image data for QR detection
    const imageData = this.ctx.getImageData(
      0,
      0,
      this.canvas.width,
      this.canvas.height
    );

    // Log image data stats occasionally
    if (this.scanCount % 50 === 1) {
      // Analyze image brightness to see if QR might be visible
      let minBrightness = 255, maxBrightness = 0;
      for (let i = 0; i < imageData.data.length; i += 400) { // Sample every 100th pixel
        const r = imageData.data[i];
        const g = imageData.data[i + 1];
        const b = imageData.data[i + 2];
        const brightness = (r + g + b) / 3;
        minBrightness = Math.min(minBrightness, brightness);
        maxBrightness = Math.max(maxBrightness, brightness);
      }
      console.log('[SCANNER] Image:', imageData.width, 'x', imageData.height,
        'brightness range:', Math.round(minBrightness), '-', Math.round(maxBrightness),
        '(need 0-255 range for QR)');
    }

    // Attempt to decode QR code
    if (this.scanCount % 50 === 1) {
      console.log('[SCANNER] Calling jsQR...');
    }
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'attemptBoth',  // Try both normal and inverted
    });
    if (this.scanCount % 50 === 1) {
      console.log('[SCANNER] jsQR result:', code ? 'FOUND: ' + code.data : 'null');
    }

    if (code && code.data) {
      console.log('[SCANNER] Found QR code:', code.data);
      const now = Date.now();

      // Debounce: don't report same QR code repeatedly
      if (
        code.data !== this.lastScannedData ||
        now - this.lastScanTime > this.debounceMs
      ) {
        this.lastScannedData = code.data;
        this.lastScanTime = now;
        console.log('[SCANNER] Reporting scan (not debounced)');

        this.onScan({
          data: code.data,
          timestamp: now,
        });
      }
    }
  }

  /**
   * Decode QR code from ImageData directly (for custom video sources)
   */
  static decodeFromImageData(imageData: ImageData): string | null {
    const code = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert',
    });
    return code?.data ?? null;
  }

  /**
   * Check if camera is available
   */
  static async isAvailable(): Promise<boolean> {
    if (typeof navigator === 'undefined' || !navigator.mediaDevices) {
      return false;
    }
    try {
      const devices = await navigator.mediaDevices.enumerateDevices();
      return devices.some((device) => device.kind === 'videoinput');
    } catch {
      return false;
    }
  }
}

/**
 * Utility functions for QR code capacity estimation
 */

/**
 * Estimate QR code data capacity at different error correction levels
 */
export function estimateQRCapacity(
  errorCorrectionLevel: 'L' | 'M' | 'Q' | 'H' = 'M'
): number {
  // Approximate byte capacity for version 10 QR code
  const capacities = {
    L: 652,
    M: 513,
    Q: 364,
    H: 288,
  };
  return capacities[errorCorrectionLevel];
}

/**
 * Check if data fits in a single QR code
 */
export function fitsInQR(
  data: string,
  errorCorrectionLevel: 'L' | 'M' | 'Q' | 'H' = 'M'
): boolean {
  const byteLength = new TextEncoder().encode(data).length;
  return byteLength <= estimateQRCapacity(errorCorrectionLevel);
}
