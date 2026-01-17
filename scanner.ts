/**
 * QR Scanner - Physical layer for QR code scanning
 *
 * Uses native BarcodeDetector API when available (Chrome/Edge 88+, Safari 17.4+)
 * for hardware-accelerated scanning. Falls back to jsQR for older browsers.
 */

import jsQR from 'jsqr';

// Check for native BarcodeDetector support
const hasBarcodeDetector = typeof (window as any).BarcodeDetector !== 'undefined';
let barcodeDetector: any = null;
let scannerMode = 'jsQR';

if (hasBarcodeDetector) {
  try {
    barcodeDetector = new (window as any).BarcodeDetector({ formats: ['qr_code'] });
    scannerMode = 'BarcodeDetector';
    console.log('[Scanner] Using native BarcodeDetector (hardware-accelerated)');
  } catch (e) {
    console.log('[Scanner] BarcodeDetector init failed, using jsQR fallback');
  }
} else {
  console.log('[Scanner] BarcodeDetector not available, using jsQR');
}

export function getScannerMode(): string {
  return scannerMode;
}

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

  // Debug stats
  public scanCount: number = 0;
  public lastScanResult: string = 'none';

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

  /**
   * Perform a single scan - uses native BarcodeDetector if available
   */
  private async scan(): Promise<void> {
    if (!this.video || !this.canvas || !this.ctx) return;
    if (this.video.readyState !== this.video.HAVE_ENOUGH_DATA) return;

    this.scanCount++;
    let data: string | null = null;

    // Try native BarcodeDetector first (much more reliable)
    if (barcodeDetector && this.video) {
      try {
        const codes = await barcodeDetector.detect(this.video);
        if (codes.length > 0) {
          data = codes[0].rawValue;
        }
      } catch (e) {
        // Fall through to jsQR
      }
    }

    // Fall back to jsQR
    if (!data) {
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

      const code = jsQR(imageData.data, imageData.width, imageData.height, {
        inversionAttempts: 'attemptBoth',
      });

      if (code) {
        data = code.data;
      }
    }

    this.lastScanResult = data ? `FOUND: ${data.slice(0, 20)}` : 'no QR detected';

    if (data) {
      const now = Date.now();

      // Debounce: don't report same QR code repeatedly
      if (
        data !== this.lastScannedData ||
        now - this.lastScanTime > this.debounceMs
      ) {
        this.lastScannedData = data;
        this.lastScanTime = now;

        this.onScan({
          data,
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
