// Simple client-side browser fingerprinting and telemetry tracking

export interface BehavioralTelemetry {
  averageVelocity: number;
  totalDistance: number;
  jerkMetric: number; // rate of change of acceleration
  keyIntervals: number[]; // times between keypresses
  typingSpeed: number; // characters per minute
}

export interface DeviceFingerprint {
  browser: string;
  os: string;
  screenResolution: string;
  canvasHash: string;
  timezone: string;
  language: string;
}

/**
 * Generates a mock canvas fingerprint (deterministic hash based on canvas rendering)
 */
export function getCanvasFingerprint(): string {
  try {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    if (!ctx) return 'canvas-not-supported';

    canvas.width = 200;
    canvas.height = 50;

    // Draw interesting text and shapes with color gradients
    ctx.textBaseline = "top";
    ctx.font = "14px 'Arial'";
    ctx.textBaseline = "alphabetic";
    ctx.fillStyle = "#f60";
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = "#069";
    ctx.fillText("ZTNA Shield, <canvas> 1.0", 2, 15);
    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
    ctx.fillText("ZTNA Shield, <canvas> 1.0", 4, 17);

    const dataUrl = canvas.toDataURL();
    
    // Hash the data URL using a simple custom algorithm
    let hash = 0;
    for (let i = 0; i < dataUrl.length; i++) {
      const char = dataUrl.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16);
  } catch (e) {
    return 'fingerprint-error';
  }
}

/**
 * Parses user agent to detect OS and Browser
 */
export function getOSAndBrowser(): { os: string; browser: string } {
  const ua = navigator.userAgent;
  let os = 'Unknown OS';
  let browser = 'Unknown Browser';

  if (ua.indexOf('Win') !== -1) os = 'Windows 11'; // Mock modern Windows
  else if (ua.indexOf('Mac') !== -1) os = 'macOS Ventura';
  else if (ua.indexOf('X11') !== -1) os = 'Linux';
  else if (ua.indexOf('Linux') !== -1) os = 'Android';
  else if (ua.indexOf('iPhone') !== -1) os = 'iOS';

  if (ua.indexOf('Chrome') !== -1 && ua.indexOf('Safari') !== -1) browser = 'Chrome';
  else if (ua.indexOf('Firefox') !== -1) browser = 'Firefox';
  else if (ua.indexOf('Safari') !== -1 && ua.indexOf('Chrome') === -1) browser = 'Safari';
  else if (ua.indexOf('Edge') !== -1) browser = 'Edge';

  return { os, browser };
}

/**
 * Gets complete client fingerprint
 */
export function getDeviceFingerprint(): DeviceFingerprint {
  const { os, browser } = getOSAndBrowser();
  return {
    browser,
    os,
    screenResolution: `${window.screen.width}x${window.screen.height}`,
    canvasHash: getCanvasFingerprint(),
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    language: navigator.language
  };
}

/**
 * Helper class to track real-time typing dynamics on input elements
 */
export class TypingTracker {
  private keyTimes: number[] = [];
  private lastTime: number = 0;

  public reset() {
    this.keyTimes = [];
    this.lastTime = 0;
  }

  public recordKeyPress() {
    const now = performance.now();
    if (this.lastTime !== 0) {
      const interval = now - this.lastTime;
      // Filter out abnormally long delays (e.g. user stopped typing to think)
      if (interval < 1500) {
        this.keyTimes.push(Math.round(interval));
      }
    }
    this.lastTime = now;
  }

  public getTelemetry(): { keyIntervals: number[]; typingSpeed: number } {
    if (this.keyTimes.length === 0) {
      return { keyIntervals: [], typingSpeed: 120 }; // default
    }

    const averageInterval = this.keyTimes.reduce((a, b) => a + b, 0) / this.keyTimes.length;
    // Estimate Words Per Minute (WPM) based on character intervals
    // 5 chars = 1 word. WPM = (60000ms / averageInterval) / 5
    const wpm = Math.round((60000 / averageInterval) / 5);

    return {
      keyIntervals: this.keyTimes,
      typingSpeed: wpm
    };
  }
}

/**
 * Helper class to track mouse telemetry velocity, distance and jerk
 */
export class MouseTracker {
  private points: { x: number; y: number; t: number }[] = [];
  private maxPoints = 150;

  public recordMove(e: MouseEvent) {
    this.points.push({
      x: e.clientX,
      y: e.clientY,
      t: performance.now()
    });
    
    if (this.points.length > this.maxPoints) {
      this.points.shift();
    }
  }

  public getTelemetry(): BehavioralTelemetry {
    if (this.points.length < 2) {
      return { averageVelocity: 0, totalDistance: 0, jerkMetric: 0, keyIntervals: [], typingSpeed: 0 };
    }

    let totalDistance = 0;
    const velocities: number[] = [];
    const accelerations: number[] = [];
    const jerks: number[] = [];

    for (let i = 1; i < this.points.length; i++) {
      const p1 = this.points[i - 1];
      const p2 = this.points[i];

      const dx = p2.x - p1.x;
      const dy = p2.y - p1.y;
      const dt = (p2.t - p1.t) / 1000; // in seconds

      if (dt <= 0) continue;

      const dist = Math.sqrt(dx * dx + dy * dy);
      totalDistance += dist;

      const vel = dist / dt;
      velocities.push(vel);

      if (velocities.length > 1) {
        const dv = vel - velocities[velocities.length - 2];
        const acc = dv / dt;
        accelerations.push(acc);

        if (accelerations.length > 1) {
          const da = acc - accelerations[accelerations.length - 2];
          const jerk = da / dt;
          jerks.push(jerk);
        }
      }
    }

    const avgVel = velocities.length > 0 ? velocities.reduce((a, b) => a + b, 0) / velocities.length : 0;
    const avgJerk = jerks.length > 0 ? jerks.reduce((a, b) => a + b, 0) / jerks.length : 0;

    return {
      averageVelocity: Math.round(avgVel),
      totalDistance: Math.round(totalDistance),
      jerkMetric: Math.round(avgJerk),
      keyIntervals: [],
      typingSpeed: 0
    };
  }
}
