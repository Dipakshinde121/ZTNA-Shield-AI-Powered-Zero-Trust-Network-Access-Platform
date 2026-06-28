import type { SimulatedDevice } from '../context/SimulationContext';

// Helper to compute HMAC-SHA256 signature in browser using Web Crypto API
async function computeHMACSHA256(secret: string, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);

  const key = await window.crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await window.crypto.subtle.sign(
    'HMAC',
    key,
    messageData
  );

  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Creates custom headers with authorization and simulated device posture
 */
export async function getSecurityHeaders(
  endpoint: string,
  device: SimulatedDevice,
  token: string | null
): Promise<HeadersInit> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-mock-country': device.country,
    'x-device-fingerprint': device.fingerprint
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Only include full posture headers on registration channels (login/mfa verify) and status telemetry checks
  const isRegistrationOrTelemetry = 
    endpoint.includes('/api/auth/login') || 
    endpoint.includes('/api/auth/mfa/verify') || 
    endpoint.includes('/api/gateway/session-status');

  if (isRegistrationOrTelemetry) {
    headers['x-device-mac'] = device.macHash;
    headers['x-device-hostname'] = device.hostname;
    headers['x-device-os'] = device.os;
    headers['x-device-browser'] = device.browser;
    headers['x-device-encryption'] = String(device.diskEncryption);
    headers['x-device-firewall'] = String(device.firewall);
    headers['x-device-antivirus'] = String(device.antivirus);
    headers['x-device-vpn'] = String(device.isVPN);
    headers['x-device-tor'] = String(device.isTor);

    // Cryptographic attestation for status keepalive telemetry
    if (endpoint.includes('/api/gateway/session-status')) {
      const secret = localStorage.getItem('ztna_device_secret');
      if (secret) {
        const timestamp = Date.now().toString();
        const message = [
          timestamp,
          device.fingerprint,
          String(device.diskEncryption),
          String(device.firewall),
          String(device.antivirus),
          String(device.isVPN),
          String(device.isTor)
        ].join(':');

        try {
          const signature = await computeHMACSHA256(secret, message);
          headers['x-device-signature'] = signature;
          headers['x-device-timestamp'] = timestamp;
        } catch (e) {
          console.error('[ATTESTATION] Failed to sign posture telemetry:', e);
        }
      }
    }
  }

  return headers;
}

/**
 * Core API Client fetching from ZTNA Control Plane
 */
export async function ztnaFetch(
  endpoint: string,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  device: SimulatedDevice,
  token: string | null,
  body?: any
): Promise<Response> {
  const headers = await getSecurityHeaders(endpoint, device, token);
  const options: RequestInit = {
    method,
    headers
  };

  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  return fetch(`${endpoint}`, options);
}
