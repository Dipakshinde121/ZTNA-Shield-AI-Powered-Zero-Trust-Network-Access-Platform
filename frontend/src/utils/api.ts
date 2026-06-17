import type { SimulatedDevice } from '../context/SimulationContext';

/**
 * Creates custom headers with authorization and simulated device posture
 */
export function getSecurityHeaders(device: SimulatedDevice, token: string | null): HeadersInit {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-mock-country': device.country,
    'x-device-fingerprint': device.fingerprint,
    'x-device-mac': device.macHash,
    'x-device-hostname': device.hostname,
    'x-device-os': device.os,
    'x-device-browser': device.browser,
    'x-device-encryption': String(device.diskEncryption),
    'x-device-firewall': String(device.firewall),
    'x-device-antivirus': String(device.antivirus),
    'x-device-vpn': String(device.isVPN),
    'x-device-tor': String(device.isTor)
  };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
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
  const headers = getSecurityHeaders(device, token);
  const options: RequestInit = {
    method,
    headers
  };

  if (body && method !== 'GET') {
    options.body = JSON.stringify(body);
  }

  return fetch(`${endpoint}`, options);
}
