/**
 * Stytch Fingerprint Helper
 * Collects a telemetry_id from the Stytch JS SDK for device fingerprinting.
 * Returns null when Stytch is not configured or unavailable. A locally
 * generated UUID must never be presented to Stytch as genuine telemetry.
 *
 * Usage: const telemetryId = await getTelemetryId();
 */

const PUBLIC_TOKEN = import.meta.env.VITE_STYTCH_PUBLIC_TOKEN || null;

/**
 * getTelemetryId
 * @returns {Promise<string|null>} - Genuine Stytch telemetry_id or null
 */
export async function getTelemetryId() {
  if (!PUBLIC_TOKEN) return null;

  if (typeof window === 'undefined' || typeof window.GetTelemetryID !== 'function') return null;

  try {
    const id = await window.GetTelemetryID({ publicToken: PUBLIC_TOKEN });
    return typeof id === 'string' && id.length > 0 ? id : null;
  } catch {
    return null;
  }
}
