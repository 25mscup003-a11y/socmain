const CONSENT_COOKIE = 'soc_location_consent';
const SESSION_CACHE_KEY = 'soc_browser_location';

function rememberConsent(value) {
  if (typeof document === 'undefined') return;
  const secure = window.location.protocol === 'https:' ? '; Secure' : '';
  document.cookie = `${CONSENT_COOKIE}=${encodeURIComponent(value)}; Max-Age=31536000; Path=/; SameSite=Lax${secure}`;
}

function cacheLocation(location) {
  try { sessionStorage.setItem(SESSION_CACHE_KEY, JSON.stringify(location)); } catch {}
}

export function getCachedBrowserLocation(maxAgeMs = 2 * 60 * 60 * 1000) {
  try {
    const value = JSON.parse(sessionStorage.getItem(SESSION_CACHE_KEY) || 'null');
    if (!value?.capturedAt || Date.now() - new Date(value.capturedAt).getTime() > maxAgeMs) return null;
    return value;
  } catch {
    return null;
  }
}

export async function captureBrowserLocation() {
  if (typeof navigator === 'undefined' || !navigator.geolocation) {
    rememberConsent('unsupported');
    return { permission: 'unsupported' };
  }

  let permission = 'prompt';
  try {
    if (navigator.permissions?.query) permission = (await navigator.permissions.query({ name: 'geolocation' })).state;
  } catch {}
  if (permission === 'denied') {
    rememberConsent('denied');
    return { permission: 'denied' };
  }

  return new Promise(resolve => {
    navigator.geolocation.getCurrentPosition(
      position => {
        const location = {
          permission: 'granted',
          latitude: Number(position.coords.latitude.toFixed(6)),
          longitude: Number(position.coords.longitude.toFixed(6)),
          accuracyMeters: Math.round(position.coords.accuracy || 0),
          capturedAt: new Date(position.timestamp || Date.now()).toISOString(),
        };
        rememberConsent('granted');
        cacheLocation(location);
        resolve(location);
      },
      error => {
        const state = error.code === error.PERMISSION_DENIED ? 'denied' : 'unavailable';
        rememberConsent(state);
        resolve({ permission: state });
      },
      { enableHighAccuracy: true, timeout: 8000, maximumAge: 60000 },
    );
  });
}
