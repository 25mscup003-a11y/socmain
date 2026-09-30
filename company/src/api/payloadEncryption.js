import { API_BASE_URL } from './config';

export const WEB_TRANSPORT_VERSION = 'aes-256-gcm-rsa-oaep-v1';
const REQUEST_AAD = new TextEncoder().encode('AJNAT-WEB-API-REQUEST-V1');
const META_AAD = new TextEncoder().encode('AJNAT-WEB-API-METADATA-V1');
const RESPONSE_AAD = new TextEncoder().encode('AJNAT-WEB-API-RESPONSE-V1');
const encoder = new TextEncoder();
const decoder = new TextDecoder();

let sessionPromise;

function bytesToBase64(bytes) {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let index = 0; index < view.length; index += 0x8000) {
    binary += String.fromCharCode(...view.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(String(value || ''));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

function pemToDer(pem) {
  return base64ToBytes(String(pem)
    .replace(/-----BEGIN PUBLIC KEY-----/g, '')
    .replace(/-----END PUBLIC KEY-----/g, '')
    .replace(/\s/g, ''));
}

async function createSession() {
  if (!globalThis.crypto?.subtle) throw new Error('Secure browser cryptography is unavailable');
  const response = await fetch(`${API_BASE_URL}/transport/public-key`, {
    cache: 'no-store',
    headers: { Accept: 'application/x-pem-file' },
  });
  if (!response.ok) throw new Error(`API transport key unavailable (${response.status})`);
  const publicKey = await crypto.subtle.importKey(
    'spki',
    pemToDer(await response.text()),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);
  const wrappedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawKey);
  return { aesKey, wrappedKey: bytesToBase64(wrappedKey) };
}

function transportSession() {
  if (!sessionPromise) sessionPromise = createSession().catch(error => {
    sessionPromise = null;
    throw error;
  });
  return sessionPromise;
}

async function encryptValue(value, aesKey, aad) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(value));
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    aesKey,
    plaintext,
  ));
  return {
    v: 1,
    alg: 'A256GCM',
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(sealed.slice(0, -16)),
    tag: bytesToBase64(sealed.slice(-16)),
  };
}

async function decryptEnvelope(envelope, aesKey, aad = RESPONSE_AAD) {
  if (!envelope || envelope.v !== 1 || envelope.alg !== 'A256GCM') {
    throw new Error('Unsupported encrypted API response');
  }
  const ciphertext = base64ToBytes(envelope.ciphertext);
  const tag = base64ToBytes(envelope.tag);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext);
  sealed.set(tag, ciphertext.length);
  return new Uint8Array(await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(envelope.nonce),
      additionalData: aad,
      tagLength: 128,
    },
    aesKey,
    sealed,
  ));
}

function queryObject(value) {
  if (!value) return {};
  if (value instanceof URLSearchParams) {
    const output = {};
    for (const [key, item] of value.entries()) {
      if (Object.prototype.hasOwnProperty.call(output, key)) {
        output[key] = Array.isArray(output[key]) ? [...output[key], item] : [output[key], item];
      } else output[key] = item;
    }
    return output;
  }
  return typeof value === 'object' ? value : {};
}

function splitUrlQuery(config) {
  const raw = String(config.url || '');
  const queryIndex = raw.indexOf('?');
  const params = { ...queryObject(config.params) };
  if (queryIndex < 0) return { url: raw, params };
  const search = new URLSearchParams(raw.slice(queryIndex + 1));
  for (const [key, value] of search.entries()) {
    if (Object.prototype.hasOwnProperty.call(params, key)) {
      params[key] = Array.isArray(params[key]) ? [...params[key], value] : [params[key], value];
    } else params[key] = value;
  }
  return { url: raw.slice(0, queryIndex), params };
}

function headerValue(headers, name) {
  return headers?.get?.(name) || headers?.[name] || headers?.[name.toLowerCase()] || '';
}

function setHeader(headers, name, value) {
  if (headers?.set) headers.set(name, value);
  else headers[name] = value;
}

function removeHeader(headers, name) {
  if (headers?.delete) headers.delete(name);
  else {
    delete headers[name];
    delete headers[name.toLowerCase()];
  }
}

function isEncryptableBody(value) {
  if (value == null) return false;
  if (typeof FormData !== 'undefined' && value instanceof FormData) return false;
  if (typeof Blob !== 'undefined' && value instanceof Blob) return false;
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) return false;
  return true;
}

export async function encryptApiRequest(config, token = '') {
  if (String(config.url || '').includes('/transport/public-key')) return config;

  // Axios keeps the transformed request config on errors. Preserve the
  // plaintext inputs so a single transport-key refresh can faithfully retry
  // the request after the API process rotates its RSA key.
  if (!config.__ajnatOriginalRequest) {
    config.__ajnatOriginalRequest = {
      url: config.url,
      params: config.params,
      data: config.data,
    };
  } else if (config.__ajnatTransportRetried) {
    config.url = config.__ajnatOriginalRequest.url;
    config.params = config.__ajnatOriginalRequest.params;
    config.data = config.__ajnatOriginalRequest.data;
  }

  const { aesKey, wrappedKey } = await transportSession();
  const headers = config.headers || {};
  const authorization = headerValue(headers, 'Authorization') || (token ? `Bearer ${token}` : '');
  const split = splitUrlQuery(config);
  config.url = split.url;
  config.params = undefined;

  const metaEnvelope = await encryptValue({ authorization, params: split.params }, aesKey, META_AAD);
  setHeader(headers, 'X-AJNAT-Web-Encryption', WEB_TRANSPORT_VERSION);
  setHeader(headers, 'X-AJNAT-Wrapped-Key', wrappedKey);
  setHeader(headers, 'X-AJNAT-Encrypted-Meta', bytesToBase64(encoder.encode(JSON.stringify(metaEnvelope))));
  removeHeader(headers, 'Authorization');

  if (isEncryptableBody(config.data)) {
    config.data = await encryptValue({ value: config.data }, aesKey, REQUEST_AAD);
    setHeader(headers, 'Content-Type', 'application/json');
  }
  config.headers = headers;
  config.__ajnatTransportKey = aesKey;
  return config;
}

async function responseEnvelope(value) {
  if (typeof Blob !== 'undefined' && value instanceof Blob) return JSON.parse(await value.text());
  if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
    const bytes = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return JSON.parse(decoder.decode(bytes));
  }
  return typeof value === 'string' ? JSON.parse(value) : value;
}

export async function decryptApiResponse(response) {
  if (!response || String(response.headers?.['x-ajnat-web-encryption'] || '').toLowerCase() !== WEB_TRANSPORT_VERSION) {
    return response;
  }
  const aesKey = response.config?.__ajnatTransportKey;
  if (!aesKey) throw new Error('Encrypted API response has no matching browser session key');
  const plaintext = await decryptEnvelope(await responseEnvelope(response.data), aesKey);
  const originalType = String(response.headers?.['x-ajnat-original-content-type'] || 'application/json').toLowerCase();
  response.data = originalType.includes('json') ? JSON.parse(decoder.decode(plaintext)) : decoder.decode(plaintext);
  return response;
}

export function resetTransportSession() {
  sessionPromise = null;
}
