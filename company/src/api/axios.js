import { authStorage } from './authStorage';
import axios from 'axios';
import { API_BASE_URL } from './config';
import {
  decryptApiResponse,
  encryptApiRequest,
  resetTransportSession,
} from './payloadEncryption';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  // No withCredentials — we use Authorization header (JWT), not cookies
});

const GET_CACHE_MS = Number(import.meta.env.VITE_GET_CACHE_MS || 5000);
const getCache = new Map();
const getInflight = new Map();
const realGet = api.get.bind(api);

function cacheableGet(url = '', config = {}) {
  if (config?.skipCache || config?.responseType || String(url).includes('/ai/jobs/')) {
    return realGet(url, config);
  }
  const key = `${url}::${JSON.stringify(config?.params || {})}`;
  const now = Date.now();
  const cached = getCache.get(key);
  if (cached && cached.expiresAt > now) return Promise.resolve(cached.response);
  if (getInflight.has(key)) return getInflight.get(key);
  const request = realGet(url, config)
    .then(response => {
      getCache.set(key, { response, expiresAt: Date.now() + GET_CACHE_MS });
      return response;
    })
    .finally(() => getInflight.delete(key));
  getInflight.set(key, request);
  return request;
}

api.get = cacheableGet;

api.interceptors.request.use(async (config) => {
  const token = authStorage.getItem('co_token') || authStorage.getItem('sa_token') || authStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  // Module pages opened from System Monitoring carry the selected endpoint in
  // the URL. Forward that scope to every GET request unless the page already
  // supplied one explicitly, so module dashboards stay endpoint-specific.
  if (typeof window !== 'undefined' && String(config.method || 'get').toLowerCase() === 'get') {
    const routeParams = new URLSearchParams(window.location.search);
    const scopedSystemId = routeParams.get('systemId');
    const returnTo = routeParams.get('returnTo');
    if (scopedSystemId && returnTo && !config.params?.systemId) {
      config.params = { ...(config.params || {}), systemId: scopedSystemId };
    }
  }
  return encryptApiRequest(config, token || '');
});

let sessionCheck = null;
let redirectingToLogin = false;

function isPublicAuthRequest(url = '') {
  return [
    '/auth/login',
    '/auth/verify-login-otp',
    '/auth/verify-2fa-login',
    '/auth/resend-otp',
    '/auth/signup',
    '/auth/partner-register',
  ].some(path => String(url).includes(path));
}

function isTransportAuthenticationFailure(error) {
  return error.response?.status === 400
    && error.response?.data?.message === 'Encrypted API payload authentication failed';
}

function clearCompanySession() {
  ['co_token', 'co_user', 'co_company', 'co_tenant', 'co_impersonation']
    .forEach(key => authStorage.removeItem(key));
  try { sessionStorage.removeItem('partner_plan'); } catch {}
  delete api.defaults.headers.common.Authorization;
}

function redirectToLogin() {
  if (redirectingToLogin || window.location.pathname === '/login') return;
  redirectingToLogin = true;
  clearCompanySession();
  window.location.assign('/login?reason=session_expired');
}

// A feature endpoint can return 401 for its own permission rules even while
// the JWT is healthy. Confirm the session with /auth/me before signing the user
// out, and share one check across simultaneous failed requests.
function confirmSession(token) {
  if (!sessionCheck) {
    sessionCheck = api.get('/auth/me', {
      skipCache: true,
      timeout: 10000,
    }).then(({ data }) => {
      if (data?.token) {
        authStorage.setItem('co_token', data.token);
        api.defaults.headers.common.Authorization = `Bearer ${data.token}`;
      }
      if (data?.user) authStorage.setItem('co_user', JSON.stringify(data.user));
      return true;
    }).catch(error => {
      // Only an explicit auth rejection proves that the session has ended.
      // Network errors and 5xx responses must not destroy a valid local login.
      if (error.response?.status === 401 || error.response?.status === 404) {
        redirectToLogin();
        return false;
      }
      return true;
    }).finally(() => {
      sessionCheck = null;
    });
  }
  return sessionCheck;
}

api.interceptors.response.use(
  (res) => decryptApiResponse(res),
  async (err) => {
    if (err.response) {
      try { await decryptApiResponse(err.response); } catch { /* preserve transport error */ }
    }

    // The browser session key is cached for performance. A backend restart can
    // rotate an ephemeral RSA key, so fetch the new key and retry exactly once.
    if (isTransportAuthenticationFailure(err) && !err.config?.__ajnatTransportRetried) {
      resetTransportSession();
      return api.request({
        ...err.config,
        __ajnatTransportRetried: true,
      });
    }

    const token = authStorage.getItem('co_token') || authStorage.getItem('sa_token') || authStorage.getItem('token');
    if (err.response?.status === 402 && err.response?.data?.code === 'REGISTRATION_PAYMENT_REQUIRED'
      && !/^\/register(?:\/|$)/.test(window.location.pathname) && window.location.pathname !== '/checkout') {
      window.location.replace('/register');
    }
    if (err.response?.status === 401 && token && !isPublicAuthRequest(err.config?.url)) {
      if (String(err.config?.url || '').includes('/auth/me')) {
        redirectToLogin();
      } else {
        // Keep the original API error for the calling page after validation.
        confirmSession(token);
      }
    }
    return Promise.reject(err);
  }
);

export default api;
