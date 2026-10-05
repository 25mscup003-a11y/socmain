import { authStorage } from './authStorage';
import { io as socketIO } from 'socket.io-client';

const DEFAULT_API_URL = typeof window !== 'undefined' && window.location.origin
  ? (window.location.port === '3000' || window.location.port === '3001' ? 'http://localhost:5000/api' : `${window.location.origin}/api`)
  : 'http://localhost:5000/api';

export const API_BASE_URL = (import.meta.env.VITE_API_URL || DEFAULT_API_URL).replace(/\/+$/, '');

export const SOCKET_URL = (
  import.meta.env.VITE_SOCKET_URL ||
  API_BASE_URL.replace(/\/api\/?$/, '') ||
  DEFAULT_API_URL.replace(/\/api$/, '')
).replace(/\/+$/, '');

export const socketOptions = {
  // Use a single WebSocket connection. Long-polling sessions are tied to an
  // Engine.IO `sid` and produce HTTP 400 responses when a backend restarts or
  // when consecutive requests reach different instances without sticky
  // sessions.
  transports: ['websocket'],
  upgrade: false,
  autoConnect: false,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 10000,
  randomizationFactor: 0.4,
  timeout: 5000,
};

export const pollingSocketOptions = {
  ...socketOptions,
  transports: ['websocket'],
};

// Central shared socket instance and connection pooling
let sharedSocketInstance = null;
let activeListenersCount = 0;
let disconnectTimeoutId = null;

export function io(url, opts = {}) {
  const targetUrl = url || SOCKET_URL;
  if (!sharedSocketInstance) {
    
    // Keep every caller on the shared WebSocket transport. Some pages pass
    // legacy polling options; accepting those here reintroduces stale SID 400s.
    const finalOpts = {
      ...socketOptions,
      ...opts,
      auth: (callback) => {
        const token = authStorage.getItem('co_token') || authStorage.getItem('sa_token') || authStorage.getItem('token') || '';
        if (typeof opts.auth === 'function') {
          opts.auth((userAuth) => callback({ token, ...(userAuth || {}) }));
        } else {
          callback({ token, ...(opts.auth || {}) });
        }
      },
      transports: ['websocket'],
      upgrade: false,
    };
    
    const socket = socketIO(targetUrl, finalOpts);
    sharedSocketInstance = socket;

    socket.on('connect_error', (err) => {
      if (err?.message?.includes('authentication') || err?.message?.includes('Unauthorized') || err?.message?.includes('Socket authentication required')) {
        socket.disconnect();
      }
    });

    // Track active room context for auto-reconnection
    socket.currentRoom = null;

    const originalEmit = socket.emit;
    socket.emit = function (event, ...args) {
      if (event === 'join:company') {
        const nextRoom = { type: 'company', id: args[0] };
        if (socket.connected && socket.currentRoom && socket.currentRoom.type === nextRoom.type && String(socket.currentRoom.id) === String(nextRoom.id)) {
          return socket;
        }
        socket.currentRoom = nextRoom;
      } else if (event === 'join:superadmin') {
        const nextRoom = { type: 'superadmin' };
        if (socket.connected && socket.currentRoom && socket.currentRoom.type === nextRoom.type) {
          return socket;
        }
        socket.currentRoom = nextRoom;
      } else if (event === 'join:partner') {
        const nextRoom = { type: 'partner', id: args[0] };
        if (socket.connected && socket.currentRoom && socket.currentRoom.type === nextRoom.type && String(socket.currentRoom.id) === String(nextRoom.id)) {
          return socket;
        }
        socket.currentRoom = nextRoom;
      }
      return originalEmit.apply(this, [event, ...args]);
    };

    // Auto re-join room on reconnect
    socket.on('connect', () => {
      if (socket.currentRoom) {
        if (socket.currentRoom.type === 'company') {
          originalEmit.call(socket, 'join:company', socket.currentRoom.id);
        } else if (socket.currentRoom.type === 'superadmin') {
          originalEmit.call(socket, 'join:superadmin');
        } else if (socket.currentRoom.type === 'partner') {
          originalEmit.call(socket, 'join:partner', socket.currentRoom.id);
        }
      }
    });

    socket.on('disconnect', (reason) => {
    });
  }
  return sharedSocketInstance;
}

export function connectSocket(socket) {
  activeListenersCount++;
  if (disconnectTimeoutId) {
    window.clearTimeout(disconnectTimeoutId);
    disconnectTimeoutId = null;
  }

  const timer = window.setTimeout(() => {
    const token = authStorage.getItem('co_token') || authStorage.getItem('sa_token') || authStorage.getItem('token');
    if (token && !socket.connected) {
      socket.connect();
    }
  }, 0);

  return () => {
    window.clearTimeout(timer);
    activeListenersCount--;
    
    if (activeListenersCount <= 0) {
      // Debounce socket disconnection during fast navigation/route changes
      disconnectTimeoutId = window.setTimeout(() => {
        if (activeListenersCount <= 0 && socket.connected) {
          socket.disconnect();
        }
      }, 2000);
    }
  };
}

// Helper to batch high-frequency socket events
export function createEventBuffer(onFlush, intervalMs = 1000) {
  let buffer = [];
  let timer = null;

  const add = (item) => {
    buffer.push(item);
    if (!timer) {
      timer = window.setTimeout(() => {
        const itemsToFlush = [...buffer];
        buffer = [];
        timer = null;
        onFlush(itemsToFlush);
      }, intervalMs);
    }
  };

  const clear = () => {
    if (timer) {
      window.clearTimeout(timer);
      timer = null;
    }
    buffer = [];
  };

  return { add, clear };
}

// Throttle function to restrict API call frequency
export function throttle(func, limit) {
  let inThrottle = false;
  return function (...args) {
    if (!inThrottle) {
      func.apply(this, args);
      inThrottle = true;
      window.setTimeout(() => {
        inThrottle = false;
      }, limit);
    }
  };
}
