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
  transports: ['websocket', 'polling'],
  autoConnect: false,
  reconnectionAttempts: Infinity,
  reconnectionDelay: 1000,
  reconnectionDelayMax: 10000,
  randomizationFactor: 0.4,
  timeout: 5000,
};

export const pollingSocketOptions = {
  ...socketOptions,
  transports: ['polling'],
};

// Central shared socket instance and connection pooling
let sharedSocketInstance = null;
let activeListenersCount = 0;
let disconnectTimeoutId = null;

export function io(url, opts = {}) {
  const targetUrl = url || SOCKET_URL;
  if (!sharedSocketInstance) {
    
    // Always prefer websocket, fallback to polling
    const finalOpts = {
      ...socketOptions,
      ...opts,
      auth: opts.auth || ((callback) => callback({
        token: authStorage.getItem('sa_token') || '',
      })),
      transports: ['websocket', 'polling']
    };
    
    const socket = socketIO(targetUrl, finalOpts);
    sharedSocketInstance = socket;

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
    if (!socket.connected) {
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
