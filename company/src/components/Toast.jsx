/**
 * Toast.jsx — Global notification system
 * Usage:
 *   import { useToast, ToastContainer } from '../components/Toast';
 *   const toast = useToast();
 *   toast.success('Saved!');
 *   toast.error('Something went wrong');
 *   toast.info('Loading...');
 *   toast.warning('Check settings');
 */
import React, { createContext, useContext, useState, useCallback, useRef } from 'react';

const ToastCtx = createContext(null);

let _global_toast = null;
export function getToast() { return _global_toast; }

const ICONS = { success:'✅', error:'❌', warning:'⚠️', info:'ℹ️', loading:'⏳' };
const COLORS = {
  success: { bg:'#052e16', border:'#22c55e44', text:'#4ade80' },
  error:   { bg:'#1c0a0a', border:'#ef444444', text:'#f87171' },
  warning: { bg:'#1c1408', border:'#f59e0b44', text:'#fbbf24' },
  info:    { bg:'#0a1628', border:'#3b82f644', text:'#60a5fa' },
  loading: { bg:'#0a1628', border:'#a78bfa44', text:'#c4b5fd' },
};

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const counter = useRef(0);

  const remove = useCallback((id) => {
    setToasts(p => p.filter(t => t.id !== id));
  }, []);

  const add = useCallback((type, message, duration = 4000) => {
    const id = ++counter.current;
    setToasts(p => [...p.slice(-4), { id, type, message }]); // max 5
    if (duration > 0) setTimeout(() => remove(id), duration);
    return id;
  }, [remove]);

  const api = {
    success: (msg, dur) => add('success', msg, dur),
    error:   (msg, dur) => add('error',   msg, dur ?? 6000),
    warning: (msg, dur) => add('warning', msg, dur),
    info:    (msg, dur) => add('info',    msg, dur),
    loading: (msg)      => add('loading', msg, 0),
    dismiss: remove,
  };

  _global_toast = api;

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <ToastContainer toasts={toasts} onRemove={remove} />
    </ToastCtx.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastCtx);
  if (!ctx) throw new Error('useToast must be inside ToastProvider');
  return ctx;
}

function ToastContainer({ toasts, onRemove }) {
  if (!toasts.length) return null;
  return (
    <div style={{
      position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
      display: 'flex', flexDirection: 'column', gap: 10,
      maxWidth: 380, width: '90vw',
    }}>
      {toasts.map(t => {
        const c = COLORS[t.type] || COLORS.info;
        return (
          <div key={t.id} style={{
            background: c.bg, border: `1px solid ${c.border}`, color: c.text,
            borderRadius: 10, padding: '12px 16px', fontSize: 13,
            display: 'flex', alignItems: 'flex-start', gap: 10,
            boxShadow: '0 8px 32px rgba(0,0,0,.6)',
            animation: 'toast-in .25s ease',
          }}>
            <span style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }}>{ICONS[t.type]}</span>
            <span style={{ flex: 1, lineHeight: 1.5 }}>{t.message}</span>
            <button onClick={() => onRemove(t.id)} style={{
              background: 'none', border: 'none', color: c.text, cursor: 'pointer',
              fontSize: 14, opacity: .6, padding: 0, flexShrink: 0, lineHeight: 1,
            }}>✕</button>
          </div>
        );
      })}
      <style>{`
        @keyframes toast-in { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
      `}</style>
    </div>
  );
}

/** Standalone spinner for inline loading states */
export function Spinner({ size = 18, color = '#3b82f6' }) {
  return (
    <span style={{
      display: 'inline-block', width: size, height: size,
      border: `2px solid ${color}33`, borderTopColor: color,
      borderRadius: '50%', animation: 'spin .7s linear infinite', flexShrink: 0,
    }}>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </span>
  );
}

/** Full-page loader overlay */
export function PageLoader({ text = 'Loading…' }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      height: 260, flexDirection: 'column', gap: 16, color: '#1e40af',
    }}>
      <Spinner size={36} />
      <span style={{ fontSize: 13 }}>{text}</span>
    </div>
  );
}

/** Inline error banner */
export function ErrorBanner({ message, onRetry }) {
  if (!message) return null;
  return (
    <div style={{
      background: '#1c0a0a', border: '1px solid #ef444433', color: '#f87171',
      borderRadius: 8, padding: '12px 16px', marginBottom: 14, fontSize: 13,
      display: 'flex', alignItems: 'center', gap: 10,
    }}>
      <span>❌</span>
      <span style={{ flex: 1 }}>{message}</span>
      {onRetry && (
        <button onClick={onRetry} style={{
          fontSize: 11, padding: '4px 12px', borderRadius: 6, cursor: 'pointer',
          border: '1px solid #f87171', background: 'none', color: '#f87171',
        }}>Retry</button>
      )}
    </div>
  );
}

/** Success banner */
export function SuccessBanner({ message }) {
  if (!message) return null;
  return (
    <div style={{
      background: '#052e16', border: '1px solid #22c55e33', color: '#4ade80',
      borderRadius: 8, padding: '12px 16px', marginBottom: 14, fontSize: 13,
      display: 'flex', alignItems: 'center', gap: 10,
    }}>
      <span>✅</span>
      <span>{message}</span>
    </div>
  );
}
