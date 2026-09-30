import { useCallback, useEffect, useRef, useState } from 'react';
import api from '../api/axios';

export default function SocChatModal({ contact, onClose }) {
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [sending, setSending] = useState(false);
  const endRef = useRef(null);
  const load = useCallback(async () => {
    if (!contact?._id) return;
    try {
      const { data } = await api.get(`/soc-chat/thread/${contact._id}`, { skipCache: true });
      setMessages(data.messages || []); setError('');
    } catch (e) { setError(e.response?.data?.message || 'Unable to load chat'); }
  }, [contact?._id]);
  useEffect(() => {
    load();
    const timer = window.setInterval(() => document.visibilityState === 'visible' && load(), 5000);
    return () => window.clearInterval(timer);
  }, [load]);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  const send = async e => {
    e.preventDefault();
    const text = draft.trim();
    if (!text || sending) return;
    setSending(true);
    try {
      const { data } = await api.post(`/soc-chat/thread/${contact._id}/messages`, { message: text });
      setMessages(rows => [...rows, data.message]); setDraft(''); setError('');
    } catch (err) { setError(err.response?.data?.message || 'Message could not be sent'); }
    finally { setSending(false); }
  };
  return <div style={overlay} onMouseDown={e => e.target === e.currentTarget && onClose()}>
    <section style={modal}>
      <header style={header}><div><h3 style={{ margin: 0, color: '#f8fafc' }}>💬 {contact.name}</h3><small style={{ color: '#67e8f9' }}>SOC Manager · secure direct chat</small></div><button onClick={onClose} style={close}>✕</button></header>
      {error && <div style={errorBox}>{error}</div>}
      <main style={messageList}>
        {!messages.length && <div style={{ margin: 'auto', color: '#64748b' }}>Start a conversation with {contact.name}.</div>}
        {messages.map(message => {
          const mine = message.senderId?.role === 'superadmin';
          return <div key={message._id} style={{ ...bubble, ...(mine ? mineBubble : {}) }}><b style={{ color: '#67e8f9', fontSize: 10 }}>{mine ? 'You' : message.senderId?.name || contact.name}</b><p style={{ margin: '5px 0', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{message.message}</p><time style={{ color: '#71839b', fontSize: 9 }}>{new Date(message.createdAt).toLocaleString()}{mine && <span style={{ marginLeft: 8, color: message.readAt ? '#67e8f9' : '#94a3b8', fontWeight: 800 }}>{message.readAt ? '✓✓ Seen' : '✓ Sent'}</span>}</time></div>;
        })}<div ref={endRef} />
      </main>
      <form onSubmit={send} style={compose}><textarea autoFocus value={draft} maxLength={4000} onChange={e => setDraft(e.target.value)} placeholder={`Message ${contact.name}…`} style={textarea} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form.requestSubmit(); } }} /><button disabled={!draft.trim() || sending} style={sendButton}>{sending ? 'Sending…' : 'Send ➤'}</button></form>
    </section>
  </div>;
}

const overlay = { position: 'fixed', inset: 0, zIndex: 500, display: 'grid', placeItems: 'center', padding: 18, background: 'rgba(2,6,23,.82)', backdropFilter: 'blur(7px)' };
const modal = { width: 'min(720px,96vw)', height: 'min(700px,88vh)', display: 'flex', flexDirection: 'column', overflow: 'hidden', border: '1px solid #1e3a5f', borderRadius: 14, background: '#091624', boxShadow: '0 28px 70px rgba(0,0,0,.55)' };
const header = { padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e3a5f', background: '#0d1d31' };
const close = { border: 0, background: '#1e293b', color: '#e2e8f0', borderRadius: 7, padding: '7px 10px', cursor: 'pointer' };
const errorBox = { padding: 10, background: '#350d16', color: '#fca5a5', borderBottom: '1px solid #7f1d1d' };
const messageList = { flex: 1, minHeight: 0, overflowY: 'auto', padding: 18, display: 'flex', flexDirection: 'column', gap: 10, color: '#e2e8f0' };
const bubble = { alignSelf: 'flex-start', maxWidth: '76%', padding: '10px 12px', border: '1px solid #294765', borderRadius: '4px 12px 12px', background: '#10233c' };
const mineBubble = { alignSelf: 'flex-end', background: '#173f75', borderColor: '#2563eb', borderRadius: '12px 4px 12px 12px' };
const compose = { display: 'flex', gap: 10, padding: 12, borderTop: '1px solid #1e3a5f', background: '#0d1d31' };
const textarea = { flex: 1, minWidth: 0, height: 52, resize: 'none', padding: 10, border: '1px solid #294765', borderRadius: 8, background: '#07111f', color: '#e2e8f0', font: 'inherit' };
const sendButton = { padding: '0 20px', border: 0, borderRadius: 8, background: '#2563eb', color: 'white', fontWeight: 800, cursor: 'pointer' };
