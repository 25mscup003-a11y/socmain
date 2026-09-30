import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';
import { useAuth } from '../context/AuthContext';

const ROLE_LABEL = {
  superadmin: 'Super Admin', company_admin: 'Company Admin', department_admin: 'Department Admin', soc_manager: 'SOC Manager',
  l1_analyst: 'L1 Analyst', l2_analyst: 'L2 Analyst', l3_analyst: 'L3 Analyst', l4_analyst: 'L4 TI Analyst',
};

export default function SocChatPage({ heading = 'Contact Support' }) {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const [contacts, setContacts] = useState([]);
  const [selectedId, setSelectedId] = useState(params.get('contact') || '');
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState('');
  const [contactFilter, setContactFilter] = useState('all');
  const [error, setError] = useState('');
  const [sending, setSending] = useState(false);
  const bottomRef = useRef(null);

  const loadContacts = useCallback(async () => {
    try {
      const { data } = await api.get('/soc-chat/contacts', { skipCache: true });
      setContacts(data.contacts || []);
      setSelectedId(current => current || params.get('contact') || data.contacts?.[0]?._id || '');
    } catch (e) { setError(e.response?.data?.message || 'Unable to load support contacts'); }
  }, [params]);

  const loadThread = useCallback(async (quiet = false) => {
    if (!selectedId) return;
    try {
      const { data } = await api.get(`/soc-chat/thread/${selectedId}`, { skipCache: true });
      setMessages(data.messages || []);
      if (!quiet) setError('');
    } catch (e) { if (!quiet) setError(e.response?.data?.message || 'Unable to load chat'); }
  }, [selectedId]);

  useEffect(() => { loadContacts(); }, [loadContacts]);
  useEffect(() => { loadThread(); }, [loadThread]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [messages]);
  useEffect(() => {
    const socket = io(SOCKET_URL);
    const refresh = () => { loadContacts(); loadThread(true); };
    const markSeen = event => {
      if (String(event?.readerId || '') !== String(selectedId)) return;
      setMessages(current => current.map(message => {
        const mine = String(message.senderId?._id || message.senderId) === String(user?._id || user?.id);
        return mine && !message.readAt ? { ...message, readAt: event.readAt } : message;
      }));
    };
    socket.on('soc-chat:message', refresh);
    socket.on('soc-chat:read', markSeen);
    const disconnect = connectSocket(socket);
    const timer = window.setInterval(() => document.visibilityState === 'visible' && refresh(), 20000);
    return () => { window.clearInterval(timer); socket.off('soc-chat:message', refresh); socket.off('soc-chat:read', markSeen); disconnect(); };
  }, [loadContacts, loadThread, selectedId, user?._id, user?.id]);

  const quickContactRole = user?.role === 'department_admin' ? 'soc_manager' : '';
  const quickContacts = useMemo(() => contacts.filter(item => item.role === quickContactRole), [contacts, quickContactRole]);
  const visibleContacts = useMemo(() => (
    contactFilter === 'all' ? contacts : contacts.filter(item => item.role === contactFilter)
  ), [contactFilter, contacts]);
  const selected = useMemo(() => contacts.find(item => String(item._id) === String(selectedId)), [contacts, selectedId]);
  const choose = id => {
    setSelectedId(id);
    params.set('contact', id);
    setParams(params, { replace: true });
  };
  const showQuickContacts = () => {
    setContactFilter(quickContactRole);
    if (quickContacts.length && !quickContacts.some(item => String(item._id) === String(selectedId))) {
      choose(quickContacts[0]._id);
    }
  };
  const send = async e => {
    e.preventDefault();
    const text = draft.trim();
    if (!text || !selectedId || sending) return;
    setSending(true); setError('');
    try {
      const { data } = await api.post(`/soc-chat/thread/${selectedId}/messages`, { message: text });
      setMessages(current => [...current, data.message]);
      setDraft('');
      loadContacts();
    } catch (err) { setError(err.response?.data?.message || 'Message could not be sent'); }
    finally { setSending(false); }
  };

  return (
    <div className="soc-chat-page">
      <header className="soc-chat-header">
        <div><h1>💬 {heading}</h1><p>Secure role-scoped SOC communication</p></div>
        <div className="soc-chat-header-actions">
          {quickContactRole && (
            <button
              type="button"
              className={contactFilter === quickContactRole ? 'active' : ''}
              onClick={showQuickContacts}
              disabled={!quickContacts.length}
              title={quickContacts.length ? `Show assigned ${ROLE_LABEL[quickContactRole]} contacts` : `No ${ROLE_LABEL[quickContactRole]} is assigned to your scope`}
            >
              🛡️ Chat with {ROLE_LABEL[quickContactRole]}{quickContacts.length ? ` (${quickContacts.length})` : ''}
            </button>
          )}
          <span className="soc-chat-live">● Live</span>
        </div>
      </header>
      {error && <div className="soc-chat-error">{error}</div>}
      <div className="soc-chat-shell">
        <aside className="soc-chat-contacts">
          <div style={{ minHeight: 'calc(100% + 20px)' }}>
            <div className="soc-chat-contact-title">
              <span>{contactFilter === 'all' ? 'Authorized contacts' : `${ROLE_LABEL[contactFilter]} contacts`}</span>
              {contactFilter !== 'all' && <button type="button" onClick={() => setContactFilter('all')}>Show all</button>}
            </div>
            {!visibleContacts.length && <div className="soc-chat-empty">{contactFilter === 'all' ? 'No support contact is assigned to your scope.' : `No ${ROLE_LABEL[contactFilter]} is assigned to your scope.`}</div>}
            {visibleContacts.map(contact => (
              <button key={contact._id} onClick={() => choose(contact._id)} className={String(contact._id) === String(selectedId) ? 'active' : ''}>
                <span className="soc-chat-avatar">{(contact.name || 'U')[0].toUpperCase()}</span>
                <span className="soc-chat-contact-copy"><b>{contact.name}</b><small>{ROLE_LABEL[contact.role] || contact.role}</small><em>{contact.lastMessage || contact.email}</em></span>
                {contact.unread > 0 && <i>{contact.unread > 99 ? '99+' : contact.unread}</i>}
              </button>
            ))}
          </div>
        </aside>
        <section className="soc-chat-thread">
          {selected ? <>
            <div className="soc-chat-person"><span className="soc-chat-avatar">{(selected.name || 'U')[0].toUpperCase()}</span><div><b>{selected.name}</b><small>{ROLE_LABEL[selected.role] || selected.role} · {selected.email}</small></div></div>
            <div className="soc-chat-messages">
              {!messages.length && <div className="soc-chat-empty">Start a secure conversation with {selected.name}.</div>}
              {messages.map(message => {
                const mine = String(message.senderId?._id || message.senderId) === String(user?._id || user?.id);
                return <div key={message._id} className={`soc-chat-bubble ${mine ? 'mine' : ''}`}><b>{mine ? 'You' : message.senderId?.name || selected.name}</b><p>{message.message}</p><time>{new Date(message.createdAt).toLocaleString()}{mine && <span className={message.readAt ? 'seen' : ''}>{message.readAt ? '✓✓ Seen' : '✓ Sent'}</span>}</time></div>;
              })}
              <div ref={bottomRef} />
            </div>
            <form className="soc-chat-compose" onSubmit={send}>
              <textarea value={draft} onChange={e => setDraft(e.target.value)} maxLength={4000} placeholder={`Message ${selected.name}…`} onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form.requestSubmit(); } }} />
              <button disabled={!draft.trim() || sending}>{sending ? 'Sending…' : 'Send ➤'}</button>
            </form>
          </> : <div className="soc-chat-empty center">Select an authorized contact to begin.</div>}
        </section>
      </div>
      <style>{`
        .soc-chat-page{color:#dbeafe;min-width:0}.soc-chat-header{display:flex;justify-content:space-between;align-items:center;padding:18px 20px;margin-bottom:14px;border:1px solid #1e3a5f;border-radius:14px;background:linear-gradient(135deg,#0c1a2e,#101d35)}.soc-chat-header h1{font-size:22px;margin:0}.soc-chat-header p{color:#94a3b8;margin:5px 0 0;font-size:12px}.soc-chat-header-actions{display:flex;align-items:center;gap:14px}.soc-chat-header-actions button{padding:9px 12px;border:1px solid #2563eb;border-radius:9px;background:#10233c;color:#bfdbfe;font-weight:800;cursor:pointer}.soc-chat-header-actions button:hover,.soc-chat-header-actions button.active{background:#1d4ed8;color:white}.soc-chat-header-actions button:disabled{opacity:.45;cursor:not-allowed}.soc-chat-live{color:#34d399;font-size:12px;font-weight:800;white-space:nowrap}.soc-chat-error{padding:10px 14px;margin-bottom:12px;border:1px solid #7f1d1d;border-radius:8px;background:#350d16;color:#fca5a5}.soc-chat-shell{display:grid;grid-template-columns:320px minmax(0,1fr);height:calc(100vh - 220px);min-height:380px;border:1px solid #1e3a5f;border-radius:14px;overflow:hidden;background:#091624}.soc-chat-contacts{border-right:1px solid #1e3a5f;overflow-y:scroll;position:relative}.soc-chat-contact-title{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px;color:#7dd3fc;font-size:11px;font-weight:900;text-transform:uppercase;letter-spacing:.7px;position:sticky;top:0;z-index:10;background:#091624;border-bottom:1px solid #1e3a5f}.soc-chat-contact-title button{width:auto;padding:0;border:0;background:transparent;color:#93c5fd;font-size:10px;font-weight:800;text-transform:none;white-space:nowrap}.soc-chat-contacts>div>button{display:flex;width:100%;gap:10px;align-items:center;padding:12px;border:0;border-top:1px solid #172b45;background:transparent;color:#dbeafe;text-align:left;cursor:pointer}.soc-chat-contacts>div>button:hover,.soc-chat-contacts>div>button.active{background:#10233c}.soc-chat-avatar{width:38px;height:38px;flex:0 0 38px;border-radius:11px;display:grid;place-items:center;background:linear-gradient(135deg,#2563eb,#7c3aed);font-weight:900;color:white}.soc-chat-contact-copy{min-width:0;flex:1}.soc-chat-contact-copy b,.soc-chat-contact-copy small,.soc-chat-contact-copy em{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.soc-chat-contact-copy small{color:#67e8f9;font-size:10px;margin-top:2px}.soc-chat-contact-copy em{color:#64748b;font-size:10px;font-style:normal;margin-top:4px}.soc-chat-contacts>div>button i{background:#ef4444;color:white;border-radius:999px;padding:2px 6px;font-size:10px;font-style:normal}.soc-chat-thread{display:flex;min-width:0;flex-direction:column;position:relative;overflow:hidden}.soc-chat-person{display:flex;gap:10px;align-items:center;padding:12px 16px;border-bottom:1px solid #1e3a5f;background:#0d1d31;position:sticky;top:0;z-index:10}.soc-chat-person small{display:block;color:#94a3b8;font-size:10px;margin-top:3px}.soc-chat-messages{flex:1;min-height:0;overflow-y:scroll;padding:18px;display:flex;flex-direction:column;gap:10px}.soc-chat-bubble{align-self:flex-start;max-width:min(72%,650px);padding:10px 12px;border:1px solid #294765;border-radius:4px 12px 12px;background:#10233c}.soc-chat-bubble.mine{align-self:flex-end;background:#173f75;border-color:#2563eb;border-radius:12px 4px 12px 12px}.soc-chat-bubble b{font-size:10px;color:#67e8f9}.soc-chat-bubble p{margin:5px 0;color:#e2e8f0;white-space:pre-wrap;overflow-wrap:anywhere}.soc-chat-bubble time{display:flex;justify-content:flex-end;gap:7px;color:#7c8da5;font-size:9px}.soc-chat-bubble time span{color:#94a3b8;font-weight:800}.soc-chat-bubble time span.seen{color:#67e8f9}.soc-chat-compose{display:flex;gap:10px;padding:12px;border-top:1px solid #1e3a5f;background:#0d1d31}.soc-chat-compose textarea{flex:1;min-width:0;height:48px;resize:none;padding:10px;border:1px solid #294765;border-radius:9px;background:#07111f;color:#e2e8f0;font:inherit}.soc-chat-compose button{padding:0 20px;border:0;border-radius:9px;background:#2563eb;color:white;font-weight:800;cursor:pointer}.soc-chat-compose button:disabled{opacity:.45;cursor:not-allowed}.soc-chat-empty{padding:18px;color:#64748b;font-size:12px}.soc-chat-empty.center{margin:auto;font-size:14px}@supports not selector(::-webkit-scrollbar) {
  .soc-chat-contacts, .soc-chat-messages {
    scrollbar-width: thin;
    scrollbar-color: #2563eb transparent;
  }
}
.soc-chat-contacts::-webkit-scrollbar,
.soc-chat-messages::-webkit-scrollbar {
  width: 8px;
  height: 8px;
  display: block !important;
}
.soc-chat-contacts::-webkit-scrollbar-track,
.soc-chat-messages::-webkit-scrollbar-track {
  background: transparent !important;
  border: 0 !important;
}
.soc-chat-contacts::-webkit-scrollbar-thumb,
.soc-chat-messages::-webkit-scrollbar-thumb {
  background: #2563eb !important;
  border-radius: 999px !important;
}
.soc-chat-contacts::-webkit-scrollbar-thumb:hover,
.soc-chat-messages::-webkit-scrollbar-thumb:hover {
  background: #3b82f6 !important;
}
.soc-chat-contacts::-webkit-scrollbar-button,
.soc-chat-messages::-webkit-scrollbar-button {
  display: none !important;
}
@media(max-width:760px){.soc-chat-header{align-items:flex-start;gap:12px}.soc-chat-header-actions{align-items:flex-end;flex-direction:column;gap:8px}.soc-chat-header-actions button{font-size:11px}.soc-chat-shell{grid-template-columns:1fr;height:auto}.soc-chat-contacts{max-height:230px;border-right:0;border-bottom:1px solid #1e3a5f}.soc-chat-thread{min-height:500px}.soc-chat-bubble{max-width:88%}}
      `}</style>
    </div>
  );
}
