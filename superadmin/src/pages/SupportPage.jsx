import { useEffect, useRef, useState } from 'react';
import { Building2, Check, CheckCheck, MessageSquare, Search, Send } from 'lucide-react';
import api from '../api/axios';
import { connectSocket, io, SOCKET_URL } from '../api/config';
import './SupportPage.css';

const statuses = ['Open', 'In Progress', 'Resolved', 'Closed'];
const companyIdOf = ticket => ticket?.companyId?._id || ticket?.companyId;
const formatTime = value => value ? new Date(value).toLocaleString() : '';
const errorMessage = (error, fallback) => error.response?.data?.message || fallback;
const mergeReadReceipts = (current, updated) => {
  if (!current || current._id !== updated?._id) return current;
  const receipts = new Map((updated.messages || []).filter(message => message.readAt).map(message => [message._id, message.readAt]));
  if (!(current.messages || []).some(message => !message.readAt && receipts.has(message._id))) return current;
  return { ...current, messages: current.messages.map(message => receipts.has(message._id) ? { ...message, readAt: message.readAt || receipts.get(message._id) } : message) };
};

export default function SupportPage() {
  const [filters, setFilters] = useState({ search: '', status: '', companyId: '', page: 1 });
  const [inbox, setInbox] = useState({ tickets: [], companies: [], total: 0, limit: 20 });
  const [selected, setSelected] = useState(null);
  const [ticket, setTicket] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadingChat, setLoadingChat] = useState(false);
  const [listError, setListError] = useState('');
  const [chatError, setChatError] = useState('');
  const [reply, setReply] = useState('');
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const [refresh, setRefresh] = useState(0);
  const conversation = useRef(null);
  const selection = useRef(null);
  const mutation = useRef(false);
  selection.current = selected?._id;

  const updateFilter = (key, value) => {
    setFilters(previous => ({ ...previous, [key]: value, page: 1 }));
    setSelected(null);
  };

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setListError('');
    const timer = window.setTimeout(async () => {
      try {
        const { data } = await api.get('/superadmin/company-support-tickets', {
          params: Object.fromEntries(Object.entries(filters).filter(([, value]) => value !== '')),
          signal: controller.signal,
        });
        if (controller.signal.aborted) return;
        setInbox(data);
        setSelected(previous => data.tickets.find(item => item._id === previous?._id) || data.tickets[0] || null);
      } catch (error) {
        if (!controller.signal.aborted) setListError(errorMessage(error, 'Unable to load support tickets.'));
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }, filters.search ? 250 : 0);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [filters, refresh]);

  const selectedId = selected?._id;
  const selectedCompanyId = companyIdOf(selected);
  useEffect(() => {
    setReply('');
    setNotice('');
  }, [selectedId]);

  useEffect(() => {
    const controller = new AbortController();
    setChatError('');
    setTicket(previous => previous?._id === selectedId ? previous : null);
    if (!selectedId || !selectedCompanyId) { setLoadingChat(false); return undefined; }
    setLoadingChat(true);
    api.get(`/superadmin/companies/${selectedCompanyId}/support-tickets/${selectedId}`, { signal: controller.signal })
      .then(({ data }) => { if (!controller.signal.aborted) setTicket(data); })
      .catch(error => {
        if (!controller.signal.aborted) {
          setTicket(null);
          setChatError(errorMessage(error, 'Unable to load this conversation.'));
        }
      })
      .finally(() => { if (!controller.signal.aborted) setLoadingChat(false); });
    return () => controller.abort();
  }, [selectedId, selectedCompanyId, refresh]);

  useEffect(() => {
    const socket = io(SOCKET_URL);
    let timer;
    const refreshInbox = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => setRefresh(value => value + 1), 200);
    };
    const onSupportEvent = event => {
      // Partner support uses the same socket event names. Fetch the authorized
      // inbox instead of inserting an arbitrary event payload into this page.
      if (event?.companyId || event?.ticket?.companyId) refreshInbox();
    };
    socket.emit('join:superadmin');
    socket.on('connect', refreshInbox);
    const events = ['support:ticket_new', 'support:message_new', 'support:ticket_updated'];
    events.forEach(event => socket.on(event, onSupportEvent));
    const onRead = event => setTicket(current => mergeReadReceipts(current, event?.ticket));
    socket.on('support:messages_read', onRead);
    const disconnect = connectSocket(socket);
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') refreshInbox();
    }, 30000);
    return () => {
      window.clearTimeout(timer);
      window.clearInterval(interval);
      socket.off('connect', refreshInbox);
      events.forEach(event => socket.off(event, onSupportEvent));
      socket.off('support:messages_read', onRead);
      disconnect();
    };
  }, []);

  useEffect(() => {
    if (conversation.current) conversation.current.scrollTop = conversation.current.scrollHeight;
  }, [ticket?._id, ticket?.messages?.length]);

  useEffect(() => {
    if (!ticket) return undefined;
    const messageIds = (ticket.messages || []).filter(message => message._id && !message.readAt && !['superadmin', 'partner_admin'].includes(message.senderRole)).slice(0, 200).map(message => message._id);
    if (!messageIds.length) return undefined;
    const controller = new AbortController();
    let pending = false;
    const acknowledge = async () => {
      if (document.visibilityState !== 'visible' || pending) return;
      pending = true;
      try {
        const { data } = await api.post(`/superadmin/companies/${companyIdOf(ticket)}/support-tickets/${ticket._id}/read`, { messageIds }, { signal: controller.signal });
        if (!controller.signal.aborted) setTicket(current => mergeReadReceipts(current, data));
      } catch { /* Retry when visible or on the next interval; never assume read. */ }
      finally { pending = false; }
    };
    acknowledge();
    document.addEventListener('visibilitychange', acknowledge);
    const timer = window.setInterval(acknowledge, 10000);
    return () => { controller.abort(); window.clearInterval(timer); document.removeEventListener('visibilitychange', acknowledge); };
  }, [ticket]);

  const save = async (kind, value) => {
    if (!ticket || mutation.current || (kind === 'messages' && !value.trim())) return;
    const targetId = ticket._id;
    const companyId = companyIdOf(ticket);
    mutation.current = true;
    setBusy(true);
    setChatError('');
    setNotice('');
    try {
      const path = `/superadmin/companies/${companyId}/support-tickets/${targetId}/${kind}`;
      if (kind === 'messages') await api.post(path, { message: value.trim() });
      else await api.patch(path, { status: value });
      if (selection.current === targetId) {
        if (kind === 'messages') setReply('');
        setNotice(kind === 'messages' ? 'Reply sent.' : 'Ticket status updated.');
      }
      setRefresh(previous => previous + 1);
    } catch (error) {
      if (selection.current === targetId) setChatError(errorMessage(error, 'Unable to save. Please try again.'));
    } finally {
      mutation.current = false;
      setBusy(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(inbox.total / inbox.limit));
  return (
    <div className="sa-support" aria-label="Company support">
      <div className="sa-support-filters">
        <label className="sa-support-search"><Search size={16} /><input aria-label="Search support tickets" placeholder="Search company, ticket or subject" maxLength={200} value={filters.search} onChange={event => updateFilter('search', event.target.value)} /></label>
        <select aria-label="Filter by company" value={filters.companyId} onChange={event => updateFilter('companyId', event.target.value)}><option value="">All direct companies</option>{inbox.companies.map(company => <option key={company._id} value={company._id}>{company.name}</option>)}</select>
        <select aria-label="Filter by ticket status" value={filters.status} onChange={event => updateFilter('status', event.target.value)}><option value="">All statuses</option>{statuses.map(status => <option key={status}>{status}</option>)}</select>
      </div>
      {listError && <div className="sa-support-error" role="alert">{listError} <button type="button" onClick={() => setRefresh(value => value + 1)}>Retry</button></div>}
      <div className="sa-support-workspace">
        <section className="sa-support-inbox" aria-label="Support tickets" aria-busy={loading}>
          <div className="sa-support-inbox-title"><h2>Conversations</h2><span>{inbox.total} tickets</span></div>
          <select className="sa-support-conversation-picker" aria-label="Select support conversation" value={selectedId || ''} disabled={loading || busy || inbox.tickets.length === 0} onChange={event => setSelected(inbox.tickets.find(item => item._id === event.target.value) || null)}>
            {inbox.tickets.length === 0 && <option value="">{loading ? 'Loading tickets…' : 'No support tickets found'}</option>}
            {inbox.tickets.map(item => <option key={item._id} value={item._id}>{item.ticketId} · {item.subject}</option>)}
          </select>
          <div className="sa-support-ticket-list">
            {loading && <p className="sa-support-empty" role="status">Loading tickets…</p>}
            {!loading && !listError && inbox.tickets.length === 0 && <p className="sa-support-empty">No support tickets found. Companies can start a conversation from Settings → Support.</p>}
            {inbox.tickets.map(item => <button key={item._id} type="button" className={`sa-support-ticket${selectedId === item._id ? ' selected' : ''}`} aria-pressed={selectedId === item._id} onClick={() => setSelected(item)} disabled={busy}>
              <span className="sa-support-ticket-meta"><span>{item.ticketId}</span><span className={`sa-support-status status-${item.status.toLowerCase().replaceAll(' ', '-')}`}>{item.status}</span></span>
              <strong>{item.subject}</strong><span className="sa-support-company"><Building2 size={13} />{item.companyId?.name || 'Company'}</span>
              <span className="sa-support-ticket-meta"><span className="sa-support-severity">{item.severity}</span><time dateTime={item.updatedAt}>{formatTime(item.updatedAt)}</time></span>
            </button>)}
          </div>
          <div className="sa-support-pagination" data-single-page={totalPages === 1}><button type="button" disabled={filters.page <= 1 || loading || busy} onClick={() => setFilters(previous => ({ ...previous, page: previous.page - 1 }))}>Previous</button><span>Page {filters.page} of {totalPages}</span><button type="button" disabled={filters.page >= totalPages || loading || busy} onClick={() => setFilters(previous => ({ ...previous, page: previous.page + 1 }))}>Next</button></div>
        </section>
        <section className="sa-support-chat" aria-label="Support conversation" aria-busy={loadingChat}>
          {chatError && <div className="sa-support-error" role="alert">{chatError} {!ticket && <button type="button" onClick={() => setRefresh(value => value + 1)}>Retry conversation</button>}</div>}
          {notice && <p className="sa-support-notice" role="status">{notice}</p>}
          {loadingChat && !ticket ? <div className="sa-support-empty" role="status">Loading conversation…</div> : !ticket ? <div className="sa-support-empty"><MessageSquare size={32} /><p>Select a ticket to view the conversation.</p></div> : <>
            <header className="sa-support-chat-header"><div><span>{ticket.ticketId} · {ticket.companyId?.name}</span><h2>{ticket.subject}</h2><p>{ticket.companyId?.email}</p></div><label>Status<select aria-label="Ticket status" value={ticket.status} disabled={busy} onChange={event => save('status', event.target.value)}>{statuses.map(status => <option key={status}>{status}</option>)}</select></label></header>
            <div className="sa-support-messages" ref={conversation} role="log" aria-label="Chat messages" aria-live="polite">
              {ticket.messages?.length ? ticket.messages.map((message, index) => <article key={message._id || index} className={`sa-support-message${message.senderRole === 'superadmin' ? ' from-admin' : ''}`}><div><strong>{message.senderName}</strong><span>{message.senderRole === 'superadmin' ? 'Super Admin' : 'Company'}</span></div><p>{message.message}</p><footer className="sa-support-message-footer"><time dateTime={message.createdAt}>{formatTime(message.createdAt)}</time>{message.senderRole === 'superadmin' && <span className={`sa-support-receipt${message.readAt ? ' is-read' : ''}`} aria-label={message.readAt ? 'Read' : 'Sent'} title={message.readAt ? `Read ${formatTime(message.readAt)}` : 'Sent, not read yet'}>{message.readAt ? <CheckCheck size={18} aria-hidden="true" /> : <Check size={16} aria-hidden="true" />}</span>}</footer></article>) : <article className="sa-support-message"><p>{ticket.description}</p></article>}
            </div>
            {ticket.status === 'Closed' ? <p className="sa-support-closed">This ticket is closed. Change its status to Open to continue the conversation.</p> : <form className="sa-support-composer" onSubmit={event => { event.preventDefault(); save('messages', reply); }}><label htmlFor="sa-support-reply">Reply to {ticket.companyId?.name || 'company'}</label><textarea id="sa-support-reply" placeholder="Write your reply…" rows={3} maxLength={10000} value={reply} disabled={busy} onChange={event => setReply(event.target.value)} /><div><span>{reply.length.toLocaleString()} / 10,000</span><button type="submit" disabled={busy || !reply.trim()}><Send size={15} />{busy ? 'Sending…' : 'Send reply'}</button></div></form>}
          </>}
        </section>
      </div>
    </div>
  );
}
