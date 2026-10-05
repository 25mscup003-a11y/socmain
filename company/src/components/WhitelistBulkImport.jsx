import React, { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import api from '../api/axios';
import { MAX_WHITELIST_IMPORT, parseWhitelistImport } from '../utils/whitelistImport';
import './WhitelistBulkImport.css';

const typeNames = { ip: 'IP address', cidr: 'CIDR range', domain: 'Domain' };
const statusNames = { ready: 'Ready', invalid: 'Invalid', duplicate: 'Duplicate — skipped', existing: 'Already whitelisted — skipped', importing: 'Importing…', imported: 'Imported', failed: 'Failed' };

export default function WhitelistBulkImport({ existingEntries, onClose, onImported }) {
  const dialogRef = useRef(null);
  const running = useRef(false);
  const [input, setInput] = useState('');
  const [reason, setReason] = useState('');
  const [results, setResults] = useState({});
  const [busy, setBusy] = useState(false);
  const [finished, setFinished] = useState(false);
  const preview = useMemo(() => parseWhitelistImport(input, existingEntries), [input, existingEntries]);
  const rows = preview.rows.map(row => ({ ...row, ...results[row.id] }));
  const invalid = rows.filter(row => row.status === 'invalid').length;
  const imported = rows.filter(row => row.status === 'imported').length;
  const failed = rows.filter(row => row.status === 'failed').length;
  const skipped = rows.filter(row => ['existing', 'duplicate'].includes(row.status)).length;
  const eligible = rows.filter(row => ['ready', 'failed'].includes(row.status));

  useEffect(() => {
    const dialog = dialogRef.current;
    const opener = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    dialog.showModal();
    dialog.querySelector('textarea')?.focus({ preventScroll: true });
    document.body.style.overflow = 'hidden';
    return () => { dialog.close(); document.body.style.overflow = previousOverflow; if (opener?.isConnected) opener.focus({ preventScroll: true }); };
  }, []);

  const close = () => { if (!running.current) onClose(); };
  const importEntries = async event => {
    event.preventDefault();
    if (running.current || invalid || preview.tooMany || !eligible.length) return;
    running.current = true;
    setBusy(true); setFinished(false);
    try {
      // Keep the existing authenticated whitelist endpoint, with bounded work
      // and a result per entry so one failure never hides successful imports.
      for (let start = 0; start < eligible.length; start += 3) {
        await Promise.all(eligible.slice(start, start + 3).map(async row => {
          setResults(current => ({ ...current, [row.id]: { status: 'importing' } }));
          try {
            const { data } = await api.post('/ips-proxy/whitelist', { value: row.value, type: row.type, reason: reason.trim() || 'Bulk import' });
            if (data?.ok === false || data?.success === false) throw new Error(data.message || data.error || 'Import rejected');
            setResults(current => ({ ...current, [row.id]: { status: 'imported' } }));
          } catch (error) {
            const message = error.response?.data?.message || error.response?.data?.error || error.message || 'Import failed. Retry this entry.';
            setResults(current => ({ ...current, [row.id]: { status: 'failed', error: String(message) } }));
          }
        }));
      }
      await onImported();
    } finally {
      running.current = false;
      setBusy(false); setFinished(true);
    }
  };

  const editInput = value => { setInput(value); setResults({}); setFinished(false); };

  return createPortal(<dialog ref={dialogRef} className="whitelist-import-dialog" aria-labelledby="whitelist-import-title" aria-describedby="whitelist-import-description"
    onCancel={event => { event.preventDefault(); close(); }}
    onClick={event => {
      if (event.target !== event.currentTarget) return;
      const bounds = event.currentTarget.getBoundingClientRect();
      if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) close();
    }}>
    <form onSubmit={importEntries}>
      <header><div><h2 id="whitelist-import-title">Bulk Import Whitelist</h2><p id="whitelist-import-description">Add multiple trusted IPs, CIDR ranges or domains.</p></div>
        <button type="button" aria-label="Close bulk import" onClick={close} disabled={busy}>✕</button></header>
      <div className="whitelist-import-body" aria-busy={busy}>
        <label htmlFor="whitelist-import-values">Entries</label>
        <textarea id="whitelist-import-values" autoFocus rows={6} value={input} onChange={event => editInput(event.target.value)} disabled={busy} maxLength={60000}
          placeholder={'192.168.1.100\n10.0.0.0/8\ntrusted.example.com\n2001:db8::1'} aria-describedby="whitelist-import-help" spellCheck={false} />
        <p id="whitelist-import-help">Separate entries with commas or new lines. Types are detected automatically. Maximum {MAX_WHITELIST_IMPORT} entries per import.</p>
        <label htmlFor="whitelist-import-reason">Reason <span>(optional)</span></label>
        <input id="whitelist-import-reason" value={reason} onChange={event => setReason(event.target.value)} maxLength={500} disabled={busy} placeholder="e.g., Office networks or trusted partners" />
        {preview.tooMany && <p className="whitelist-import-error" role="alert">Too many entries. Keep at most {MAX_WHITELIST_IMPORT} entries in one import.</p>}
        {invalid > 0 && <p className="whitelist-import-error" role="alert">Correct {invalid} invalid {invalid === 1 ? 'entry' : 'entries'} before importing.</p>}
        {rows.length > 0 && <>
          <div className="whitelist-import-summary" role="status" aria-live="polite">
            {busy ? `Importing… ${imported + failed} of ${rows.filter(row => !['duplicate', 'existing', 'invalid'].includes(row.status)).length} processed`
              : finished ? `${imported} imported · ${failed} failed · ${skipped} skipped`
                : `${eligible.length} ready · ${invalid} invalid · ${skipped} skipped`}
          </div>
          <div className="whitelist-import-preview"><table><thead><tr><th>Entry</th><th>Type</th><th>Status</th></tr></thead><tbody>
            {rows.map(row => <tr key={row.id}><td><code>{row.value}</code></td><td>{typeNames[row.type] || '—'}</td><td><span className={`whitelist-import-status ${row.status}`}>{statusNames[row.status]}</span>{row.error && <small>{row.error}</small>}</td></tr>)}
          </tbody></table></div>
        </>}
      </div>
      <footer><span>{busy ? 'Keep this popup open until the import finishes.' : failed ? 'Retry sends only failed entries.' : 'Existing and duplicate entries are skipped.'}</span>
        <div><button type="button" onClick={close} disabled={busy}>{finished ? 'Done' : 'Cancel'}</button>
          <button type="submit" className="primary" disabled={busy || invalid > 0 || preview.tooMany || !eligible.length}>{busy ? 'Importing…' : finished && failed ? `Retry ${failed} failed` : `Import${eligible.length ? ` ${eligible.length}` : ''} entries`}</button></div>
      </footer>
    </form>
  </dialog>, document.body);
}
