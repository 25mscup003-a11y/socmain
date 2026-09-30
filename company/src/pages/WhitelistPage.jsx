import React, { useEffect, useState, useCallback } from 'react';
import api from '../api/axios';
import { useToast, Spinner, PageLoader, ErrorBanner } from '../components/Toast';

/**
 * Whitelist Management Page
 * Manage IP addresses and domains that should NOT be blocked by IPS
 */

function WhitelistPage() {
  const { showToast } = useToast();

  // ── State ──────────────────────────────────────────────────────────────────
  const [whitelist, setWhitelist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Form state
  const [newEntry, setNewEntry] = useState({
    value: '',
    type: 'IP', // IP | Domain
    reason: '',
  });
  const [submitting, setSubmitting] = useState(false);

  // ── Fetch Whitelist ────────────────────────────────────────────────────────
  const fetchWhitelist = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await api.get('http://localhost:5050/whitelist', {
        withCredentials: false,
      });

      const data = response.data || {};
      setWhitelist(data.whitelist || []);
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to fetch whitelist';
      setError(msg);
      showToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  }, [showToast]);

  useEffect(() => {
    fetchWhitelist();
  }, [fetchWhitelist]);

  // ── Add to Whitelist ───────────────────────────────────────────────────────
  const handleAdd = async (e) => {
    e.preventDefault();

    if (!newEntry.value.trim()) {
      showToast('Please enter IP or domain', 'error');
      return;
    }

    try {
      setSubmitting(true);

      const response = await api.post('http://localhost:5050/whitelist', newEntry, {
        withCredentials: false,
      });

      showToast('✅ Added to whitelist', 'success');
      setNewEntry({ value: '', type: 'IP', reason: '' });

      // Refresh list
      await fetchWhitelist();
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to add to whitelist';
      showToast(msg, 'error');
    } finally {
      setSubmitting(false);
    }
  };

  // ── Remove from Whitelist ──────────────────────────────────────────────────
  const handleRemove = async (value) => {
    if (!window.confirm(`Remove "${value}" from whitelist?`)) return;

    try {
      await api.delete(`http://localhost:5050/whitelist/${encodeURIComponent(value)}`, {
        withCredentials: false,
      });

      showToast('✅ Removed from whitelist', 'success');
      await fetchWhitelist();
    } catch (err) {
      const msg = err.response?.data?.error || err.message || 'Failed to remove';
      showToast(msg, 'error');
    }
  };

  if (loading) return <PageLoader />;
  if (error && !whitelist.length) return <ErrorBanner error={error} onRetry={fetchWhitelist} />;

  return (
    <div style={{ padding: '20px', maxWidth: '1200px', margin: '0 auto' }}>
      {/* Header */}
      <div style={{ marginBottom: '30px' }}>
        <h1 style={{ fontSize: '28px', fontWeight: 'bold', color: '#fff', margin: 0 }}>
          ✅ Whitelist Management
        </h1>
        <p style={{ color: '#999', marginTop: '8px' }}>
          Manage IPs and domains that should never be blocked by the IPS system
        </p>
      </div>

      {/* Add New Entry Form */}
      <div
        style={{
          background: 'linear-gradient(135deg, #0c1a2e 0%, #1a2a3e 100%)',
          border: '2px solid #34d39922',
          borderRadius: '12px',
          padding: '24px',
          marginBottom: '30px',
        }}
      >
        <h2 style={{ fontSize: '18px', fontWeight: 'bold', margin: '0 0 16px 0', color: '#34d399' }}>
          ➕ Add Entry to Whitelist
        </h2>

        <form onSubmit={handleAdd}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr auto', gap: '12px' }}>
            {/* Value Input */}
            <input
              type="text"
              placeholder="IP address or domain..."
              value={newEntry.value}
              onChange={(e) => setNewEntry({ ...newEntry, value: e.target.value })}
              style={{
                padding: '10px 12px',
                background: '#0a0f1a',
                border: '1px solid #34d39944',
                borderRadius: '6px',
                color: '#fff',
                fontSize: '14px',
              }}
            />

            {/* Type Selector */}
            <select
              value={newEntry.type}
              onChange={(e) => setNewEntry({ ...newEntry, type: e.target.value })}
              style={{
                padding: '10px 12px',
                background: '#0a0f1a',
                border: '1px solid #34d39944',
                borderRadius: '6px',
                color: '#fff',
                fontSize: '14px',
              }}
            >
              <option value="IP">IP Address</option>
              <option value="Domain">Domain</option>
            </select>

            {/* Reason Input */}
            <input
              type="text"
              placeholder="Reason (optional)..."
              value={newEntry.reason}
              onChange={(e) => setNewEntry({ ...newEntry, reason: e.target.value })}
              style={{
                padding: '10px 12px',
                background: '#0a0f1a',
                border: '1px solid #34d39944',
                borderRadius: '6px',
                color: '#fff',
                fontSize: '14px',
              }}
            />

            {/* Submit Button */}
            <button
              type="submit"
              disabled={submitting || !newEntry.value.trim()}
              style={{
                padding: '10px 20px',
                background: submitting ? '#34d39955' : '#34d399',
                border: 'none',
                borderRadius: '6px',
                color: '#0c1a2e',
                fontWeight: 'bold',
                cursor: submitting ? 'not-allowed' : 'pointer',
                opacity: submitting || !newEntry.value.trim() ? 0.5 : 1,
                transition: 'all 0.2s',
              }}
              onMouseOver={(e) => {
                if (!submitting && newEntry.value.trim()) {
                  e.currentTarget.opacity = 0.9;
                  e.currentTarget.transform = 'scale(1.02)';
                }
              }}
            >
              {submitting ? <Spinner small /> : '➕ Add'}
            </button>
          </div>
        </form>
      </div>

      {/* Whitelist Table */}
      <div
        style={{
          background: 'linear-gradient(135deg, #0c1a2e 0%, #1a2a3e 100%)',
          border: '2px solid #3b82f622',
          borderRadius: '12px',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '150px 1fr 2fr 150px',
            gap: '16px',
            padding: '16px 20px',
            background: '#0a0f1a',
            borderBottom: '1px solid #3b82f633',
            fontWeight: 'bold',
            color: '#3b82f6',
            fontSize: '14px',
          }}
        >
          <div>Type</div>
          <div>Value</div>
          <div>Reason</div>
          <div style={{ textAlign: 'right' }}>Action</div>
        </div>

        {whitelist.length === 0 ? (
          <div
            style={{
              padding: '40px 20px',
              textAlign: 'center',
              color: '#666',
              fontSize: '14px',
            }}
          >
            🎉 No entries — everything will be checked!
          </div>
        ) : (
          whitelist.map((entry, idx) => (
            <div
              key={idx}
              style={{
                display: 'grid',
                gridTemplateColumns: '150px 1fr 2fr 150px',
                gap: '16px',
                padding: '16px 20px',
                borderBottom: '1px solid #3b82f622',
                alignItems: 'center',
              }}
            >
              {/* Type Badge */}
              <div>
                <span
                  style={{
                    display: 'inline-block',
                    padding: '4px 8px',
                    background: entry.type === 'IP' ? '#3b82f622' : '#8b5cf622',
                    border: `1px solid ${entry.type === 'IP' ? '#3b82f6' : '#8b5cf6'}`,
                    borderRadius: '4px',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    color: entry.type === 'IP' ? '#3b82f6' : '#8b5cf6',
                  }}
                >
                  {entry.type}
                </span>
              </div>

              {/* Value */}
              <div style={{ color: '#fff', fontFamily: 'monospace', fontSize: '13px' }}>
                {entry.value}
              </div>

              {/* Reason */}
              <div style={{ color: '#888', fontSize: '13px' }}>
                {entry.reason || <span style={{ color: '#555' }}>—</span>}
              </div>

              {/* Remove Button */}
              <div style={{ textAlign: 'right' }}>
                <button
                  onClick={() => handleRemove(entry.value)}
                  style={{
                    padding: '6px 12px',
                    background: '#ef444422',
                    border: '1px solid #ef4444',
                    borderRadius: '4px',
                    color: '#ef4444',
                    fontSize: '12px',
                    fontWeight: 'bold',
                    cursor: 'pointer',
                    transition: 'all 0.2s',
                  }}
                  onMouseOver={(e) => {
                    e.currentTarget.background = '#ef4444';
                    e.currentTarget.color = '#fff';
                  }}
                  onMouseOut={(e) => {
                    e.currentTarget.background = '#ef444422';
                    e.currentTarget.color = '#ef4444';
                  }}
                >
                  ❌ Remove
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Info Section */}
      <div
        style={{
          marginTop: '30px',
          padding: '20px',
          background: '#1a3a1a22',
          border: '1px solid #34d39944',
          borderRadius: '8px',
          color: '#888',
          fontSize: '14px',
          lineHeight: '1.6',
        }}
      >
        <h4 style={{ color: '#34d399', marginTop: 0 }}>ℹ️ How Whitelist Works:</h4>
        <ul style={{ margin: '8px 0', paddingLeft: '20px' }}>
          <li>When an IP/domain is whitelisted, the agent will <strong>skip blocking</strong> it</li>
          <li>Whitelist is checked before any IPS action takes place</li>
          <li>Both <strong>IP addresses</strong> and <strong>domains</strong> are supported</li>
          <li>Changes take effect immediately across all agents</li>
          <li>Useful for whitelisting office IPs, trusted partners, or critical services</li>
        </ul>
      </div>
    </div>
  );
}

export default WhitelistPage;
