export default function PaginationControls({ page, total, pageSize = 6, onPageChange, ariaLabel = 'Staff table pagination' }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (!total) return null;
  const currentPage = Math.min(Math.max(1, page), totalPages);
  const start = (currentPage - 1) * pageSize + 1;
  const end = Math.min(currentPage * pageSize, total);
  const buttonStyle = disabled => ({
    padding: '7px 13px', borderRadius: 7, border: '1px solid #1e3a5f',
    background: disabled ? '#08111f' : '#0c1a2e', color: disabled ? '#64748b' : '#93c5fd',
    cursor: disabled ? 'not-allowed' : 'pointer', fontSize: 12, fontWeight: 700,
  });

  return (
    <nav aria-label={ariaLabel} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginTop: 14, padding: '10px 12px', background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 9 }}>
      <span style={{ color: '#94a3b8', fontSize: 12 }}>Showing {start}–{end} of {total} · {pageSize} per page</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <button type="button" disabled={currentPage === 1} onClick={() => onPageChange(currentPage - 1)} style={buttonStyle(currentPage === 1)}>← Previous</button>
        <span aria-live="polite" style={{ color: '#94a3b8', fontSize: 12, minWidth: 72, textAlign: 'center' }}>Page {currentPage} / {totalPages}</span>
        <button type="button" disabled={currentPage === totalPages} onClick={() => onPageChange(currentPage + 1)} style={buttonStyle(currentPage === totalPages)}>Next →</button>
      </div>
    </nav>
  );
}
