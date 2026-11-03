import { useState, useEffect } from 'react';

export default function AuditLogExplorer({ operatorToken }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [targetAgentFilter, setTargetAgentFilter] = useState('');

  // Selected entry for modal view
  const [selectedLog, setSelectedLog] = useState(null);

  const activeToken = operatorToken || sessionStorage.getItem('rmm_operator_token') || 'rmm_admin_dev_token_2026';

  const fetchLogs = (customAction = actionFilter) => {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${activeToken}`,
    };
    const params = new URLSearchParams();
    if (searchTerm.trim()) params.append('search', searchTerm.trim());
    if (customAction.trim()) params.append('action', customAction.trim());
    if (targetAgentFilter.trim()) params.append('target_agent_id', targetAgentFilter.trim());
    params.append('limit', '150');

    fetch(`/api/v1/audit-logs?${params.toString()}`, { headers })
      .then(async (res) => {
        if (!res.ok) {
          if (res.status === 403) {
            throw new Error('Access denied: Audit log inspection requires audit:read permission (SuperAdmin or Auditor).');
          }
          throw new Error(`Failed to fetch audit logs (HTTP ${res.status})`);
        }
        const data = await res.json();
        setLogs(data);
        setError(null);
      })
      .catch((err) => {
        setError(err.message);
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    let cancelled = false;
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${activeToken}`,
    };
    const params = new URLSearchParams();
    if (actionFilter.trim()) params.append('action', actionFilter.trim());
    params.append('limit', '150');

    fetch(`/api/v1/audit-logs?${params.toString()}`, { headers })
      .then(async (res) => {
        if (cancelled) return;
        if (!res.ok) {
          if (res.status === 403) {
            throw new Error('Access denied: Audit log inspection requires audit:read permission (SuperAdmin or Auditor).');
          }
          throw new Error(`Failed to fetch audit logs (HTTP ${res.status})`);
        }
        const data = await res.json();
        setLogs(data);
        setError(null);
      })
      .catch((err) => {
        if (!cancelled) setError(err.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeToken, actionFilter]);

  const handleFilterSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    fetchLogs();
  };

  const handleClearFilters = () => {
    setSearchTerm('');
    setActionFilter('');
    setTargetAgentFilter('');
    setLoading(true);
    fetchLogs('');
  };

  return (
    <div style={{ padding: '24px', maxWidth: '1300px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827', margin: 0 }}>
            Immutable Audit Log Explorer
          </h2>
          <p style={{ color: '#6b7280', fontSize: '14px', margin: '4px 0 0 0' }}>
            Append-only security ledger tracking operator actions, target agents, commands, and cryptographic SHA-256 output digests.
          </p>
        </div>
        <button
          onClick={() => {
            setLoading(true);
            fetchLogs();
          }}
          style={{
            backgroundColor: '#f3f4f6',
            color: '#374151',
            border: '1px solid #d1d5db',
            padding: '8px 14px',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '13px',
            fontWeight: '500',
          }}
        >
          ↻ Refresh Logs
        </button>
      </div>

      {/* Filter Toolbar */}
      <form
        onSubmit={handleFilterSubmit}
        style={{
          backgroundColor: 'white',
          padding: '16px',
          borderRadius: '8px',
          boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
          marginBottom: '20px',
          display: 'flex',
          gap: '12px',
          alignItems: 'center',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ flex: 1, minWidth: '220px' }}>
          <input
            type="text"
            placeholder="Search command, action, username..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #d1d5db',
              fontSize: '13px',
            }}
          />
        </div>

        <div style={{ width: '200px' }}>
          <select
            value={actionFilter}
            onChange={(e) => setActionFilter(e.target.value)}
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #d1d5db',
              fontSize: '13px',
              backgroundColor: 'white',
            }}
          >
            <option value="">All Actions</option>
            <option value="WS_TASK_COMPLETE">WS_TASK_COMPLETE</option>
            <option value="WS_TASK_DISPATCH">WS_TASK_DISPATCH</option>
            <option value="WS_TERM_IN">WS_TERM_IN</option>
            <option value="WS_DISPATCH_DENIED">WS_DISPATCH_DENIED</option>
            <option value="POST /api/v1/agents">REST Agent Task Dispatch</option>
            <option value="POST /api/v1/scripts">REST Script Actions</option>
          </select>
        </div>

        <div style={{ width: '220px' }}>
          <input
            type="text"
            placeholder="Filter by Agent UUID..."
            value={targetAgentFilter}
            onChange={(e) => setTargetAgentFilter(e.target.value)}
            style={{
              width: '100%',
              boxSizing: 'border-box',
              padding: '8px 12px',
              borderRadius: '6px',
              border: '1px solid #d1d5db',
              fontSize: '13px',
            }}
          />
        </div>

        <button
          type="submit"
          style={{
            backgroundColor: '#2563eb',
            color: 'white',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '6px',
            fontSize: '13px',
            fontWeight: '600',
            cursor: 'pointer',
          }}
        >
          Filter
        </button>

        <button
          type="button"
          onClick={handleClearFilters}
          style={{
            backgroundColor: '#f3f4f6',
            color: '#4b5563',
            border: '1px solid #d1d5db',
            padding: '8px 14px',
            borderRadius: '6px',
            fontSize: '13px',
            cursor: 'pointer',
          }}
        >
          Clear
        </button>
      </form>

      {error && (
        <div style={{ backgroundColor: '#fef2f2', border: '1px solid #ef4444', color: '#991b1b', padding: '12px 16px', borderRadius: '6px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Audit Log Table */}
      <div style={{ backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f9fafb', borderBottom: '1px solid #e5e7eb', color: '#4b5563' }}>
              <th style={{ padding: '12px 14px' }}>Timestamp</th>
              <th style={{ padding: '12px 14px' }}>Operator</th>
              <th style={{ padding: '12px 14px' }}>Target Agent</th>
              <th style={{ padding: '12px 14px' }}>Action</th>
              <th style={{ padding: '12px 14px' }}>Command Text</th>
              <th style={{ padding: '12px 14px' }}>Output Hash (SHA-256)</th>
              <th style={{ padding: '12px 14px', textAlign: 'center' }}>Status</th>
              <th style={{ padding: '12px 14px', textAlign: 'right' }}>Details</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="8" style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>
                  Loading immutable audit trail...
                </td>
              </tr>
            ) : logs.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>
                  No audit log entries matching criteria.
                </td>
              </tr>
            ) : (
              logs.map((log) => {
                const isSuccess = log.status_code >= 200 && log.status_code < 300;
                return (
                  <tr key={log.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                    <td style={{ padding: '12px 14px', whiteSpace: 'nowrap', color: '#6b7280' }}>
                      {new Date(log.created_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <div style={{ fontWeight: '600', color: '#111827' }}>{log.admin_username}</div>
                      <div style={{ fontSize: '11px', color: '#6b7280' }}>{log.admin_role}</div>
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'monospace', fontSize: '12px' }}>
                      {log.target_agent_id ? (
                        <span title={log.target_agent_id} style={{ color: '#2563eb' }}>
                          {log.target_agent_id.slice(0, 8)}...
                        </span>
                      ) : (
                        <span style={{ color: '#9ca3af' }}>—</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 14px' }}>
                      <span
                        style={{
                          backgroundColor: '#f1f5f9',
                          color: '#334155',
                          padding: '2px 6px',
                          borderRadius: '4px',
                          fontFamily: 'monospace',
                          fontSize: '11px',
                          fontWeight: '600',
                        }}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace' }}>
                      <span title={log.command_text}>
                        {log.command_text || '—'}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', fontFamily: 'monospace', fontSize: '11px' }}>
                      <span title={log.output_hash} style={{ color: '#047857' }}>
                        {log.output_hash ? `${log.output_hash.slice(0, 10)}...${log.output_hash.slice(-6)}` : '—'}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'center' }}>
                      <span
                        style={{
                          backgroundColor: isSuccess ? '#dcfce7' : '#fee2e2',
                          color: isSuccess ? '#15803d' : '#b91c1c',
                          padding: '2px 6px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: '600',
                        }}
                      >
                        {log.status_code}
                      </span>
                    </td>
                    <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                      <button
                        onClick={() => setSelectedLog(log)}
                        style={{
                          backgroundColor: '#e0e7ff',
                          color: '#3730a3',
                          border: 'none',
                          padding: '4px 8px',
                          borderRadius: '4px',
                          fontSize: '12px',
                          cursor: 'pointer',
                          fontWeight: '500',
                        }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Audit Log Inspect Modal */}
      {selectedLog && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 50,
          }}
        >
          <div
            style={{
              backgroundColor: 'white',
              borderRadius: '8px',
              padding: '24px',
              width: '100%',
              maxWidth: '680px',
              maxHeight: '90vh',
              overflowY: 'auto',
              boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid #e5e7eb', paddingBottom: '12px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 'bold' }}>
                  Audit Record Details
                </h3>
                <span style={{ fontSize: '12px', color: '#6b7280', fontFamily: 'monospace' }}>
                  ID: {selectedLog.id}
                </span>
              </div>
              <button
                onClick={() => setSelectedLog(null)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  fontSize: '20px',
                  cursor: 'pointer',
                  color: '#9ca3af',
                }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', fontSize: '13px', marginBottom: '16px' }}>
              <div>
                <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase' }}>Operator</span>
                <strong>{selectedLog.admin_username}</strong> ({selectedLog.admin_role})
                <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#9ca3af' }}>ID: {selectedLog.admin_id}</div>
              </div>
              <div>
                <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase' }}>Target Agent</span>
                <span style={{ fontFamily: 'monospace' }}>{selectedLog.target_agent_id || 'None (Global / Server)'}</span>
              </div>
              <div>
                <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase' }}>HTTP Route</span>
                <code>{selectedLog.method} {selectedLog.path}</code>
              </div>
              <div>
                <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase' }}>Recorded At</span>
                <span>{new Date(selectedLog.created_at).toLocaleString()}</span>
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase', marginBottom: '4px' }}>
                Dispatched Command / Payload Text
              </span>
              <pre
                style={{
                  backgroundColor: '#111827',
                  color: '#f3f4f6',
                  padding: '12px',
                  borderRadius: '6px',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                  overflowX: 'auto',
                  margin: 0,
                  whiteSpace: 'pre-wrap',
                }}
              >
                {selectedLog.command_text || '(Empty command text)'}
              </pre>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase', marginBottom: '4px' }}>
                Cryptographic Output Digest (SHA-256)
              </span>
              <div
                style={{
                  backgroundColor: '#f0fdf4',
                  border: '1px solid #bbf7d0',
                  color: '#166534',
                  padding: '10px 12px',
                  borderRadius: '6px',
                  fontFamily: 'monospace',
                  fontSize: '12px',
                  wordBreak: 'break-all',
                }}
              >
                {selectedLog.output_hash}
              </div>
            </div>

            {selectedLog.details && (
              <div style={{ marginBottom: '16px' }}>
                <span style={{ color: '#6b7280', display: 'block', fontSize: '11px', textTransform: 'uppercase', marginBottom: '4px' }}>
                  Structured Execution Metadata
                </span>
                <pre
                  style={{
                    backgroundColor: '#f8fafc',
                    border: '1px solid #e2e8f0',
                    color: '#334155',
                    padding: '10px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontFamily: 'monospace',
                    overflowX: 'auto',
                    margin: 0,
                  }}
                >
                  {JSON.stringify(selectedLog.details, null, 2)}
                </pre>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '16px' }}>
              <button
                onClick={() => setSelectedLog(null)}
                style={{
                  backgroundColor: '#3b82f6',
                  color: 'white',
                  border: 'none',
                  padding: '8px 16px',
                  borderRadius: '6px',
                  cursor: 'pointer',
                  fontWeight: '600',
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
