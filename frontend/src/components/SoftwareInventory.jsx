import { useState, useEffect, useCallback } from 'react';

export default function SoftwareInventory({ agentId, operatorToken }) {
  const [software, setSoftware] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [refreshTick, setRefreshTick] = useState(0);

  const fetchSoftware = useCallback(
    async (signal) => {
      if (!agentId) return;

      const activeToken =
        operatorToken ||
        sessionStorage.getItem('rmm_operator_token') ||
        '';

      const params = new URLSearchParams();
      if (searchQuery.trim()) {
        params.set('search', searchQuery.trim());
      }
      const queryString = params.toString();
      const url = `/api/v1/agents/${encodeURIComponent(agentId)}/software${
        queryString ? `?${queryString}` : ''
      }`;

      setLoading(true);
      try {
        const response = await fetch(url, {
          headers: {
            Authorization: `Bearer ${activeToken}`,
          },
          signal,
        });
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data = await response.json();
        setSoftware(Array.isArray(data) ? data : []);
        setError(null);
      } catch (err) {
        if (err.name !== 'AbortError') {
          setError(err.message);
        }
      } finally {
        if (!signal?.aborted) {
          setLoading(false);
        }
      }
    },
    [agentId, operatorToken, searchQuery]
  );

  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      fetchSoftware(controller.signal);
    }, 200);

    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [fetchSoftware, refreshTick]);

  return (
    <div
      style={{
        backgroundColor: '#ffffff',
        borderRadius: '8px',
        padding: '20px',
        border: '1px solid #e5e7eb',
        boxShadow: '0 1px 3px rgba(0,0,0,0.05)',
        marginBottom: '20px',
      }}
    >
      {/* Header & Search Controls */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          marginBottom: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <h3 style={{ margin: 0, fontSize: '18px', color: '#111827' }}>
            Installed Software Inventory
          </h3>
          <span
            style={{
              backgroundColor: '#e5e7eb',
              color: '#374151',
              fontSize: '12px',
              fontWeight: 'bold',
              padding: '2px 8px',
              borderRadius: '9999px',
            }}
          >
            {software.length} {software.length === 1 ? 'package' : 'packages'}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search name, publisher, or version..."
            style={{
              padding: '7px 12px',
              borderRadius: '6px',
              border: '1px solid #d1d5db',
              fontSize: '13px',
              minWidth: '260px',
              outline: 'none',
            }}
          />
          <button
            type="button"
            onClick={() => setRefreshTick((prev) => prev + 1)}
            disabled={loading}
            style={{
              padding: '7px 12px',
              borderRadius: '6px',
              border: '1px solid #d1d5db',
              backgroundColor: '#f9fafb',
              color: '#374151',
              fontSize: '13px',
              fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
            }}
          >
            {loading ? 'Syncing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && (
        <div
          style={{
            color: '#dc2626',
            backgroundColor: '#fee2e2',
            padding: '8px 12px',
            borderRadius: '6px',
            fontSize: '13px',
            marginBottom: '12px',
          }}
        >
          Error loading software inventory: {error}
        </div>
      )}

      {/* Scrollable Software Catalog Table */}
      <div
        style={{
          maxHeight: '300px',
          overflowY: 'auto',
          border: '1px solid #e5e7eb',
          borderRadius: '6px',
        }}
      >
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: '13px',
          }}
        >
          <thead>
            <tr
              style={{
                backgroundColor: '#f9fafb',
                color: '#374151',
                textAlign: 'left',
                position: 'sticky',
                top: 0,
                borderBottom: '1px solid #e5e7eb',
              }}
            >
              <th style={{ padding: '10px 12px' }}>Application / Package</th>
              <th style={{ padding: '10px 12px' }}>Version</th>
              <th style={{ padding: '10px 12px' }}>Publisher / Maintainer</th>
              <th style={{ padding: '10px 12px' }}>Install Date</th>
            </tr>
          </thead>
          <tbody>
            {software.map((item) => (
              <tr
                key={item.id || `${item.name}-${item.version}`}
                style={{ borderBottom: '1px solid #f3f4f6' }}
              >
                <td style={{ padding: '9px 12px', fontWeight: 600, color: '#111827' }}>
                  {item.name}
                </td>
                <td
                  style={{
                    padding: '9px 12px',
                    fontFamily: 'monospace',
                    color: '#2563eb',
                  }}
                >
                  {item.version || 'N/A'}
                </td>
                <td style={{ padding: '9px 12px', color: '#4b5563' }}>
                  {item.publisher || 'Unknown'}
                </td>
                <td style={{ padding: '9px 12px', color: '#6b7280' }}>
                  {item.install_date || '—'}
                </td>
              </tr>
            ))}

            {software.length === 0 && !loading && (
              <tr>
                <td
                  colSpan="4"
                  style={{
                    padding: '24px',
                    textAlign: 'center',
                    color: '#9ca3af',
                  }}
                >
                  {searchQuery.trim()
                    ? 'No installed packages match your search filter.'
                    : 'No software inventory synchronized for this endpoint yet.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
