import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import AgentInventory from './components/AgentInventory';
import HostDetails from './components/HostDetails';
import UserManagement from './components/UserManagement';
import RolePermissions from './components/RolePermissions';
import AuditLogExplorer from './components/AuditLogExplorer';

const DEFAULT_DEV_TOKEN = 'rmm_admin_dev_token_2026';

function NavItem({ to, label, icon }) {
  const location = useLocation();
  const isActive = location.pathname.startsWith(to);

  return (
    <Link
      to={to}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        padding: '10px 12px',
        borderRadius: '6px',
        color: isActive ? '#ffffff' : '#9ca3af',
        backgroundColor: isActive ? '#374151' : 'transparent',
        textDecoration: 'none',
        fontSize: '14px',
        fontWeight: isActive ? '600' : '500',
        transition: 'background-color 0.15s ease',
      }}
    >
      <span>{icon}</span>
      <span>{label}</span>
    </Link>
  );
}

function App() {
  const [operatorToken, setOperatorToken] = useState(() => {
    return sessionStorage.getItem('rmm_operator_token') || DEFAULT_DEV_TOKEN;
  });

  const [principal, setPrincipal] = useState(null);

  useEffect(() => {
    const fetchPrincipal = async () => {
      try {
        const res = await fetch('/api/v1/users/me', {
          headers: {
            Authorization: `Bearer ${operatorToken}`,
          },
        });
        if (res.ok) {
          const data = await res.json();
          setPrincipal(data);
        } else {
          setPrincipal(null);
        }
      } catch {
        setPrincipal(null);
      }
    };

    fetchPrincipal();
  }, [operatorToken]);

  const handleTokenChange = (e) => {
    const nextToken = e.target.value;
    setOperatorToken(nextToken);
    sessionStorage.setItem('rmm_operator_token', nextToken);
  };

  return (
    <BrowserRouter>
      <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: '#f3f4f6' }}>
        {/* Management Sidebar */}
        <div
          style={{
            width: '260px',
            background: '#111827',
            color: 'white',
            padding: '24px 16px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
            borderRight: '1px solid #1f2937',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '28px', padding: '0 8px' }}>
              <div
                style={{
                  width: '32px',
                  height: '32px',
                  backgroundColor: '#2563eb',
                  borderRadius: '6px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontWeight: 'bold',
                  fontSize: '16px',
                }}
              >
                T
              </div>
              <div>
                <h2 style={{ fontSize: '16px', margin: 0, fontWeight: 'bold', letterSpacing: '-0.3px' }}>
                  Tactical RMM
                </h2>
                <span style={{ fontSize: '11px', color: '#9ca3af' }}>Control Plane v1.0</span>
              </div>
            </div>

            {/* Navigation links */}
            <nav style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#6b7280', fontWeight: 'bold', padding: '8px 12px 4px 12px', letterSpacing: '0.05em' }}>
                Fleet Operations
              </div>
              <NavItem to="/agents" label="Agent Inventory" icon="💻" />

              <div style={{ fontSize: '11px', textTransform: 'uppercase', color: '#6b7280', fontWeight: 'bold', padding: '16px 12px 4px 12px', letterSpacing: '0.05em' }}>
                Administration & RBAC
              </div>
              <NavItem to="/users" label="User Management" icon="👥" />
              <NavItem to="/roles" label="Role Permissions" icon="🛡️" />
              <NavItem to="/audit" label="Audit Log Explorer" icon="📜" />
            </nav>
          </div>

          <div>
            {/* Operator Identity Badge */}
            {principal && (
              <div
                style={{
                  backgroundColor: '#1f2937',
                  borderRadius: '6px',
                  padding: '10px 12px',
                  marginBottom: '16px',
                  fontSize: '12px',
                  border: '1px solid #374151',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                  <span style={{ fontWeight: '600', color: '#f9fafb' }}>{principal.username}</span>
                  <span
                    style={{
                      fontSize: '10px',
                      padding: '2px 6px',
                      borderRadius: '8px',
                      backgroundColor:
                        principal.role === 'SuperAdmin' ? '#7c3aed' : principal.role === 'SiteTechnician' ? '#2563eb' : '#059669',
                      color: 'white',
                      fontWeight: 'bold',
                    }}
                  >
                    {principal.role}
                  </span>
                </div>
                <div style={{ color: '#9ca3af', fontSize: '11px' }}>
                  Scope: {principal.site_id ? 'Assigned Site' : principal.org_id ? 'Assigned Org' : 'Global Admin'}
                </div>
              </div>
            )}

            {/* Operator API Token input */}
            <div style={{ borderTop: '1px solid #374151', paddingTop: '15px' }}>
              <label
                htmlFor="operator-token-input"
                style={{ display: 'block', fontSize: '11px', color: '#9ca3af', marginBottom: '6px', textTransform: 'uppercase', fontWeight: '600' }}
              >
                Operator Bearer Token
              </label>
              <input
                id="operator-token-input"
                type="password"
                value={operatorToken}
                onChange={handleTokenChange}
                placeholder="Enter operator token..."
                style={{
                  width: '100%',
                  boxSizing: 'border-box',
                  padding: '7px 10px',
                  borderRadius: '6px',
                  border: '1px solid #4b5563',
                  backgroundColor: '#111827',
                  color: '#f9fafb',
                  fontSize: '12px',
                  fontFamily: 'monospace',
                }}
              />
            </div>
          </div>
        </div>

        {/* Main Workspace Display */}
        <main style={{ flex: 1, overflowY: 'auto', minHeight: '100vh' }}>
          <Routes>
            <Route path="/" element={<Navigate to="/agents" replace />} />
            <Route path="/agents" element={<AgentInventory operatorToken={operatorToken} />} />
            <Route path="/agents/:id" element={<HostDetails operatorToken={operatorToken} />} />
            <Route path="/users" element={<UserManagement operatorToken={operatorToken} />} />
            <Route path="/roles" element={<RolePermissions operatorToken={operatorToken} />} />
            <Route path="/audit" element={<AuditLogExplorer operatorToken={operatorToken} />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
