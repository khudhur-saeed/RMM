import { useState, useEffect } from 'react';

const ALL_KNOWN_PERMISSIONS = [
  { name: 'organizations:read', category: 'Tenancy', description: 'View organization profiles & tenants' },
  { name: 'organizations:write', category: 'Tenancy', description: 'Create and modify organizations' },
  { name: 'sites:read', category: 'Tenancy', description: 'View sites within permitted scope' },
  { name: 'sites:write', category: 'Tenancy', description: 'Create and modify sites' },
  { name: 'tokens:read', category: 'Enrollment', description: 'View generated agent enrollment tokens' },
  { name: 'tokens:write', category: 'Enrollment', description: 'Issue single-use agent enrollment tokens' },
  { name: 'agents:read', category: 'Fleet Management', description: 'View agent metadata, inventory & telemetry' },
  { name: 'agents:write', category: 'Fleet Management', description: 'Modify agent configuration or metadata' },
  { name: 'agents:dispatch', category: 'Fleet Management', description: 'Dispatch tasks and commands to agents' },
  { name: 'scripts:read', category: 'Script Keystore', description: 'Inspect stored shell scripts and templates' },
  { name: 'scripts:write', category: 'Script Keystore', description: 'Create, update, and delete stored scripts' },
  { name: 'scripts:execute', category: 'Script Keystore', description: 'Render and dispatch parameterized scripts' },
  { name: 'keys:read', category: 'Cryptographic Security', description: 'Inspect active Ed25519 public keys' },
  { name: 'keys:verify', category: 'Cryptographic Security', description: 'Verify script and payload signatures' },
  { name: 'keys:sign', category: 'Cryptographic Security', description: 'Sign script payloads with private Ed25519 key' },
  { name: 'keys:rotate', category: 'Cryptographic Security', description: 'Rotate server Ed25519 signing keypair' },
  { name: 'ws:connect', category: 'C2 WebSockets', description: 'Establish real-time WebSocket connection to agents' },
  { name: 'ws:dispatch', category: 'C2 WebSockets', description: 'Send terminal input or task frames over WebSocket' },
  { name: 'users:read', category: 'Access Control', description: 'List operator accounts and profile details' },
  { name: 'users:write', category: 'Access Control', description: 'Create operators, rotate tokens, toggle status' },
  { name: 'audit:read', category: 'Access Control', description: 'Inspect immutable security audit logs' },
];

export default function RolePermissions({ operatorToken }) {
  const [roles, setRoles] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [selectedRole, setSelectedRole] = useState('SuperAdmin');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const activeToken = operatorToken || sessionStorage.getItem('rmm_operator_token') || 'rmm_admin_dev_token_2026';

  useEffect(() => {
    let isMounted = true;
    const fetchData = async () => {
      setError(null);
      try {
        const headers = {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${activeToken}`,
        };
        const [meRes, rolesRes] = await Promise.all([
          fetch('/api/v1/users/me', { headers }),
          fetch('/api/v1/users/roles', { headers }),
        ]);

        if (meRes.ok && isMounted) {
          setCurrentUser(await meRes.json());
        }

        if (!rolesRes.ok) {
          throw new Error(`Failed to load roles metadata (HTTP ${rolesRes.status})`);
        }
        const rolesData = await rolesRes.json();
        if (isMounted) {
          setRoles(rolesData);
        }
      } catch (err) {
        if (isMounted) {
          setError(err.message);
        }
      } finally {
        if (isMounted) {
          setLoading(false);
        }
      }
    };

    fetchData();
    return () => {
      isMounted = false;
    };
  }, [activeToken]);

  const activeRoleData = roles.find((r) => r.role === selectedRole) || {
    role: selectedRole,
    description: '',
    permissions: [],
  };

  // Group permissions by category for visual matrix
  const permissionsByCategory = ALL_KNOWN_PERMISSIONS.reduce((acc, perm) => {
    if (!acc[perm.category]) acc[perm.category] = [];
    acc[perm.category].push(perm);
    return acc;
  }, {});

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827', margin: 0 }}>
          Role-Based Access Control (RBAC) Permissions Matrix
        </h2>
        <p style={{ color: '#6b7280', fontSize: '14px', margin: '4px 0 0 0' }}>
          Inspect canonical roles, immutable security boundaries, and effective access rights.
        </p>
      </div>

      {currentUser && (
        <div style={{
          backgroundColor: '#f8fafc',
          border: '1px solid #e2e8f0',
          borderRadius: '8px',
          padding: '12px 16px',
          marginBottom: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '13px',
        }}>
          <div>
            Logged in as: <strong>{currentUser.username}</strong>
            <span style={{
              marginLeft: '8px',
              backgroundColor: '#e0e7ff',
              color: '#3730a3',
              padding: '2px 8px',
              borderRadius: '10px',
              fontWeight: '600',
            }}>
              {currentUser.role}
            </span>
          </div>
          <div style={{ color: '#64748b' }}>
            Granted Permissions: <strong>{currentUser.permissions?.length || 0}</strong>
          </div>
        </div>
      )}

      {error && (
        <div style={{ backgroundColor: '#fef2f2', border: '1px solid #ef4444', color: '#991b1b', padding: '12px 16px', borderRadius: '6px', marginBottom: '16px' }}>
          {error}
        </div>
      )}

      {/* Role Selection Tabs */}
      <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid #e5e7eb', marginBottom: '20px' }}>
        {['SuperAdmin', 'SiteTechnician', 'Auditor'].map((roleName) => {
          const isSelected = selectedRole === roleName;
          const roleObj = roles.find((r) => r.role === roleName);
          return (
            <button
              key={roleName}
              onClick={() => setSelectedRole(roleName)}
              style={{
                padding: '10px 18px',
                border: 'none',
                borderBottom: isSelected ? '2px solid #2563eb' : '2px solid transparent',
                backgroundColor: 'transparent',
                color: isSelected ? '#2563eb' : '#6b7280',
                fontWeight: isSelected ? '600' : '500',
                fontSize: '14px',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span>{roleName}</span>
              {roleObj && (
                <span
                  style={{
                    backgroundColor: isSelected ? '#dbeafe' : '#f3f4f6',
                    color: isSelected ? '#1d4ed8' : '#4b5563',
                    padding: '2px 6px',
                    borderRadius: '10px',
                    fontSize: '11px',
                  }}
                >
                  {roleObj.permissions.length} perms
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Selected Role Summary Card */}
      <div style={{
        backgroundColor: 'white',
        border: '1px solid #e5e7eb',
        borderRadius: '8px',
        padding: '20px',
        marginBottom: '24px',
        boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
          <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 'bold', color: '#111827' }}>
            {activeRoleData.role}
          </h3>
          <span style={{
            fontSize: '12px',
            padding: '2px 8px',
            borderRadius: '12px',
            backgroundColor: selectedRole === 'SuperAdmin' ? '#f3e8ff' : selectedRole === 'SiteTechnician' ? '#dbeafe' : '#dcfce7',
            color: selectedRole === 'SuperAdmin' ? '#6b21a8' : selectedRole === 'SiteTechnician' ? '#1e40af' : '#15803d',
            fontWeight: '600',
          }}>
            {selectedRole === 'SuperAdmin' ? 'Global Admin' : selectedRole === 'SiteTechnician' ? 'Scoped Operator' : 'Compliance & Read-Only'}
          </span>
        </div>
        <p style={{ margin: 0, color: '#4b5563', fontSize: '14px', lineHeight: '1.5' }}>
          {activeRoleData.description || 'Loading role specification...'}
        </p>
      </div>

      {/* Permissions Breakdown Matrix */}
      <div style={{ backgroundColor: 'white', borderRadius: '8px', border: '1px solid #e5e7eb', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f9fafb', borderBottom: '1px solid #e5e7eb', color: '#4b5563' }}>
              <th style={{ padding: '12px 16px', width: '220px' }}>Permission Key</th>
              <th style={{ padding: '12px 16px', width: '160px' }}>Category</th>
              <th style={{ padding: '12px 16px' }}>Description</th>
              <th style={{ padding: '12px 16px', width: '120px', textAlign: 'center' }}>Granted</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="4" style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>
                  Loading permissions matrix...
                </td>
              </tr>
            ) : (
              Object.entries(permissionsByCategory).map(([, items]) => (
                items.map((perm) => {
                  const isGranted = activeRoleData.permissions.includes(perm.name);
                  return (
                    <tr
                      key={perm.name}
                      style={{
                        borderBottom: '1px solid #f3f4f6',
                        backgroundColor: isGranted ? 'transparent' : '#fafafa',
                      }}
                    >
                      <td style={{ padding: '10px 16px', fontFamily: 'monospace', fontWeight: '600', color: isGranted ? '#111827' : '#9ca3af' }}>
                        {perm.name}
                      </td>
                      <td style={{ padding: '10px 16px', color: '#6b7280' }}>
                        {perm.category}
                      </td>
                      <td style={{ padding: '10px 16px', color: isGranted ? '#374151' : '#9ca3af' }}>
                        {perm.description}
                      </td>
                      <td style={{ padding: '10px 16px', textAlign: 'center' }}>
                        {isGranted ? (
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            backgroundColor: '#dcfce7',
                            color: '#15803d',
                            width: '24px',
                            height: '24px',
                            borderRadius: '50%',
                            fontWeight: 'bold',
                            fontSize: '14px',
                          }}>
                            ✓
                          </span>
                        ) : (
                          <span style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            backgroundColor: '#f3f4f6',
                            color: '#9ca3af',
                            width: '24px',
                            height: '24px',
                            borderRadius: '50%',
                            fontSize: '12px',
                          }}>
                            —
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
