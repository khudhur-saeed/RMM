import { useState, useEffect } from 'react';

export default function UserManagement({ operatorToken }) {
  const [users, setUsers] = useState([]);
  const [sites, setSites] = useState([]);
  const [orgs, setOrgs] = useState([]);
  const [currentUser, setCurrentUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Form State for creating a new user
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newUsername, setNewUsername] = useState('');
  const [newEmail, setNewEmail] = useState('');
  const [newRole, setNewRole] = useState('Auditor');
  const [newSiteId, setNewSiteId] = useState('');
  const [newOrgId, setNewOrgId] = useState('');
  const [createdUserToken, setCreatedUserToken] = useState(null);

  // State for token rotation popup
  const [rotatedTokenInfo, setRotatedTokenInfo] = useState(null);

  const activeToken = operatorToken || sessionStorage.getItem('rmm_operator_token') || 'rmm_admin_dev_token_2026';

  const loadData = () => {
    const headers = {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${activeToken}`,
    };

    Promise.all([
      fetch('/api/v1/users/me', { headers }),
      fetch('/api/v1/users', { headers }),
      fetch('/api/v1/sites', { headers }),
      fetch('/api/v1/organizations', { headers }),
    ])
      .then(async ([meRes, usersRes, sitesRes, orgsRes]) => {
        if (meRes.ok) {
          const meData = await meRes.json();
          setCurrentUser(meData);
        }

        if (!usersRes.ok) {
          if (usersRes.status === 403) {
            throw new Error('Access denied: You need users:read or SuperAdmin permissions.');
          }
          throw new Error(`Failed to fetch users (HTTP ${usersRes.status})`);
        }
        const usersData = await usersRes.json();
        setUsers(usersData);

        if (sitesRes.ok) setSites(await sitesRes.json());
        if (orgsRes.ok) setOrgs(await orgsRes.json());
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

    Promise.all([
      fetch('/api/v1/users/me', { headers }),
      fetch('/api/v1/users', { headers }),
      fetch('/api/v1/sites', { headers }),
      fetch('/api/v1/organizations', { headers }),
    ])
      .then(async ([meRes, usersRes, sitesRes, orgsRes]) => {
        if (cancelled) return;
        if (meRes.ok) {
          const meData = await meRes.json();
          setCurrentUser(meData);
        }

        if (!usersRes.ok) {
          if (usersRes.status === 403) {
            throw new Error('Access denied: You need users:read or SuperAdmin permissions.');
          }
          throw new Error(`Failed to fetch users (HTTP ${usersRes.status})`);
        }
        const usersData = await usersRes.json();
        setUsers(usersData);

        if (sitesRes.ok) setSites(await sitesRes.json());
        if (orgsRes.ok) setOrgs(await orgsRes.json());
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
  }, [activeToken]);

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    try {
      const payload = {
        username: newUsername.trim(),
        email: newEmail.trim() || null,
        role: newRole,
        site_id: newSiteId || null,
        org_id: newOrgId || null,
        is_active: true,
      };

      const res = await fetch('/api/v1/users', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${activeToken}`,
        },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Error creating user (HTTP ${res.status})`);
      }

      setCreatedUserToken({
        username: data.username,
        api_token: data.api_token,
      });
      setSuccessMsg(`User '${data.username}' created successfully.`);
      setShowCreateModal(false);
      setNewUsername('');
      setNewEmail('');
      setNewRole('Auditor');
      setNewSiteId('');
      setNewOrgId('');
      loadData();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggleActive = async (user) => {
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`/api/v1/users/${user.id}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${activeToken}`,
        },
        body: JSON.stringify({ is_active: !user.is_active }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Failed to update user status (HTTP ${res.status})`);
      }
      setSuccessMsg(`User '${user.username}' is now ${!user.is_active ? 'Active' : 'Disabled'}.`);
      loadData();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleRotateToken = async (user) => {
    if (!window.confirm(`Rotate bearer API token for user '${user.username}'? The old token will be immediately invalidated.`)) {
      return;
    }
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`/api/v1/users/${user.id}/rotate-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${activeToken}`,
        },
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || `Failed to rotate token (HTTP ${res.status})`);
      }
      setRotatedTokenInfo({
        username: user.username,
        api_token: data.api_token,
      });
      setSuccessMsg(`Token rotated for '${user.username}'.`);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleDeleteUser = async (user) => {
    if (!window.confirm(`Are you sure you want to permanently delete user '${user.username}'?`)) {
      return;
    }
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await fetch(`/api/v1/users/${user.id}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${activeToken}`,
        },
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `Failed to delete user (HTTP ${res.status})`);
      }
      setSuccessMsg(`User '${user.username}' deleted.`);
      loadData();
    } catch (err) {
      setError(err.message);
    }
  };

  const isSuperAdmin = currentUser?.role === 'SuperAdmin';
  const hasUserWrite = isSuperAdmin || currentUser?.permissions?.includes('users:write');

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div>
          <h2 style={{ fontSize: '24px', fontWeight: 'bold', color: '#111827', margin: 0 }}>
            User Management
          </h2>
          <p style={{ color: '#6b7280', fontSize: '14px', margin: '4px 0 0 0' }}>
            Configure RBAC operators, assign roles, enforce site scopes, and rotate API credentials.
          </p>
        </div>
        {hasUserWrite && (
          <button
            onClick={() => setShowCreateModal(true)}
            style={{
              backgroundColor: '#2563eb',
              color: 'white',
              border: 'none',
              padding: '10px 16px',
              borderRadius: '6px',
              fontWeight: '600',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              boxShadow: '0 1px 2px rgba(0,0,0,0.05)',
            }}
          >
            <span>+ Add Operator</span>
          </button>
        )}
      </div>

      {/* Success Notification */}
      {successMsg && (
        <div style={{ backgroundColor: '#ecfdf5', border: '1px solid #10b981', color: '#065f46', padding: '12px 16px', borderRadius: '6px', marginBottom: '16px', fontSize: '14px' }}>
          {successMsg}
        </div>
      )}

      {/* Error Notification */}
      {error && (
        <div style={{ backgroundColor: '#fef2f2', border: '1px solid #ef4444', color: '#991b1b', padding: '12px 16px', borderRadius: '6px', marginBottom: '16px', fontSize: '14px' }}>
          {error}
        </div>
      )}

      {/* Plaintext Token Exposure Modals */}
      {(createdUserToken || rotatedTokenInfo) && (
        <div style={{
          backgroundColor: '#eff6ff',
          border: '1px solid #3b82f6',
          borderRadius: '8px',
          padding: '16px',
          marginBottom: '20px',
        }}>
          <h4 style={{ color: '#1e40af', margin: '0 0 8px 0', fontSize: '16px' }}>
            🔑 One-Time Bearer Token for {(createdUserToken || rotatedTokenInfo).username}
          </h4>
          <p style={{ fontSize: '13px', color: '#1e3a8a', margin: '0 0 10px 0' }}>
            Copy this token now! It will not be shown again. Use it in the Authorization header: <code style={{ background: '#dbeafe', padding: '2px 4px', borderRadius: '4px' }}>Bearer &lt;TOKEN&gt;</code>
          </p>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <input
              readOnly
              value={(createdUserToken || rotatedTokenInfo).api_token}
              style={{
                flex: 1,
                fontFamily: 'monospace',
                fontSize: '13px',
                padding: '8px 12px',
                border: '1px solid #93c5fd',
                borderRadius: '4px',
                background: '#ffffff',
              }}
            />
            <button
              onClick={() => {
                navigator.clipboard.writeText((createdUserToken || rotatedTokenInfo).api_token);
                alert('Token copied to clipboard!');
              }}
              style={{
                backgroundColor: '#1d4ed8',
                color: 'white',
                border: 'none',
                padding: '8px 14px',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: '600',
              }}
            >
              Copy
            </button>
            <button
              onClick={() => {
                setCreatedUserToken(null);
                setRotatedTokenInfo(null);
              }}
              style={{
                backgroundColor: '#9ca3af',
                color: 'white',
                border: 'none',
                padding: '8px 14px',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Users Table */}
      <div style={{ backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 1px 3px rgba(0,0,0,0.1)', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px' }}>
          <thead>
            <tr style={{ backgroundColor: '#f9fafb', borderBottom: '1px solid #e5e7eb', color: '#4b5563' }}>
              <th style={{ padding: '12px 16px' }}>Username</th>
              <th style={{ padding: '12px 16px' }}>Role</th>
              <th style={{ padding: '12px 16px' }}>Scope</th>
              <th style={{ padding: '12px 16px' }}>Status</th>
              <th style={{ padding: '12px 16px' }}>Created</th>
              <th style={{ padding: '12px 16px', textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="6" style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>
                  Loading users...
                </td>
              </tr>
            ) : users.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>
                  No operator accounts found.
                </td>
              </tr>
            ) : (
              users.map((u) => {
                const siteObj = sites.find((s) => s.id === u.site_id);
                const orgObj = orgs.find((o) => o.id === u.org_id);
                const roleBadgeColor =
                  u.role === 'SuperAdmin' ? '#7c3aed' : u.role === 'SiteTechnician' ? '#2563eb' : '#059669';

                return (
                  <tr key={u.id} style={{ borderBottom: '1px solid #f3f4f6' }}>
                    <td style={{ padding: '14px 16px', fontWeight: '600', color: '#111827' }}>
                      <div>{u.username}</div>
                      {u.email && <div style={{ fontSize: '12px', color: '#6b7280', fontWeight: 'normal' }}>{u.email}</div>}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span
                        style={{
                          backgroundColor: `${roleBadgeColor}15`,
                          color: roleBadgeColor,
                          border: `1px solid ${roleBadgeColor}30`,
                          padding: '3px 8px',
                          borderRadius: '12px',
                          fontSize: '12px',
                          fontWeight: '600',
                        }}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px', color: '#374151' }}>
                      {siteObj ? (
                        <span>Site: <strong>{siteObj.name}</strong></span>
                      ) : orgObj ? (
                        <span>Org: <strong>{orgObj.name}</strong></span>
                      ) : (
                        <span style={{ color: '#9ca3af', fontStyle: 'italic' }}>Global / Unscoped</span>
                      )}
                    </td>
                    <td style={{ padding: '14px 16px' }}>
                      <span
                        style={{
                          backgroundColor: u.is_active ? '#dcfce7' : '#fee2e2',
                          color: u.is_active ? '#15803d' : '#b91c1c',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '12px',
                          fontWeight: '500',
                        }}
                      >
                        {u.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td style={{ padding: '14px 16px', color: '#6b7280', fontSize: '13px' }}>
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>
                    <td style={{ padding: '14px 16px', textAlign: 'right' }}>
                      {hasUserWrite && (
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            onClick={() => handleToggleActive(u)}
                            style={{
                              backgroundColor: u.is_active ? '#fef3c7' : '#dcfce7',
                              color: u.is_active ? '#92400e' : '#166534',
                              border: 'none',
                              padding: '5px 10px',
                              borderRadius: '4px',
                              fontSize: '12px',
                              cursor: 'pointer',
                              fontWeight: '500',
                            }}
                          >
                            {u.is_active ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            onClick={() => handleRotateToken(u)}
                            style={{
                              backgroundColor: '#e0e7ff',
                              color: '#3730a3',
                              border: 'none',
                              padding: '5px 10px',
                              borderRadius: '4px',
                              fontSize: '12px',
                              cursor: 'pointer',
                              fontWeight: '500',
                            }}
                          >
                            Rotate Token
                          </button>
                          <button
                            onClick={() => handleDeleteUser(u)}
                            style={{
                              backgroundColor: '#fee2e2',
                              color: '#991b1b',
                              border: 'none',
                              padding: '5px 10px',
                              borderRadius: '4px',
                              fontSize: '12px',
                              cursor: 'pointer',
                              fontWeight: '500',
                            }}
                          >
                            Delete
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Create User Modal */}
      {showCreateModal && (
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
              maxWidth: '480px',
              boxShadow: '0 20px 25px -5px rgba(0,0,0,0.1)',
            }}
          >
            <h3 style={{ margin: '0 0 16px 0', fontSize: '18px', fontWeight: 'bold' }}>
              Create New Operator User
            </h3>
            <form onSubmit={handleCreateUser} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>
                  Username *
                </label>
                <input
                  required
                  type="text"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  placeholder="e.g. jdoe_tech"
                  style={{ width: '100%', boxSizing: 'border-box', padding: '8px 12px', borderRadius: '4px', border: '1px solid #d1d5db' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>
                  Email (Optional)
                </label>
                <input
                  type="email"
                  value={newEmail}
                  onChange={(e) => setNewEmail(e.target.value)}
                  placeholder="e.g. jdoe@company.com"
                  style={{ width: '100%', boxSizing: 'border-box', padding: '8px 12px', borderRadius: '4px', border: '1px solid #d1d5db' }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>
                  Role *
                </label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '8px 12px', borderRadius: '4px', border: '1px solid #d1d5db', backgroundColor: 'white' }}
                >
                  <option value="Auditor">Auditor (Read-Only & Sign Verification)</option>
                  <option value="SiteTechnician">SiteTechnician (Operational Site Dispatch)</option>
                  <option value="SuperAdmin">SuperAdmin (Full Control Plane Access)</option>
                </select>
              </div>

              {newRole === 'SiteTechnician' && (
                <div>
                  <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', marginBottom: '4px' }}>
                    Assigned Site (Recommended for Technicians)
                  </label>
                  <select
                    value={newSiteId}
                    onChange={(e) => setNewSiteId(e.target.value)}
                    style={{ width: '100%', boxSizing: 'border-box', padding: '8px 12px', borderRadius: '4px', border: '1px solid #d1d5db', backgroundColor: 'white' }}
                  >
                    <option value="">-- No specific site (Global) --</option>
                    {sites.map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name} ({s.id.slice(0, 8)}...)
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '12px' }}>
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  style={{
                    backgroundColor: '#f3f4f6',
                    color: '#374151',
                    border: '1px solid #d1d5db',
                    padding: '8px 16px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                  }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  style={{
                    backgroundColor: '#2563eb',
                    color: 'white',
                    border: 'none',
                    padding: '8px 16px',
                    borderRadius: '4px',
                    cursor: 'pointer',
                    fontWeight: '600',
                  }}
                >
                  Create & Generate Token
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
