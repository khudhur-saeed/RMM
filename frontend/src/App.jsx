import { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, Link } from 'react-router-dom';
import AgentInventory from './components/AgentInventory';
import HostDetails from './components/HostDetails';

const DEFAULT_DEV_TOKEN = 'rmm_admin_dev_token_2026';

function App() {
  const [operatorToken, setOperatorToken] = useState(() => {
    return sessionStorage.getItem('rmm_operator_token') || DEFAULT_DEV_TOKEN;
  });

  const handleTokenChange = (e) => {
    const nextToken = e.target.value;
    setOperatorToken(nextToken);
    sessionStorage.setItem('rmm_operator_token', nextToken);
  };

  return (
    <BrowserRouter>
      <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: '#f3f4f6' }}>
        {/* الشريط الجانبي الإداري */}
        <div style={{ width: '250px', background: '#1f2937', color: 'white', padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h2 style={{ fontSize: '18px', margin: '0 0 20px 0' }}>Tactical RMM</h2>
            <nav style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <Link to="/agents" style={{ color: '#9ca3af', textDecoration: 'none' }}>Agents</Link>
            </nav>
          </div>

          <div style={{ marginTop: '20px', borderTop: '1px solid #374151', paddingTop: '15px' }}>
            <label htmlFor="operator-token-input" style={{ display: 'block', fontSize: '12px', color: '#9ca3af', marginBottom: '6px' }}>
              Operator API Token
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
                padding: '6px 8px',
                borderRadius: '4px',
                border: '1px solid #4b5563',
                backgroundColor: '#111827',
                color: '#f9fafb',
                fontSize: '12px',
              }}
            />
          </div>
        </div>
        
        {/* مساحة العرض الرئيسية */}
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Navigate to="/agents" replace />} />
            <Route path="/agents" element={<AgentInventory operatorToken={operatorToken} />} />
            <Route path="/agents/:id" element={<HostDetails operatorToken={operatorToken} />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
