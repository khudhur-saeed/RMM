import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import AgentInventory from './components/AgentInventory';
import HostDetails from './components/HostDetails';

function App() {
  return (
    <BrowserRouter>
      <div style={{ display: 'flex', minHeight: '100vh', backgroundColor: '#f3f4f6' }}>
        {/* الشريط الجانبي الإداري */}
        <div style={{ width: '250px', background: '#1f2937', color: 'white', padding: '20px' }}>
          <h2 style={{ fontSize: '18px', margin: '0 0 20px 0' }}>Tactical RMM</h2>
          <nav style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <a href="/agents" style={{ color: '#9ca3af', textDecoration: 'none' }}>Agents</a>
          </nav>
        </div>
        
        {/* مساحة العرض الرئيسية */}
        <main style={{ flex: 1 }}>
          <Routes>
            <Route path="/" element={<Navigate to="/agents" replace />} />
            <Route path="/agents" element={<AgentInventory />} />
            <Route path="/agents/:id" element={<HostDetails />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

export default App;
