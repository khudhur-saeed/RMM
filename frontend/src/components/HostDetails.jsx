import { useState, useEffect, useRef } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';

export default function HostDetails() {
  const { id } = useParams();
  const [agent, setAgent] = useState(null);
  const [error, setError] = useState(null);

  const terminalRef = useRef(null);
  const wsRef = useRef(null);

  // 1. جلب بيانات الجهاز وتحديثها دورياً
  const fetchAgentDetails = async () => {
    try {
      const response = await fetch(`/api/v1/agents/${id}`);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      const data = await response.json();
      setAgent(data);
    } catch (err) {
      setError(err.message);
    }
  };

  useEffect(() => {
    fetchAgentDetails();
    const interval = setInterval(fetchAgentDetails, 10000);
    return () => clearInterval(interval);
  }, [id]);

  // 2. تهيئة xterm.js ومقبس المشغل التفاعلي
  useEffect(() => {
    if (!terminalRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'monospace',
      fontSize: 14,
      theme: {
        background: '#111827',
        foreground: '#10b981',
        cursor: '#10b981'
      }
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);

    term.open(terminalRef.current);
    fitAddon.fit();

    term.writeln(`[RMM Control Plane] Workspace Initialized for Host ID: ${id}`);

    const wsUrl = `ws://localhost:8000/api/v1/ws/operator/${id}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      term.writeln('\r\n[+] Operator tunnel established. Ready for interactive session.');
      term.write('\r\n$ ');
    };

    ws.onmessage = (event) => {
      term.write(event.data);
    };

    ws.onerror = () => {
      term.writeln('\r\n[-] WebSocket connection failed. Verify server and agent status.');
    };

    ws.onclose = () => {
      term.writeln('\r\n[-] Session disconnected from control plane.');
    };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    const handleResize = () => {
      try {
        fitAddon.fit();
      } catch (e) {
        // تجاهل أخطاء الحسابات في حال إعادة تموضع العنصر
      }
    };
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
      ws.close();
      term.dispose();
    };
  }, [id]);

  const checkIsOnline = (lastSeen) => {
    if (!lastSeen) return false;
    const lastSeenTime = new Date(lastSeen).getTime();
    const currentTime = Date.now();
    const diffSeconds = (currentTime - lastSeenTime) / 1000;
    return diffSeconds < 120;
  };

  const isOnline = agent ? checkIsOnline(agent.last_seen) : false;

  return (
    <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', height: '90vh' }}>
      
      {/* ترويسة تفاصيل المضيف */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '15px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <Link to="/agents" style={{ textDecoration: 'none', color: '#3b82f6', fontWeight: 'bold' }}>&larr; Back to Grid</Link>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
            {agent ? agent.hostname : 'Loading host...'}
            <span style={{ 
              height: '14px', width: '14px', borderRadius: '50%', 
              backgroundColor: isOnline ? '#10b981' : '#ef4444',
              boxShadow: isOnline ? '0 0 10px #10b981' : 'none',
              display: 'inline-block'
            }} title={isOnline ? 'Online' : 'Offline'}></span>
          </h2>
        </div>
        <div style={{ fontSize: '13px', color: '#6b7280', fontFamily: 'monospace' }}>UUID: {id}</div>
      </div>

      {error && <div style={{ color: 'red', marginBottom: '10px' }}>Error: {error}</div>}

      {/* حاوية الطرفية غير المشروطة (Unconditional DOM Mounting) */}
      <div 
        ref={terminalRef} 
        style={{ 
          flex: 1, 
          minHeight: '400px', 
          backgroundColor: '#111827', 
          borderRadius: '8px', 
          padding: '10px', 
          overflow: 'hidden',
          boxSizing: 'border-box'
        }}
      ></div>

    </div>
  );
}
