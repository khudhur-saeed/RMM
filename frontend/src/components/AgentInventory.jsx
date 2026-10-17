import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';

export default function AgentInventory() {
  // 1. تعريف مخازن الحالة (State Managers)
  const [agents, setAgents] = useState([]);
  const [error, setError] = useState(null);

  // 2. التأثير الجانبي لجلب البيانات عند تحميل المكون
  useEffect(() => {
    const fetchAgents = async () => {
      try {
        // يتم توجيه هذا الطلب تلقائياً إلى المنفذ 8000 بفضل الوكيل العكسي (Proxy)
        const response = await fetch('/api/v1/agents');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        
        const data = await response.json();
        setAgents(data); // تحديث الواجهة بالمصفوفة المستلمة
      } catch (err) {
        setError(err.message);
      }
    };

    fetchAgents();
  }, []); // المصفوفة الفارغة تعني: "نفّذ هذا الكود مرة واحدة فقط عند فتح الشاشة"

  // 3. رسم واجهة المستخدم (JSX)
  return (
    <div style={{ padding: '20px' }}>
      <h2>Agent Inventory Grid</h2>
      {error && <p style={{ color: 'red', fontWeight: 'bold' }}>Error fetching agents: {error}</p>}
      
      <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '20px', backgroundColor: 'white', boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
        <thead>
          <tr style={{ backgroundColor: '#1f2937', color: 'white', textAlign: 'left' }}>
            <th style={{ padding: '12px' }}>Hostname</th>
            <th style={{ padding: '12px' }}>OS Architecture</th>
            <th style={{ padding: '12px' }}>Private IP</th>
            <th style={{ padding: '12px' }}>Last Seen</th>
            <th style={{ padding: '12px' }}>Actions</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((agent) => (
            <tr key={agent.id} style={{ borderBottom: '1px solid #e5e7eb' }}>
              <td style={{ padding: '12px', fontWeight: 'bold' }}>{agent.hostname}</td>
              <td style={{ padding: '12px' }}>{agent.os}</td>
              <td style={{ padding: '12px' }}>{agent.private_ip || 'N/A'}</td>
              <td style={{ padding: '12px' }}>
                {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : 'Never'}
              </td>
              <td style={{ padding: '12px' }}>
                {/* استخدام Link بدلاً من a href لمنع إعادة تحميل الصفحة وقطع الاتصالات اللحظية */}
                <Link 
                  to={`/agents/${agent.id}`} 
                  style={{ backgroundColor: '#3b82f6', color: 'white', padding: '6px 12px', borderRadius: '4px', textDecoration: 'none', fontSize: '14px' }}
                >
                  View Details
                </Link>
              </td>
            </tr>
          ))}
          
          {/* عرض رسالة إذا كانت قاعدة البيانات فارغة ولم يكن هناك أخطاء شبكية */}
          {agents.length === 0 && !error && (
            <tr>
              <td colSpan="5" style={{ padding: '20px', textAlign: 'center', color: '#6b7280' }}>
                No endpoints currently enrolled.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
