import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

export default function HostDetails() {
  // 1. استخراج المعرّف من شريط العنوان
  const { id } = useParams(); 
  
  // 2. مخازن الحالة
  const [agent, setAgent] = useState(null);
  const [error, setError] = useState(null);

  // 3. جلب بيانات الجهاز عند تحميل الشاشة
  useEffect(() => {
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

    fetchAgentDetails();
  }, [id]); // إعادة التنفيذ فقط إذا تغير المعرّف في الرابط

  // 4. دالة حساب حالة الاتصال (Online/Offline)
  const checkIsOnline = (lastSeen) => {
    if (!lastSeen) return false;
    const lastSeenTime = new Date(lastSeen).getTime();
    const currentTime = Date.now();
    const diffSeconds = (currentTime - lastSeenTime) / 1000;
    
    // نعتبر الجهاز متصلاً إذا كانت آخر نبضة منذ أقل من 120 ثانية
    return diffSeconds < 120; 
  };

  // 5. شاشات التحميل والأخطاء
  if (error) return <div style={{ padding: '20px', color: 'red', fontWeight: 'bold' }}>Error: {error}</div>;
  if (!agent) return <div style={{ padding: '20px' }}>Loading host details...</div>;

  const isOnline = checkIsOnline(agent.last_seen);

  // 6. رسم واجهة مساحة العمل
  return (
    <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', height: '90vh' }}>
      
      {/* القسم العلوي: الترويسة ومؤشر الحالة */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <Link to="/agents" style={{ textDecoration: 'none', color: '#3b82f6', fontWeight: 'bold' }}>&larr; Back to Grid</Link>
          <h2 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: '10px' }}>
            {agent.hostname}
            {/* مؤشر الحالة اللحظي */}
            <span style={{ 
              height: '14px', width: '14px', borderRadius: '50%', 
              backgroundColor: isOnline ? '#10b981' : '#ef4444',
              boxShadow: isOnline ? '0 0 10px #10b981' : 'none',
              display: 'inline-block'
            }} title={isOnline ? 'Online' : 'Offline'}></span>
          </h2>
        </div>
        <div style={{ fontSize: '13px', color: '#6b7280', fontFamily: 'monospace' }}>UUID: {agent.id}</div>
      </div>

      {/* القسم الأوسط: بطاقات المواصفات */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
        <div style={{ background: 'white', padding: '15px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <strong style={{ color: '#374151' }}>Platform Architecture</strong> 
          <p style={{ margin: '8px 0 0 0', color: '#111827' }}>{agent.os}</p>
        </div>
        <div style={{ background: 'white', padding: '15px', borderRadius: '8px', border: '1px solid #e5e7eb' }}>
          <strong style={{ color: '#374151' }}>Local Network</strong> 
          <p style={{ margin: '8px 0 0 0', color: '#111827' }}>{agent.private_ip || 'Unknown'}</p>
        </div>
      </div>

      {/* القسم السفلي: حاوية الطرفية التفاعلية */}
      <div style={{ flex: 1, backgroundColor: '#111827', borderRadius: '8px', padding: '20px', fontFamily: 'monospace', color: '#10b981', overflow: 'hidden' }}>
        <p style={{ margin: 0 }}>[RMM Control Plane] Workspace Initialized for Host: {agent.hostname}</p>
        <p style={{ margin: '10px 0 0 0', color: '#6b7280' }}>&gt; Awaiting xterm.js integration and WebSocket upgrade...</p>
      </div>

    </div>
  );
}
