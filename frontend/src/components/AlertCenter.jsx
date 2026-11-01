import { useState } from 'react';

export default function AlertCenter({ alerts = [], onDismiss }) {
  // حالة تصفية التنبيهات بحسب الخطورة
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');

  // تصفية المصفوفة محلياً استناداً إلى المرشح المحدد
  const filteredAlerts = selectedSeverity === 'ALL'
    ? alerts
    : alerts.filter((alert) => alert.severity === selectedSeverity);

  // دالة تحديد الألوان والأنماط بناءً على مستوى الخطورة
  const getSeverityBadgeStyles = (severity) => {
    switch (severity) {
      case 'CRITICAL':
        return { backgroundColor: '#fee2e2', color: '#991b1b', border: '1px solid #f87171' };
      case 'WARNING':
        return { backgroundColor: '#fef3c7', color: '#92400e', border: '1px solid #fbbf24' };
      case 'INFO':
      default:
        return { backgroundColor: '#dbeafe', color: '#1e40af', border: '1px solid #60a5fa' };
    }
  };

  return (
    <div style={{ backgroundColor: '#ffffff', borderRadius: '8px', padding: '20px', border: '1px solid #e5e7eb', boxShadow: '0 1px 3px rgba(0,0,0,0.05)', marginBottom: '20px' }}>
      
      {/* الترويسة وأزرار التصفية */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: '18px', color: '#111827' }}>Alert Center</h3>
          <p style={{ margin: '4px 0 0 0', fontSize: '13px', color: '#6b7280' }}>
            Active security and operational anomaly detections
          </p>
        </div>

        {/* أزرار الفلترة السريعة */}
        <div style={{ display: 'flex', gap: '8px' }}>
          {['ALL', 'CRITICAL', 'WARNING', 'INFO'].map((level) => (
            <button
              key={level}
              onClick={() => setSelectedSeverity(level)}
              style={{
                padding: '6px 12px',
                borderRadius: '6px',
                fontSize: '12px',
                fontWeight: 'bold',
                cursor: 'pointer',
                border: selectedSeverity === level ? '1px solid #1f2937' : '1px solid #d1d5db',
                backgroundColor: selectedSeverity === level ? '#1f2937' : '#f9fafb',
                color: selectedSeverity === level ? '#ffffff' : '#374151',
                transition: 'all 0.15s ease-in-out'
              }}
            >
              {level}
            </button>
          ))}
        </div>
      </div>

      {/* قائمة التنبيهات أو رسالة الفراغ */}
      {filteredAlerts.length === 0 ? (
        <div style={{ padding: '24px', textAlign: 'center', color: '#9ca3af', backgroundColor: '#f9fafb', borderRadius: '6px', border: '1px dashed #d1d5db' }}>
          No alerts matching the selected filter.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {filteredAlerts.map((alert) => (
            <div
              key={alert.id || `${alert.agent_id}-${alert.timestamp}`}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 16px',
                borderRadius: '6px',
                backgroundColor: '#ffffff',
                border: '1px solid #e5e7eb',
                borderLeft: `4px solid ${
                  alert.severity === 'CRITICAL' ? '#dc2626' : alert.severity === 'WARNING' ? '#d97706' : '#2563eb'
                }`
              }}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span
                    style={{
                      ...getSeverityBadgeStyles(alert.severity),
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontSize: '11px',
                      fontWeight: 'bold'
                    }}
                  >
                    {alert.severity}
                  </span>
                  <span style={{ fontSize: '14px', fontWeight: 'bold', color: '#111827' }}>
                    {alert.title}
                  </span>
                  <span style={{ fontSize: '11px', color: '#6b7280', fontFamily: 'monospace' }}>
                    Agent: {alert.agent_id ? alert.agent_id.substring(0, 8) : 'Unknown'}
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '13px', color: '#4b5563' }}>
                  {alert.message}
                </p>
              </div>

              {/* وقت التنبيه وزر الإقرار/الحذف */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span style={{ fontSize: '12px', color: '#9ca3af' }}>
                  {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : 'Just now'}
                </span>
                {onDismiss && (
                  <button
                    onClick={() => onDismiss(alert.id || alert.timestamp)}
                    style={{
                      padding: '4px 8px',
                      fontSize: '12px',
                      color: '#6b7280',
                      backgroundColor: 'transparent',
                      border: '1px solid #d1d5db',
                      borderRadius: '4px',
                      cursor: 'pointer'
                    }}
                    title="Dismiss Alert"
                  >
                    Dismiss
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
