import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';

export default function TelemetryCharts({ data = [] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '20px' }}>
      
      {/* مخطط استهلاك المعالج CPU Load */}
      <div style={{ backgroundColor: '#ffffff', borderRadius: '8px', padding: '16px', border: '1px solid #e5e7eb', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h4 style={{ margin: 0, fontSize: '15px', color: '#111827' }}>CPU Utilization (%)</h4>
          <span style={{ fontSize: '12px', fontWeight: 'bold', color: '#dc2626' }}>
            {data.length > 0 ? `${data[data.length - 1].cpu.toFixed(1)}%` : '0.0%'}
          </span>
        </div>
        <div style={{ width: '100%', height: 220 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="time" stroke="#9ca3af" fontSize={11} tickLine={false} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', borderRadius: '4px', border: 'none', color: '#ffffff', fontSize: '12px' }}
                labelStyle={{ color: '#9ca3af', marginBottom: '4px' }}
              />
              <Line
                type="monotone"
                dataKey="cpu"
                stroke="#dc2626"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* مخطط استهلاك الذاكرة RAM Usage */}
      <div style={{ backgroundColor: '#ffffff', borderRadius: '8px', padding: '16px', border: '1px solid #e5e7eb', boxShadow: '0 1px 3px rgba(0,0,0,0.05)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <h4 style={{ margin: 0, fontSize: '15px', color: '#111827' }}>Memory Utilization (%)</h4>
          <span style={{ fontSize: '12px', fontWeight: 'bold', color: '#2563eb' }}>
            {data.length > 0 ? `${data[data.length - 1].memory.toFixed(1)}%` : '0.0%'}
          </span>
        </div>
        <div style={{ width: '100%', height: 220 }}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
              <XAxis dataKey="time" stroke="#9ca3af" fontSize={11} tickLine={false} />
              <YAxis domain={[0, 100]} stroke="#9ca3af" fontSize={11} tickLine={false} />
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', borderRadius: '4px', border: 'none', color: '#ffffff', fontSize: '12px' }}
                labelStyle={{ color: '#9ca3af', marginBottom: '4px' }}
              />
              <Line
                type="monotone"
                dataKey="memory"
                stroke="#2563eb"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

    </div>
  );
}
