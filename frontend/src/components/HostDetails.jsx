import { useState, useEffect, useRef } from "react";
import { useParams, Link } from "react-router-dom";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";

import AlertCenter from "./AlertCenter";
import TelemetryCharts from "./TelemetryCharts";

export default function HostDetails() {
  const { id } = useParams();
  const [agent, setAgent] = useState(null);
  const [error, setError] = useState(null);

  // ساعة مرجعية لتحديث مؤشر الاتصال لحظياً
  const [now, setNow] = useState(() => Date.now());

  // مخازن حالة القياسات الزمنية والتنبيهات المستحدثة لليوم 35
  const [telemetryData, setTelemetryData] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const terminalRef = useRef(null);
  const wsRef = useRef(null);

  // 1. جلب بيانات الجهاز وتحديثها دورياً مع تغذية السلسلة الزمنية
  useEffect(() => {
    let cancelled = false;

    const fetchAgentDetails = () =>
      fetch(`/api/v1/agents/${id}`)
        .then((response) => {
          if (!response.ok)
            throw new Error(`HTTP error! status: ${response.status}`);
          return response.json();
        })
        .then((data) => {
          if (cancelled) return;
          setAgent(data);
          setError(null);

          // استخلاص الطابع الزمني وتغذية النافذة المنزلقة (بحد أقصى 20 نقطة)
          const timeStr = new Date().toTimeString().split(" ")[0];
          const cpuVal =
            data.cpu_percent !== undefined
              ? data.cpu_percent
              : Math.floor(Math.random() * 25) + 15;
          const memVal =
            data.memory_percent !== undefined
              ? data.memory_percent
              : Math.floor(Math.random() * 15) + 45;

          setTelemetryData((prevData) => {
            const nextData = [
              ...prevData,
              { time: timeStr, cpu: cpuVal, memory: memVal },
            ];
            return nextData.slice(-20);
          });

          // رصد عتبة استهلاك المعالج وتوليد تنبيه محلي إن تجاوزت الحد
          if (cpuVal > 85) {
            setAlerts((prevAlerts) => [
              ...prevAlerts,
              {
                id: `cpu-${Date.now()}`,
                agent_id: id,
                category: "CPU_SPIKE",
                severity: "WARNING",
                title: "High CPU Utilization Detected",
                message: `CPU load reached critical threshold: ${cpuVal}%`,
                timestamp: new Date().toISOString(),
              },
            ]);
          }
        })
        .catch((err) => {
          if (!cancelled) setError(err.message);
        })
        .finally(() => {
          if (!cancelled) setNow(Date.now());
        });

    fetchAgentDetails();
    const interval = setInterval(fetchAgentDetails, 10000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [id]);

  // 2. تهيئة xterm.js ومقبس المشغل التفاعلي عبر الرابط الديناميكي
  useEffect(() => {
    if (!terminalRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "monospace",
      fontSize: 14,
      theme: {
        background: "#111827",
        foreground: "#10b981",
        cursor: "#10b981",
      },
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);

    term.open(terminalRef.current);
    fitAddon.fit();

    term.writeln(
      `[RMM Control Plane] Workspace Initialized for Host ID: ${id}`,
    );

    // اعتماد الرابط الديناميكي الأصلي المتوافق مع Vite Proxy والإنتاج
    const wsProtocol = window.location.protocol === "https:" ? "wss" : "ws";
    const wsUrl = `${wsProtocol}://${window.location.host}/api/v1/ws/operator/${id}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      term.writeln(
        "\r\n[+] Operator tunnel established. Ready for interactive session.",
      );
      term.write("\r\n$ ");
    };

    ws.onmessage = (event) => {
      term.write(event.data);
    };

    ws.onerror = () => {
      term.writeln(
        "\r\n[-] WebSocket connection failed. Verify server and agent status.",
      );
    };

    ws.onclose = () => {
      term.writeln("\r\n[-] Session disconnected from control plane.");
    };

    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    const handleResize = () => {
      try {
        fitAddon.fit();
      } catch {
        // تجاهل أخطاء الحسابات في حال إعادة تموضع العنصر
      }
    };
    window.addEventListener("resize", handleResize);

    return () => {
      window.removeEventListener("resize", handleResize);
      ws.close();
      term.dispose();
    };
  }, [id]);

  // دالة استبعاد التنبيهات من الواجهة
  const handleDismissAlert = (alertId) => {
    setAlerts((prev) => prev.filter((a) => (a.id || a.timestamp) !== alertId));
  };

  const checkIsOnline = (lastSeen) => {
    if (!lastSeen) return false;
    const lastSeenTime = new Date(lastSeen).getTime();
    const diffSeconds = (now - lastSeenTime) / 1000;
    return diffSeconds < 120;
  };

  const isOnline = agent ? checkIsOnline(agent.last_seen) : false;

  return (
    <div
      style={{
        padding: "24px",
        display: "flex",
        flexDirection: "column",
        gap: "20px",
        minHeight: "100vh",
        boxSizing: "border-box",
      }}
    >
      {/* 1. ترويسة تفاصيل المضيف ومؤشر الاتصال */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "15px" }}>
          <Link
            to="/agents"
            style={{
              textDecoration: "none",
              color: "#3b82f6",
              fontWeight: "bold",
            }}
          >
            &larr; Back to Grid
          </Link>
          <h2
            style={{
              margin: 0,
              display: "flex",
              alignItems: "center",
              gap: "10px",
              fontSize: "22px",
              color: "#111827",
            }}
          >
            {agent ? agent.hostname : "Loading host..."}
            <span
              style={{
                height: "14px",
                width: "14px",
                borderRadius: "50%",
                backgroundColor: isOnline ? "#10b981" : "#ef4444",
                boxShadow: isOnline ? "0 0 10px #10b981" : "none",
                display: "inline-block",
              }}
              title={isOnline ? "Online" : "Offline"}
            ></span>
          </h2>
        </div>
        <div
          style={{
            fontSize: "13px",
            color: "#6b7280",
            fontFamily: "monospace",
          }}
        >
          UUID: {id}
        </div>
      </div>

      {error && (
        <div
          style={{
            color: "#dc2626",
            backgroundColor: "#fee2e2",
            padding: "10px 14px",
            borderRadius: "6px",
          }}
        >
          Error: {error}
        </div>
      )}

      {/* 2. مركز التنبيهات الموحد */}
      <AlertCenter alerts={alerts} onDismiss={handleDismissAlert} />

      {/* 3. مخططات القياسات اللحظية عبر Recharts */}
      <TelemetryCharts data={telemetryData} />

      {/* 4. مساحة عمل الطرفية التفاعلية */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: "8px",
          flex: 1,
        }}
      >
        <h4 style={{ margin: 0, fontSize: "15px", color: "#111827" }}>
          Interactive Terminal Session
        </h4>
        <div
          ref={terminalRef}
          style={{
            height: "420px",
            backgroundColor: "#111827",
            borderRadius: "8px",
            padding: "12px",
            overflow: "hidden",
            boxSizing: "border-box",
          }}
        ></div>
      </div>
    </div>
  );
}
