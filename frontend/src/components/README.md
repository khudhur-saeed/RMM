# Control Plane Dashboard Components

## Overview
React UI component library implementing tactical RMM control plane views: fleet inventory grid, host details inspection with live telemetry and interactive xterm.js terminal, alert monitoring, endpoint software package management, RBAC role matrix inspection, and immutable audit log exploration.

## Interface
- [AgentInventory.jsx:AgentInventory] React component (props: { operatorToken: string }) rendering agent fleet table with real-time connectivity status
- [HostDetails.jsx:HostDetails] React component (props: { operatorToken: string }) providing host hardware metadata, telemetry charting, and live xterm C2 shell
- [AlertCenter.jsx:AlertCenter] React component (props: { alerts: Array, onDismiss: Function }) providing anomaly detection triage and severity filtering
- [SoftwareInventory.jsx:SoftwareInventory] React component (props: { agentId: string, operatorToken: string }) rendering installed packages with on-demand scan triggers
- [TelemetryCharts.jsx:TelemetryCharts] React component (props: { data: Array<{ time: string, cpu: number, memory: number }> }) rendering CPU and memory time-series charts
- [UserManagement.jsx:UserManagement] React component (props: { operatorToken: string }) managing operator accounts, token generation, and account status
- [RolePermissions.jsx:RolePermissions] React component (props: { operatorToken: string }) inspecting predefined RBAC permissions across system domains
- [AuditLogExplorer.jsx:AuditLogExplorer] React component (props: { operatorToken: string }) querying and filtering security audit event trails

## Invariants
- [HostDetails.jsx:UUID_REGEX] Path parameter 'id' must conform to standard 8-4-4-4-12 UUID format or data fetch and terminal connection are halted
- [HostDetails.jsx:telemetryData] Telemetry time series buffer is strictly bounded to the last 20 samples (nextData.slice(-20))
- [HostDetails.jsx:alerts] Local CPU spike alerts are generated when CPU utilization exceeds 85%, throttled to 1 alert per 60s, and bounded to 50 alerts max
- [TelemetryCharts.jsx:Line] Animation is disabled (isAnimationActive=false) across chart lines for deterministic real-time rendering
- [AgentInventory.jsx:activeToken] Token resolution strictly cascades: operatorToken prop -> sessionStorage('rmm_operator_token') -> dev fallback token

## Side Effects
- [AgentInventory.jsx:fetchAgents] Dispatches HTTP GET /api/v1/agents with Bearer token authentication
- [HostDetails.jsx:fetchAgentDetails] Dispatches periodic polling (10s interval) via HTTP GET /api/v1/agents/:id and /api/v1/agents/:id/telemetry
- [HostDetails.jsx:WebSocket] Establishes persistent WebSocket connection to /api/v1/ws/operator/:id using subprotocols ['rmm.v1', 'bearer.<token>']
- [SoftwareInventory.jsx:fetchSoftware] Dispatches HTTP GET /api/v1/agents/:id/software and POST /api/v1/agents/:id/software/scan
- [UserManagement.jsx:loadData] Dispatches HTTP requests to /api/v1/users, /api/v1/sites, and /api/v1/organizations, and mutates tokens via POST /api/v1/users/:id/rotate-token
- [AuditLogExplorer.jsx:fetchLogs] Dispatches HTTP GET /api/v1/audit-logs with query filters

## Verification
- Run: `npm run build`
