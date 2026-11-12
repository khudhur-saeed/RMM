from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from app.schemas.telemetry import (
    AlertCategory,
    AlertEvent,
    AlertSeverity,
    AuthEventPayload,
    HardwareMetricsPayload,
    ServiceStatusPayload,
)


class AlertEvaluator:
    """
    Stateful evaluation engine for operational telemetry thresholds
    and cybersecurity behavioral anomalies.
    """

    def __init__(
        self,
        cpu_threshold: float = 90.0,
        brute_force_window_seconds: int = 120,
        brute_force_threshold: int = 5,
    ) -> None:
        self.cpu_threshold = cpu_threshold
        self.brute_force_window = timedelta(seconds=brute_force_window_seconds)
        self.brute_force_threshold = brute_force_threshold
        # Key: (agent_id, source_ip), Value: List of failure timestamps
        self.failed_login_tracker: Dict[Tuple[UUID, str], List[datetime]] = defaultdict(list)

    def evaluate_hardware(self, agent_id: UUID, payload: HardwareMetricsPayload) -> List[AlertEvent]:
        alerts: List[AlertEvent] = []

        if payload.cpu_percent >= self.cpu_threshold:
            alerts.append(
                AlertEvent(
                    agent_id=agent_id,
                    category=AlertCategory.CPU_SPIKE,
                    severity=AlertSeverity.WARNING,
                    title="High CPU Utilization Spike",
                    message=f"CPU load reached {payload.cpu_percent:.2f}%, exceeding threshold of {self.cpu_threshold:.2f}%.",
                )
            )

        return alerts

    def evaluate_services(self, agent_id: UUID, payload: ServiceStatusPayload) -> List[AlertEvent]:
        alerts: List[AlertEvent] = []

        for svc in payload.services:
            if svc.is_critical and svc.status.lower() == "stopped":
                alerts.append(
                    AlertEvent(
                        agent_id=agent_id,
                        category=AlertCategory.SERVICE_STOPPED,
                        severity=AlertSeverity.CRITICAL,
                        title=f"Critical Service Stopped: {svc.name}",
                        message=f"Monitored critical system service '{svc.name}' is reported in a stopped state.",
                    )
                )

        return alerts

    def evaluate_auth_event(self, agent_id: UUID, payload: AuthEventPayload) -> List[AlertEvent]:
        alerts: List[AlertEvent] = []

        # Target forensic failure types (Linux authmon or Windows 4625)
        if payload.event_type in ("SSH_LOGIN_FAILED", "SUDO_FAILED", "LOGON_FAILED_4625"):
            now = datetime.now(timezone.utc)
            ip_key = payload.source_ip or "local"
            key = (agent_id, ip_key)

            # Evict timestamps outside sliding window
            cutoff = now - self.brute_force_window
            self.failed_login_tracker[key] = [
                ts for ts in self.failed_login_tracker[key] if ts > cutoff
            ]

            # Bound total dictionary keys to prevent memory creep under IP-spoofing attacks
            if len(self.failed_login_tracker) > 5000:
                stale_keys = [k for k, v in list(self.failed_login_tracker.items()) if not v or max(v) < cutoff]
                for k in stale_keys:
                    self.failed_login_tracker.pop(k, None)

            # Record current failure
            self.failed_login_tracker[key].append(now)

            if len(self.failed_login_tracker[key]) >= self.brute_force_threshold:
                alerts.append(
                    AlertEvent(
                        agent_id=agent_id,
                        category=AlertCategory.BRUTE_FORCE,
                        severity=AlertSeverity.CRITICAL,
                        title="Brute-Force / Credential Access Detected",
                        message=(
                            f"Detected {len(self.failed_login_tracker[key])} failed logon attempts "
                            f"for user '{payload.username}' from source '{ip_key}' "
                            f"within {self.brute_force_window.total_seconds()} seconds."
                        ),
                    )
                )
                # Reset counter to avoid continuous repetitive alerts on subsequent failures
                self.failed_login_tracker[key].clear()

        return alerts


# Global singleton instance for injection into WebSocket pipelines
alert_evaluator = AlertEvaluator()