import uuid

import pytest
from app.api.v1.endpoints.ws import process_telemetry_frame
from app.schemas.telemetry import (
    AlertCategory,
    AlertSeverity,
    AuthEventPayload,
    HardwareMetricsPayload,
    ServiceStatusEntry,
    ServiceStatusPayload,
)
from app.services.alert_engine import AlertEvaluator


def test_hardware_cpu_spike_threshold():
    """
    Validates CPU evaluation rules: Normal loads must pass silently,
    while metrics >= 90.0% must emit WARNING alerts.
    """
    evaluator = AlertEvaluator(cpu_threshold=90.0)
    agent_id = uuid.uuid4()

    # Case 1: Normal operational threshold (no alert expected)
    normal_payload = HardwareMetricsPayload(cpu_percent=78.5, memory_percent=60.0)
    alerts_normal = evaluator.evaluate_hardware(agent_id, normal_payload)
    assert len(alerts_normal) == 0

    # Case 2: CPU Spike threshold breached (alert expected)
    spike_payload = HardwareMetricsPayload(cpu_percent=94.2, memory_percent=60.0)
    alerts_spike = evaluator.evaluate_hardware(agent_id, spike_payload)
    assert len(alerts_spike) == 1
    alert = alerts_spike[0]
    assert alert.category == AlertCategory.CPU_SPIKE
    assert alert.severity == AlertSeverity.WARNING
    assert "94.20%" in alert.message


def test_critical_service_stopped_alert():
    """
    Validates critical service rules: Running services and stopped non-critical
    services pass silently, while stopped critical services emit CRITICAL alerts.
    """
    evaluator = AlertEvaluator()
    agent_id = uuid.uuid4()

    payload = ServiceStatusPayload(
        services=[
            ServiceStatusEntry(name="nginx", status="running", is_critical=True),
            ServiceStatusEntry(name="cups", status="stopped", is_critical=False),
            ServiceStatusEntry(name="sshd", status="stopped", is_critical=True),
        ]
    )

    alerts = evaluator.evaluate_services(agent_id, payload)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.category == AlertCategory.SERVICE_STOPPED
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.title == "Critical Service Stopped: sshd"


def test_sliding_window_brute_force_detection():
    """
    Validates sliding window authentication monitoring: Exactly 5 failed attempts
    within window triggers CRITICAL brute-force alert, followed by counter reset.
    """
    evaluator = AlertEvaluator(brute_force_window_seconds=120, brute_force_threshold=5)
    agent_id = uuid.uuid4()
    source_ip = "198.51.100.25"

    auth_payload = AuthEventPayload(
        event_type="SSH_LOGIN_FAILED",
        username="root",
        source_ip=source_ip,
    )

    # Attempts 1 through 4: Must not trigger alert (below threshold)
    for attempt in range(1, 5):
        alerts = evaluator.evaluate_auth_event(agent_id, auth_payload)
        assert len(alerts) == 0, f"Unexpected alert triggered on attempt {attempt}"

    # Attempt 5: Threshold satisfied, must emit CRITICAL alert
    alerts = evaluator.evaluate_auth_event(agent_id, auth_payload)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.category == AlertCategory.BRUTE_FORCE
    assert alert.severity == AlertSeverity.CRITICAL
    assert "5 failed logon attempts" in alert.message
    assert source_ip in alert.message

    # Attempt 6: Counter reset mitigation must prevent repetitive flapping alerts
    alerts_after_reset = evaluator.evaluate_auth_event(agent_id, auth_payload)
    assert len(alerts_after_reset) == 0


@pytest.mark.asyncio
async def test_websocket_telemetry_pipeline_demux():
    """
    Validates end-to-end telemetry frame processing through the WebSocket router demux logic.
    Ensures heterogeneous payloads are ingested safely without throwing unhandled exceptions.
    """
    agent_id = uuid.uuid4()

    # Hardware telemetry frame payload
    hw_frame = {
        "type": "hardware_telemetry",
        "cpu": {"usage_percent": 95.0, "logical_cores": 4},
        "memory": {"used_percent": 70.0},
    }
    await process_telemetry_frame(agent_id, hw_frame)

    # Critical service payload
    svc_frame = {
        "type": "service_status",
        "payload": {
            "services": [
                {"name": "postgresql", "status": "stopped", "is_critical": True}
            ]
        },
    }
    await process_telemetry_frame(agent_id, svc_frame)

    # Forensic security auth payload
    auth_frame = {
        "type": "auth_event",
        "payload": {
            "event_type": "SSH_LOGIN_FAILED",
            "user": "admin",
            "source_ip": "10.0.0.15",
        },
    }
    await process_telemetry_frame(agent_id, auth_frame)
