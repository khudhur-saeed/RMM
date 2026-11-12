# Background Services & Analytical Engines

## Overview
Background workers and analytical engines for heartbeat watchdog monitoring and behavioral anomaly detection.

## Interface
- alert_engine.py:AlertEvaluator
- alert_engine.py:alert_evaluator
- watchdog.py:evaluate_lapsed_agents
- watchdog.py:run_agent_watchdog

## Invariants
- Agents are marked offline if their last_seen timestamp exceeds the threshold (default: 90 seconds) without an active Redis lease [watchdog.py:evaluate_lapsed_agents]
- AlertEvaluator tracks failed authentication attempts within a rolling window to detect brute force patterns [alert_engine.py:AlertEvaluator]

## Side Effects
- Updates Agent status column in PostgreSQL to offline [watchdog.py:evaluate_lapsed_agents]
- Evicts stale agent status keys from Redis cache [watchdog.py:evaluate_lapsed_agents]

## Verification
- Run: `cd server && pytest tests/test_watchdog.py tests/test_alert_engine.py`
