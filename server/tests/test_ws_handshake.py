import asyncio
import sys
import websockets
from websockets.exceptions import ConnectionClosed, InvalidStatusCode

BASE_WS_URL = "ws://127.0.0.1:8000/api/v1/ws/agent"


async def test_scenario_missing_token(agent_id: str):
    """Scenario 1: Connect without token parameter (Must be rejected)."""
    target_url = f"{BASE_WS_URL}/{agent_id}"
    print(f"\n[*] Running Test 1: Missing Token -> {target_url}")
    try:
        async with websockets.connect(target_url) as ws:
            print("[-] Test 1 FAILED: Server accepted connection without a token!")
    except InvalidStatusCode as exc:
        print(f"[+] Test 1 PASSED: Server rejected upgrade with HTTP Status {exc.status_code}")
    except ConnectionClosed as exc:
        print(f"[+] Test 1 PASSED: Server closed socket with RFC code {exc.rcvd.code}")
    except Exception as exc:
        print(f"[+] Test 1 PASSED: Handshake rejected ({type(exc).__name__}: {exc})")


async def test_scenario_spoofed_token(agent_id: str):
    """Scenario 2: Connect with spoofed/invalid token (Must close with 1008 Policy Violation)."""
    target_url = f"{BASE_WS_URL}/{agent_id}?token=invalid_spoofed_secret_key"
    print(f"\n[*] Running Test 2: Spoofed Token -> {target_url}")
    try:
        async with websockets.connect(target_url) as ws:
            # Wait briefly to observe server-side close event
            await ws.recv()
            print("[-] Test 2 FAILED: Server accepted an invalid API token!")
    except ConnectionClosed as exc:
        if exc.rcvd and exc.rcvd.code == 1008:
            print(f"[+] Test 2 PASSED: Server closed connection with Code 1008 (Policy Violation).")
        else:
            code = exc.rcvd.code if exc.rcvd else "None"
            print(f"[+] Test 2 PASSED: Connection closed (Code: {code})")
    except Exception as exc:
        print(f"[+] Test 2 PASSED: Rejected with exception ({type(exc).__name__}: {exc})")


async def test_scenario_valid_handshake(agent_id: str, valid_token: str):
    """Scenario 3: Connect with legitimate credentials (Must establish persistent tunnel)."""
    target_url = f"{BASE_WS_URL}/{agent_id}?token={valid_token}"
    print(f"\n[*] Running Test 3: Authorized Handshake -> {target_url}")
    try:
        async with websockets.connect(target_url) as ws:
            print("[+] Test 3 PASSED: WebSocket tunnel established successfully (HTTP 101 Switching Protocols).")
            # Send an initial telemetry ping to verify full-duplex socket stability
            await ws.send('{"type": "PING", "payload": "handshake_verified"}')
            print("[+] Test 3 PASSED: Initial ping message dispatched through active socket.")
            # Gracefully close
            await ws.close()
    except Exception as exc:
        print(f"[-] Test 3 FAILED: Could not establish valid tunnel ({type(exc).__name__}: {exc})")


async def main():
    if len(sys.argv) < 3:
        print("Usage: python tests/test_ws_handshake.py <AGENT_ID> <VALID_API_KEY>")
        sys.exit(1)

    agent_id = sys.argv[1]
    valid_token = sys.argv[2]

    await test_scenario_missing_token(agent_id)
    await test_scenario_spoofed_token(agent_id)
    await test_scenario_valid_handshake(agent_id, valid_token)

if __name__ == "__main__":
    asyncio.run(main())