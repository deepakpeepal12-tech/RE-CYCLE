"""
RE-CYCLE machine simulator (for testing before ESP32 hardware arrives).
Run this in a SECOND terminal while app.py is running.
"""
import json
import os
import time
import urllib.request
import urllib.error

SERVER_URL = os.environ.get("SERVER_URL", "http://127.0.0.1:5000").rstrip("/")
MACHINE_TOKEN = os.environ.get("MACHINE_TOKEN", "")

def call(path, method="GET", payload=None):
    headers = {"X-Machine-Token": MACHINE_TOKEN}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(SERVER_URL + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))

def main():
    if not MACHINE_TOKEN:
        print("Set MACHINE_TOKEN in this terminal to the same value used by app.py.")
        return
    print("RE-CYCLE hardware simulator")
    print("Create a recycling session from the website first.")
    print("Waiting for a user session...")
    session = None
    while session is None:
        try:
            result = call("/api/machine/next")
            if result.get("has_session"):
                session = result
            else:
                time.sleep(2)
        except Exception as e:
            print("Connection error:", e)
            time.sleep(3)

    sid = session["session_id"]
    expected = int(session["expected"])
    print(f"\nSession #{sid} received. Website expects {expected} bottle(s).")
    print("Enter the number of bottles to simulate (e.g. 2).")
    try:
        detected = int(input("How many bottles did the virtual sensor detect? ").strip())
    except ValueError:
        print("Please enter a whole number.")
        return
    detected = max(0, min(detected, 1000))
    call("/api/machine/update", "POST", {
        "session_id": sid, "detected": detected, "bin_full": False, "event": "counting"
    })
    print(f"Sent live count: {detected}/{expected}")
    input("Press ENTER to simulate the end of the bottle insertion period...")
    final = call("/api/machine/update", "POST", {
        "session_id": sid, "detected": detected, "bin_full": False, "event": "finish"
    })
    print("\nFinal result:", final.get("status", "unknown").upper())
    print("Points awarded:", final.get("points", 0))
    print(final.get("message", ""))

if __name__ == "__main__":
    main()
