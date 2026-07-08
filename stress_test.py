"""
Drone Connection Stress Tester
Run in a SEPARATE terminal while gui.py is monitoring.

Usage:
    python stress_test.py              (default: ping flood)
    python stress_test.py --mode heavy (large packet flood)
    python stress_test.py --mode burst (intermittent bursts)
"""

import subprocess
import threading
import time
import sys
import os

from config import DRONE_IP

# ─── Stress Test Modes ───────────────────────────────────────

def ping_flood(ip, duration=30):
    """Send rapid continuous pings to overwhelm the connection."""
    print(f"\n{'='*50}")
    print(f"  PING FLOOD → {ip}")
    print(f"  Duration: {duration}s")
    print(f"{'='*50}\n")

    threads = []
    stop_event = threading.Event()

    def _ping_worker(worker_id):
        count = 0
        while not stop_event.is_set():
            try:
                subprocess.run(
                    f"ping {ip} -n 1 -w 500",
                    shell=True, capture_output=True, text=True
                )
                count += 1
                if count % 10 == 0:
                    print(f"  [Worker {worker_id}] Sent {count} pings")
            except Exception:
                pass

    # Launch multiple concurrent ping workers
    print(f"  Launching 8 concurrent ping workers...\n")
    for i in range(8):
        t = threading.Thread(target=_ping_worker, args=(i+1,), daemon=True)
        t.start()
        threads.append(t)

    time.sleep(duration)
    stop_event.set()
    print(f"\n  Flood complete. Check GUI for detected threats.\n")


def heavy_flood(ip, duration=30):
    """Send large packets to stress the WiFi bandwidth."""
    print(f"\n{'='*50}")
    print(f"  HEAVY PACKET FLOOD → {ip}")
    print(f"  Duration: {duration}s | Packet size: 65500 bytes")
    print(f"{'='*50}\n")

    threads = []
    stop_event = threading.Event()

    def _heavy_worker(worker_id):
        count = 0
        while not stop_event.is_set():
            try:
                subprocess.run(
                    f"ping {ip} -n 1 -l 65500 -w 1000",
                    shell=True, capture_output=True, text=True
                )
                count += 1
                if count % 5 == 0:
                    print(f"  [Worker {worker_id}] Sent {count} heavy pings (65500 bytes each)")
            except Exception:
                pass

    print(f"  Launching 4 heavy ping workers...\n")
    for i in range(4):
        t = threading.Thread(target=_heavy_worker, args=(i+1,), daemon=True)
        t.start()
        threads.append(t)

    time.sleep(duration)
    stop_event.set()
    print(f"\n  Heavy flood complete. Check GUI for detected threats.\n")


def burst_mode(ip, duration=60):
    """Send intermittent bursts — simulates periodic interference."""
    print(f"\n{'='*50}")
    print(f"  BURST MODE → {ip}")
    print(f"  Duration: {duration}s | Pattern: 5s burst, 5s pause")
    print(f"{'='*50}\n")

    end_time = time.time() + duration
    burst_num = 0

    while time.time() < end_time:
        burst_num += 1
        print(f"  ⚡ Burst #{burst_num} — flooding for 5 seconds...")

        stop_event = threading.Event()
        threads = []

        def _burst_worker():
            while not stop_event.is_set():
                try:
                    subprocess.run(
                        f"ping {ip} -n 1 -l 65500 -w 500",
                        shell=True, capture_output=True, text=True
                    )
                except Exception:
                    pass

        for i in range(6):
            t = threading.Thread(target=_burst_worker, daemon=True)
            t.start()
            threads.append(t)

        time.sleep(5)
        stop_event.set()

        if time.time() < end_time:
            print(f"  ⏸  Pausing for 5 seconds (GUI should recover)...\n")
            time.sleep(5)

    print(f"\n  Burst mode complete. Check GUI for threat pattern.\n")


# ─── Main ────────────────────────────────────────────────────

if __name__ == "__main__":
    mode = "flood"
    duration = 30

    if "--mode" in sys.argv:
        idx = sys.argv.index("--mode")
        if idx + 1 < len(sys.argv):
            mode = sys.argv[idx + 1]

    if "--duration" in sys.argv:
        idx = sys.argv.index("--duration")
        if idx + 1 < len(sys.argv):
            duration = int(sys.argv[idx + 1])

    print(f"\n  Target: {DRONE_IP}")
    print(f"  Mode:   {mode}")
    print(f"  Press Ctrl+C to stop early\n")

    try:
        if mode == "heavy":
            heavy_flood(DRONE_IP, duration)
        elif mode == "burst":
            burst_mode(DRONE_IP, duration)
        else:
            ping_flood(DRONE_IP, duration)
    except KeyboardInterrupt:
        print("\n\n  Stopped by user. Check GUI for results.\n")
