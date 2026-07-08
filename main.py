import time
import csv

from monitor import get_signal, get_latency, get_packet_loss
from baseline import learn_baseline
from intrusion_engine import detect_threat
from response_engine import generate_response
from report import generate_report

baseline = learn_baseline()

previous_latency = None
security_score = 100

threat_log = []

with open("security_log.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow([
        "time", "signal", "latency", "packet_loss",
        "jitter", "health", "security_score", "threat"
    ])

print("\nMonitoring drone health...\n")

try:

    while True:

        signal = get_signal()
        latency = get_latency()
        packet_loss = get_packet_loss()

        if signal is None or latency is None:
            print("Drone not responding...")
            time.sleep(2)
            continue

        if previous_latency is None:
            jitter = 0
        else:
            jitter = abs(latency - previous_latency)

        previous_latency = latency

        metrics = {
            "signal": signal,
            "latency": latency,
            "packet_loss": packet_loss,
            "jitter": jitter
        }

        threat = detect_threat(metrics, baseline)

        threat_log.append(threat)

        if threat != "Normal":
            security_score -= 10

        latency_score = max(0, 100 - latency)
        packet_score = max(0, 100 - packet_loss)

        health = (
            0.4 * latency_score +
            0.3 * packet_score +
            0.3 * signal
        )

        response = generate_response(threat)

        timestamp = time.strftime("%H:%M:%S")

        print(
            f"{timestamp} | Sig:{signal}% | Lat:{latency}ms | "
            f"Loss:{packet_loss}% | Jit:{jitter}ms | "
            f"Health:{round(health)} | Sec:{security_score} | {threat}"
        )

        with open("security_log.csv", "a", newline="") as f:
            writer = csv.writer(f)

            writer.writerow([
                timestamp, signal, latency, packet_loss,
                jitter, round(health), security_score, threat
            ])

        print("Response:", response)

        time.sleep(3)

except KeyboardInterrupt:

    generate_report(threat_log)