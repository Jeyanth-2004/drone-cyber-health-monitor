def generate_response(threat):

    if threat == "Possible DoS":
        return "Recommend Emergency Landing"

    elif threat == "Possible Jamming":
        return "Reconnect Drone"

    elif threat == "Signal Interference":
        return "Stabilize Connection"

    elif threat == "Latency Spike":
        return "Reduce Data Rate"

    else:
        return "System Normal"


def generate_recommended_action(threat, security_score, metrics):
    """Generate a detailed recommended action based on threat, score, and metrics.

    Returns a tuple: (risk_level, risk_color_key, action_text)
        risk_level: str  e.g. "CRITICAL", "HIGH", "MODERATE", "LOW", "NOMINAL"
        risk_color_key: str  one of "critical", "high", "moderate", "low", "nominal"
        action_text: str  multi-line actionable recommendation
    """
    signal = metrics.get("signal", 100)
    latency = metrics.get("latency", 0)
    packet_loss = metrics.get("packet_loss", 0)
    jitter = metrics.get("jitter", 0)

    # ── Critical threats (DoS / Jamming) ─────────────────────
    if threat == "Possible DoS":
        if security_score < 40:
            return (
                "CRITICAL",
                "critical",
                "🔴 Initiate emergency landing IMMEDIATELY.\n"
                f"Packet loss at {packet_loss}% — exceeds safe threshold.\n"
                "Switch to backup communication frequency.\n"
                "Engage return-to-home failsafe."
            )
        return (
            "HIGH",
            "high",
            "🟠 DoS attack detected — packet flooding in progress.\n"
            f"Packet loss: {packet_loss}%  |  Latency: {latency} ms\n"
            "Reduce data rate and enable packet filtering.\n"
            "Prepare for emergency landing if situation worsens."
        )

    if threat == "Possible Jamming":
        if security_score < 40:
            return (
                "CRITICAL",
                "critical",
                "🔴 Severe signal jamming detected.\n"
                f"Signal strength at {signal}% — well below safe range.\n"
                "Activate autonomous return-to-home.\n"
                "Switch to anti-jam frequency hopping."
            )
        return (
            "HIGH",
            "high",
            "🟠 Jamming activity detected on communication channel.\n"
            f"Signal: {signal}%  |  Jitter: {jitter} ms\n"
            "Move drone to higher altitude to improve reception.\n"
            "Prepare manual override if signal degrades further."
        )

    # ── Warning-level threats ────────────────────────────────
    if threat == "Signal Interference":
        if security_score < 50:
            return (
                "HIGH",
                "high",
                "🟠 Persistent signal interference — risk escalating.\n"
                f"Jitter: {jitter} ms  |  Signal: {signal}%\n"
                "Relocate drone away from interference source.\n"
                "Consider switching communication channel."
            )
        return (
            "MODERATE",
            "moderate",
            "🟡 Signal interference detected.\n"
            f"Jitter elevated to {jitter} ms.\n"
            "Monitor for pattern changes.\n"
            "Stabilize connection — adjust antenna orientation."
        )

    if threat == "Latency Spike":
        if security_score < 50:
            return (
                "HIGH",
                "high",
                "🟠 Repeated latency spikes — connection unstable.\n"
                f"Latency: {latency} ms (baseline exceeded).\n"
                "Reduce telemetry data rate immediately.\n"
                "Prepare fallback to autonomous mode."
            )
        return (
            "MODERATE",
            "moderate",
            "🟡 Latency spike detected.\n"
            f"Current latency: {latency} ms.\n"
            "Reduce non-essential data transmission.\n"
            "Monitor for recurring spikes."
        )

    # ── Normal operation ─────────────────────────────────────
    if security_score < 50:
        return (
            "LOW",
            "low",
            "🟢 No active threat, but security score is degraded.\n"
            f"Score: {security_score}/100\n"
            "Continue monitoring — stay alert for anomalies.\n"
            "Consider resetting session if score remains low."
        )

    return (
        "NOMINAL",
        "nominal",
        "✅ All systems nominal. No action required.\n"
        f"Security score: {security_score}/100\n"
        "Continue standard monitoring."
    )