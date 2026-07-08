from config import THRESHOLDS


def detect_threat(metrics, baseline):

    threat = "Normal"

    if metrics["packet_loss"] > THRESHOLDS["packet_loss_limit"]:
        threat = "Possible DoS"

    elif metrics["latency"] > baseline["latency"] * 3:
        threat = "Latency Spike"

    elif metrics["jitter"] > THRESHOLDS["jitter_limit"]:
        threat = "Signal Interference"

    elif metrics["signal"] < baseline["signal"] - THRESHOLDS["signal_drop"]:
        threat = "Possible Jamming"

    return threat