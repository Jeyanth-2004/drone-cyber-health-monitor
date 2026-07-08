DRONE_IP = "192.168.169.1"

THRESHOLDS = {
    "latency_spike": 200,     # ms
    "jitter_limit": 40,       # ms
    "packet_loss_limit": 10,  # %
    "signal_drop": 25         # %
}

HEALTH_WEIGHTS = {
    "latency": 0.4,
    "packet_loss": 0.3,
    "signal": 0.3
}