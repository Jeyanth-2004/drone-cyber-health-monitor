import time
from monitor import get_signal, get_latency


def learn_baseline(samples=5):

    signals = []
    latencies = []

    print("Learning baseline behaviour...")

    while len(signals) < samples:

        signal = get_signal()
        latency = get_latency()

        if signal is not None and latency is not None:
            signals.append(signal)
            latencies.append(latency)

            print(f"Sample {len(signals)} → Signal:{signal}% Latency:{latency}ms")

        time.sleep(1)

    baseline = {
        "signal": sum(signals) / len(signals),
        "latency": sum(latencies) / len(latencies)
    }

    print("Baseline learned:", baseline)

    return baseline