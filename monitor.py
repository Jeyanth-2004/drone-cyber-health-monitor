import subprocess
import re
from config import DRONE_IP


def get_signal():
    try:
        out = subprocess.check_output(
            "netsh wlan show interfaces", shell=True, text=True
        )
        m = re.search(r"Signal\s*:\s*(\d+)%", out)
        if m:
            return int(m.group(1))
    except:
        pass
    return None


def get_latency():
    try:
        out = subprocess.check_output(
            f"ping {DRONE_IP} -n 1", shell=True, text=True
        )

        if "Reply from" not in out:
            return None

        m = re.search(r"(\d+)\s*ms", out)
        if m:
            return int(m.group(1))

        if "<1ms" in out.replace(" ", ""):
            return 1

    except:
        pass

    return None


def get_packet_loss():
    try:
        out = subprocess.check_output(
            f"ping {DRONE_IP} -n 4", shell=True, text=True
        )

        m = re.search(r"\((\d+)% loss\)", out)

        if m:
            return int(m.group(1))

    except:
        pass

    return 0