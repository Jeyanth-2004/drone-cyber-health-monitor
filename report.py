def generate_report(threat_log):

    total = len(threat_log)

    dos = threat_log.count("Possible DoS")
    jam = threat_log.count("Possible Jamming")
    interference = threat_log.count("Signal Interference")

    print("\n===== SESSION REPORT =====")

    print("Total Events:", total)
    print("DoS Events:", dos)
    print("Jamming Events:", jam)
    print("Interference Events:", interference)