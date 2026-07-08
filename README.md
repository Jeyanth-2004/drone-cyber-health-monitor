# 🛡️ Drone Cyber Health Monitor

A passive cybersecurity monitoring framework for consumer Wi-Fi drones that analyzes communication behavior in real time to detect cyber threats without modifying the drone firmware or hardware.

---

## 📌 Overview

Drone Cyber Health Monitor continuously evaluates the cybersecurity posture of consumer Wi-Fi drones by monitoring network telemetry such as signal strength, latency, packet loss, and jitter.

The framework computes a **Cyber Health Index (CHI)**, detects abnormal communication behavior, classifies potential threats, and provides real-time response recommendations through an interactive monitoring dashboard.

---

## ✨ Features

- Real-time drone security monitoring
- Cyber Health Index (CHI) calculation
- Adaptive baseline learning
- DoS attack detection
- Signal interference detection
- Jamming detection
- Latency spike detection
- Real-time event logging
- Recommended security response engine
- CSV report generation
- Interactive attack simulation
- GUI dashboard built using Tkinter

---

# Dashboard

## Normal Monitoring

![Normal Dashboard](assets/dashboard_normal.png)

---

## Attack Detection

![Attack Dashboard](assets/dashboard_attack.png)

---

# Project Architecture

```
                Drone
                   │
                   ▼
         Network Monitoring Engine
                   │
                   ▼
          Baseline Learning Module
                   │
                   ▼
          Intrusion Detection Engine
                   │
                   ▼
        Cyber Health Index (CHI)
                   │
                   ▼
        Response Recommendation Engine
                   │
                   ▼
            GUI Monitoring Dashboard
```

---

# Technologies Used

- Python
- Tkinter
- Wi-Fi Network Monitoring
- CSV Logging
- Rule-Based Threat Detection

---

# Project Structure

```
drone-cyber-health-monitor/

baseline.py
config.py
gui.py
intrusion_engine.py
main.py
monitor.py
report.py
response_engine.py
stress_test.py

assets/
    dashboard_normal.png
    dashboard_attack.png

requirements.txt
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/Jeyanth-2004/drone-cyber-health-monitor.git
```

Move into the project

```bash
cd drone-cyber-health-monitor
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python main.py
```

---

# Threats Detected

- Denial of Service (DoS)
- Signal Interference
- Jamming
- Latency Spike
- Abnormal Communication Behaviour

---

# Outputs

The framework provides

- Cyber Health Score
- Threat Classification
- Event Log
- Security Recommendations
- Session Summary
- CSV Report Export

---

# Future Improvements

- Machine Learning–based anomaly detection
- Live packet capture integration
- Support for additional drone communication protocols
- Historical analytics dashboard
- Cloud-based monitoring and alerting

---

# Author

**Jeyanth Kannan**

B.Tech Computer Science and Engineering (Cyber Security)

- LinkedIn: https://www.linkedin.com/in/jeyanth-kannan/
- GitHub: https://github.com/Jeyanth-2004

---

## License

This project is released under the MIT License.
