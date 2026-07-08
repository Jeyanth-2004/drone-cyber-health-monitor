"""
Drone Security Monitor — GUI Dashboard
Run this file: python gui.py
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import time
import csv
import os
import random

from monitor import get_signal, get_latency, get_packet_loss
from baseline import learn_baseline
from intrusion_engine import detect_threat
from response_engine import generate_response, generate_recommended_action

# ─── Color Palette ───────────────────────────────────────────────────────────

BG_DARK       = "#0f1117"
BG_CARD       = "#1a1d2e"
BG_CARD_HOVER = "#222640"
BG_HEADER     = "#12141f"
ACCENT_BLUE   = "#4e8cff"
ACCENT_CYAN   = "#00e5ff"
ACCENT_GREEN  = "#00e676"
ACCENT_YELLOW = "#ffea00"
ACCENT_ORANGE = "#ff9100"
ACCENT_RED    = "#ff1744"
TEXT_PRIMARY   = "#e8eaf6"
TEXT_SECONDARY = "#9ea7c0"
TEXT_DIM       = "#5c637a"
BORDER_COLOR  = "#2a2f45"
BTN_START     = "#00c853"
BTN_STOP      = "#ff1744"
BTN_CLEAR     = "#ff9100"
BTN_EXPORT    = "#4e8cff"


def severity_color(threat):
    """Return a color based on threat type."""
    if threat == "Normal":
        return ACCENT_GREEN
    elif threat in ("Latency Spike", "Signal Interference"):
        return ACCENT_YELLOW
    else:
        return ACCENT_RED


def metric_color(value, low_bad=True, warn=50, crit=25):
    """Return green/yellow/red based on value thresholds.
       low_bad=True means low values are bad (e.g. signal).
       low_bad=False means high values are bad (e.g. latency).
    """
    if low_bad:
        if value >= warn:
            return ACCENT_GREEN
        elif value >= crit:
            return ACCENT_YELLOW
        else:
            return ACCENT_RED
    else:
        if value <= warn:
            return ACCENT_GREEN
        elif value <= crit:
            return ACCENT_YELLOW
        else:
            return ACCENT_RED


class DroneSecurityApp:
    """Main GUI application."""

    def __init__(self, root):
        self.root = root
        self.root.title("Drone Security Monitor")
        self.root.configure(bg=BG_DARK)
        self.root.minsize(1100, 750)

        # Try to maximize or set large geometry
        try:
            self.root.state("zoomed")
        except tk.TclError:
            self.root.geometry("1280x800")

        # ── State ────────────────────────────────────────────────
        self.monitoring = False
        self.sim_mode = False
        self.monitor_thread = None
        self.data_queue = queue.Queue()
        self.threat_log = []
        self.log_rows = []
        self.security_score = 100
        self.baseline = None
        self.event_counter = 0

        # ── Fonts ────────────────────────────────────────────────
        self.FONT_TITLE   = ("Segoe UI", 18, "bold")
        self.FONT_HEADER  = ("Segoe UI", 12, "bold")
        self.FONT_METRIC  = ("Consolas", 28, "bold")
        self.FONT_LABEL   = ("Segoe UI", 10)
        self.FONT_SMALL   = ("Segoe UI", 9)
        self.FONT_LOG     = ("Consolas", 9)
        self.FONT_STATUS  = ("Segoe UI", 11, "bold")
        self.FONT_BTN     = ("Segoe UI", 10, "bold")
        self.FONT_THREAT  = ("Segoe UI", 20, "bold")
        self.FONT_RESP    = ("Segoe UI", 11)

        self._build_ui()
        self._poll_queue()

    # ─────────────────────────────────────────────────────────────
    #  UI CONSTRUCTION
    # ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        """Build all UI components."""
        self._build_header()
        self._build_body()

    def _build_header(self):
        """Top header bar."""
        header = tk.Frame(self.root, bg=BG_HEADER, height=60)
        header.pack(fill=tk.X, side=tk.TOP)
        header.pack_propagate(False)

        # Title
        tk.Label(
            header, text="⬡  DRONE SECURITY MONITOR",
            font=self.FONT_TITLE, fg=ACCENT_CYAN, bg=BG_HEADER
        ).pack(side=tk.LEFT, padx=20, pady=12)

        # Status indicator
        self.status_frame = tk.Frame(header, bg=BG_HEADER)
        self.status_frame.pack(side=tk.RIGHT, padx=20)

        self.status_dot = tk.Label(
            self.status_frame, text="●", font=("Segoe UI", 14),
            fg=TEXT_DIM, bg=BG_HEADER
        )
        self.status_dot.pack(side=tk.LEFT, padx=(0, 6))

        self.status_label = tk.Label(
            self.status_frame, text="IDLE", font=self.FONT_STATUS,
            fg=TEXT_DIM, bg=BG_HEADER
        )
        self.status_label.pack(side=tk.LEFT)

    def _build_body(self):
        """Main body below the header."""
        body = tk.Frame(self.root, bg=BG_DARK)
        body.pack(fill=tk.BOTH, expand=True, padx=16, pady=(10, 16))

        # ── Top row: metric cards ────────────────────────────
        self._build_metric_cards(body)

        # ── Middle: Threat panel + Log ───────────────────────
        mid = tk.Frame(body, bg=BG_DARK)
        mid.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        # Left column — threat + report + simulator + controls
        left_col = tk.Frame(mid, bg=BG_DARK, width=400)
        left_col.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        left_col.pack_propagate(False)

        self._build_controls(left_col)       # pack BOTTOM first to reserve space
        self._build_threat_panel(left_col)
        self._build_action_panel(left_col)
        self._build_report_panel(left_col)
        self._build_sim_panel(left_col)

        # Right column — log + range table
        right_col = tk.Frame(mid, bg=BG_DARK)
        right_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_log_panel(right_col)
        self._build_range_table(right_col)

    # ── Metric Cards ─────────────────────────────────────────

    def _build_metric_cards(self, parent):
        cards_frame = tk.Frame(parent, bg=BG_DARK)
        cards_frame.pack(fill=tk.X)

        self.metric_cards = {}
        metrics = [
            ("signal",       "SIGNAL",         "%",  "—"),
            ("latency",      "LATENCY",        "ms", "—"),
            ("packet_loss",  "PACKET LOSS",    "%",  "—"),
            ("jitter",       "JITTER",         "ms", "—"),
            ("health",       "HEALTH",         "",   "—"),
            ("security",     "SECURITY SCORE", "",   "100"),
        ]

        for i, (key, label, unit, default) in enumerate(metrics):
            card = self._create_metric_card(cards_frame, label, unit, default)
            card.grid(row=0, column=i, padx=6, pady=4, sticky="nsew")
            self.metric_cards[key] = card
            cards_frame.columnconfigure(i, weight=1)

    def _create_metric_card(self, parent, label, unit, default_value):
        """Create a single metric card and return a dict with widget refs."""
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                         highlightthickness=1, padx=16, pady=12)

        lbl = tk.Label(frame, text=label, font=self.FONT_LABEL,
                       fg=TEXT_SECONDARY, bg=BG_CARD)
        lbl.pack(anchor="w")

        val_frame = tk.Frame(frame, bg=BG_CARD)
        val_frame.pack(anchor="w", pady=(4, 0))

        val = tk.Label(val_frame, text=default_value, font=self.FONT_METRIC,
                       fg=TEXT_PRIMARY, bg=BG_CARD)
        val.pack(side=tk.LEFT)

        unit_lbl = tk.Label(val_frame, text=unit, font=self.FONT_LABEL,
                            fg=TEXT_DIM, bg=BG_CARD)
        unit_lbl.pack(side=tk.LEFT, padx=(4, 0), anchor="s", pady=(0, 4))

        # Store refs
        frame._value_label = val
        frame._unit_label = unit_lbl
        return frame

    def _update_card(self, key, value, color=None):
        card = self.metric_cards[key]
        card._value_label.config(text=str(value))
        if color:
            card._value_label.config(fg=color)

    # ── Threat Panel ─────────────────────────────────────────

    def _build_threat_panel(self, parent):
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                         highlightthickness=1)
        frame.pack(fill=tk.X, pady=(0, 4))

        tk.Label(frame, text="THREAT STATUS", font=self.FONT_HEADER,
                 fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w", padx=12, pady=(6, 2))

        self.threat_label = tk.Label(
            frame, text="—", font=("Segoe UI", 14, "bold"),
            fg=TEXT_DIM, bg=BG_CARD
        )
        self.threat_label.pack(anchor="w", padx=12, pady=(0, 1))

        self.response_label = tk.Label(
            frame, text="", font=("Segoe UI", 9),
            fg=TEXT_SECONDARY, bg=BG_CARD
        )
        self.response_label.pack(anchor="w", padx=12, pady=(0, 6))

    # ── Recommended Action Panel ─────────────────────────────

    # Color mapping for risk levels
    RISK_COLORS = {
        "critical": ACCENT_RED,
        "high":     ACCENT_ORANGE,
        "moderate": ACCENT_YELLOW,
        "low":      ACCENT_GREEN,
        "nominal":  ACCENT_GREEN,
    }

    def _build_action_panel(self, parent):
        """Build a panel that shows auto-generated recommended actions."""
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=ACCENT_CYAN,
                         highlightthickness=1)
        frame.pack(fill=tk.X, pady=(0, 4))

        tk.Label(frame, text="RECOMMENDED ACTION", font=self.FONT_HEADER,
                 fg=ACCENT_CYAN, bg=BG_CARD).pack(anchor="w", padx=12, pady=(6, 2))

        # Risk level badge
        self.risk_level_label = tk.Label(
            frame, text="● NOMINAL", font=("Segoe UI", 11, "bold"),
            fg=ACCENT_GREEN, bg=BG_CARD
        )
        self.risk_level_label.pack(anchor="w", padx=12, pady=(0, 2))

        # Multi-line action text
        self.action_text_label = tk.Label(
            frame, text="✅ Awaiting data…",
            font=("Segoe UI", 9), fg=TEXT_SECONDARY, bg=BG_CARD,
            justify=tk.LEFT, anchor="nw", wraplength=350
        )
        self.action_text_label.pack(anchor="w", padx=12, pady=(0, 8), fill=tk.X)

    def _update_action_panel(self, threat, security_score, metrics):
        """Update the recommended action panel based on current state."""
        risk_level, color_key, action_text = generate_recommended_action(
            threat, security_score, metrics
        )
        color = self.RISK_COLORS.get(color_key, TEXT_SECONDARY)

        self.risk_level_label.config(text=f"● {risk_level}", fg=color)
        self.action_text_label.config(text=action_text, fg=color)

        # Flash the panel border to draw attention on non-nominal states
        if color_key in ("critical", "high"):
            self.action_text_label.master.config(highlightbackground=color)
        else:
            self.action_text_label.master.config(highlightbackground=ACCENT_CYAN)

    # ── Report Panel ─────────────────────────────────────────

    def _build_report_panel(self, parent):
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                         highlightthickness=1)
        frame.pack(fill=tk.X, pady=(0, 4))

        tk.Label(frame, text="SESSION REPORT", font=self.FONT_HEADER,
                 fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w", padx=12, pady=(6, 3))

        self.report_vars = {}
        items = [
            ("total",        "Total Events",      ACCENT_CYAN),
            ("dos",          "DoS Events",         ACCENT_RED),
            ("jamming",      "Jamming Events",     ACCENT_ORANGE),
            ("interference", "Interference Events", ACCENT_YELLOW),
            ("normal",       "Normal Events",       ACCENT_GREEN),
        ]

        for key, label, color in items:
            row = tk.Frame(frame, bg=BG_CARD)
            row.pack(fill=tk.X, padx=12, pady=1)

            tk.Label(row, text=label, font=("Segoe UI", 9),
                     fg=TEXT_SECONDARY, bg=BG_CARD).pack(side=tk.LEFT)

            count_lbl = tk.Label(row, text="0", font=("Consolas", 10, "bold"),
                                 fg=color, bg=BG_CARD)
            count_lbl.pack(side=tk.RIGHT)
            self.report_vars[key] = count_lbl

        # bottom padding
        tk.Frame(frame, bg=BG_CARD, height=4).pack()

    def _update_report(self):
        total = len(self.threat_log)
        dos = self.threat_log.count("Possible DoS")
        jam = self.threat_log.count("Possible Jamming")
        interf = self.threat_log.count("Signal Interference")
        normal = self.threat_log.count("Normal")
        latency_spike = self.threat_log.count("Latency Spike")

        self.report_vars["total"].config(text=str(total))
        self.report_vars["dos"].config(text=str(dos))
        self.report_vars["jamming"].config(text=str(jam))
        self.report_vars["interference"].config(text=str(interf + latency_spike))
        self.report_vars["normal"].config(text=str(normal))

    # ── Simulation Panel ──────────────────────────────────────

    def _build_sim_panel(self, parent):
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground="#ff6d00",
                         highlightthickness=1)
        frame.pack(fill=tk.X, pady=(0, 4))

        header = tk.Frame(frame, bg=BG_CARD)
        header.pack(fill=tk.X, padx=12, pady=(5, 3))

        tk.Label(header, text="⚠  ATTACK SIMULATOR", font=self.FONT_HEADER,
                 fg="#ff6d00", bg=BG_CARD).pack(side=tk.LEFT)

        self.sim_status_lbl = tk.Label(
            header, text="", font=self.FONT_SMALL,
            fg=TEXT_DIM, bg=BG_CARD
        )
        self.sim_status_lbl.pack(side=tk.RIGHT)

        # Attack buttons
        attacks = [
            ("💣 DoS Attack",          ACCENT_RED,    lambda: self._simulate_attack("dos")),
            ("📡 Jamming Attack",      ACCENT_ORANGE, lambda: self._simulate_attack("jamming")),
            ("⚡ Signal Interference",  ACCENT_YELLOW, lambda: self._simulate_attack("interference")),
            ("📈 Latency Spike",       "#7c4dff",     lambda: self._simulate_attack("latency_spike")),
            ("✅ Normal (Reset)",       ACCENT_GREEN,  lambda: self._simulate_attack("normal")),
        ]

        for text, color, cmd in attacks:
            btn = tk.Button(
                frame, text=text, font=("Segoe UI", 8, "bold"),
                fg="#ffffff", bg=color, activebackground=color,
                activeforeground="#ffffff", relief=tk.FLAT,
                cursor="hand2", command=cmd, padx=6, pady=1,
                anchor="w"
            )
            btn.pack(fill=tk.X, padx=10, pady=1)

        # bottom padding
        tk.Frame(frame, bg=BG_CARD, height=3).pack()

    def _simulate_attack(self, attack_type):
        """Inject a simulated attack event into the dashboard."""
        if self.baseline is None:
            # Use a default baseline if monitoring hasn't started
            self.baseline = {"signal": 95, "latency": 20}

        # Detection order in detect_threat():
        #   1. packet_loss > 10       → "Possible DoS"
        #   2. latency > baseline*3   → "Latency Spike"
        #   3. jitter > 40            → "Signal Interference"
        #   4. signal < baseline-25   → "Possible Jamming"
        #
        # Each attack's metrics are tuned so ONLY its rule triggers.

        baseline_lat = self.baseline.get("latency", 20)
        baseline_sig = self.baseline.get("signal", 95)
        lat_spike_threshold = baseline_lat * 3

        if attack_type == "dos":
            # Trigger rule 1 (packet_loss > 10). Keep others below thresholds.
            metrics = {
                "signal": random.randint(70, 90),
                "latency": random.randint(5, max(5, min(int(lat_spike_threshold) - 1, 50))),
                "packet_loss": random.randint(15, 50),
                "jitter": random.randint(5, 35),
            }
        elif attack_type == "jamming":
            # Trigger rule 4 (signal < baseline-25). Keep rules 1-3 safe.
            max_signal = max(0, int(baseline_sig) - 26)
            metrics = {
                "signal": random.randint(max(0, max_signal - 30), max_signal),
                "latency": random.randint(5, max(5, min(int(lat_spike_threshold) - 1, 50))),
                "packet_loss": random.randint(0, 8),
                "jitter": random.randint(5, 35),
            }
        elif attack_type == "interference":
            # Trigger rule 3 (jitter > 40). Keep rules 1-2 safe.
            metrics = {
                "signal": random.randint(75, 95),
                "latency": random.randint(5, max(5, min(int(lat_spike_threshold) - 1, 50))),
                "packet_loss": random.randint(0, 8),
                "jitter": random.randint(45, 90),
            }
        elif attack_type == "latency_spike":
            # Trigger rule 2 (latency > baseline*3). Keep rule 1 safe.
            metrics = {
                "signal": random.randint(80, 100),
                "latency": random.randint(int(lat_spike_threshold) + 10, int(lat_spike_threshold) + 300),
                "packet_loss": random.randint(0, 8),
                "jitter": random.randint(5, 35),
            }
        else:  # normal
            metrics = {
                "signal": random.randint(85, 100),
                "latency": random.randint(1, max(1, min(int(lat_spike_threshold) - 1, 15))),
                "packet_loss": 0,
                "jitter": random.randint(0, 5),
            }

        # Run through the real detection engine
        threat = detect_threat(metrics, self.baseline)
        response = generate_response(threat)

        latency_score = max(0, 100 - metrics["latency"])
        packet_score = max(0, 100 - metrics["packet_loss"])
        health = round(0.4 * latency_score + 0.3 * packet_score + 0.3 * metrics["signal"])

        if threat != "Normal":
            penalty = 5 if threat in ("Latency Spike", "Signal Interference") else 10
            self.security_score = max(0, self.security_score - penalty)

        self.event_counter += 1
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        data = {
            "type": "metric",
            "event_id": self.event_counter,
            "time": timestamp,
            "source": "simulation",
            "signal": metrics["signal"],
            "latency": metrics["latency"],
            "packet_loss": metrics["packet_loss"],
            "jitter": metrics["jitter"],
            "health": health,
            "security": self.security_score,
            "threat": threat,
            "response": response,
        }

        # Push to queue for UI update
        self.data_queue.put(data)

        # Write to CSV
        self._ensure_csv_header()
        with open("security_log.csv", "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                self.event_counter, timestamp, "simulation",
                metrics["signal"], metrics["latency"],
                metrics["packet_loss"], metrics["jitter"], health,
                self.security_score, threat, response
            ])

        # Flash the sim status
        label_text = f"SIM: {attack_type.replace('_', ' ').upper()}"
        self.sim_status_lbl.config(text=label_text, fg=ACCENT_RED if attack_type != "normal" else ACCENT_GREEN)

    # ── Controls ─────────────────────────────────────────────

    def _build_controls(self, parent):
        frame = tk.Frame(parent, bg=BG_DARK)
        frame.pack(fill=tk.X, pady=(0, 0), side=tk.BOTTOM)

        # START and STOP side by side
        row1 = tk.Frame(frame, bg=BG_DARK)
        row1.pack(fill=tk.X, pady=(0, 3))

        self.btn_start = tk.Button(
            row1, text="▶ START", font=("Segoe UI", 9, "bold"),
            fg="#ffffff", bg=BTN_START, activebackground=BTN_START,
            activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", command=self._start, padx=8, pady=4
        )
        self.btn_start.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 2))

        self.btn_stop = tk.Button(
            row1, text="■ STOP", font=("Segoe UI", 9, "bold"),
            fg="#ffffff", bg=BTN_STOP, activebackground=BTN_STOP,
            activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", command=self._stop, padx=8, pady=4
        )
        self.btn_stop.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(2, 0))
        self.btn_stop.config(state=tk.DISABLED)

        # CLEAR and EXPORT side by side
        row2 = tk.Frame(frame, bg=BG_DARK)
        row2.pack(fill=tk.X, pady=(0, 3))

        self.btn_clear = tk.Button(
            row2, text="CLEAR LOG", font=("Segoe UI", 9, "bold"),
            fg="#ffffff", bg=BTN_CLEAR, activebackground=BTN_CLEAR,
            activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", command=self._clear_log, padx=8, pady=4
        )
        self.btn_clear.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 2))

        self.btn_export = tk.Button(
            row2, text="EXPORT CSV", font=("Segoe UI", 9, "bold"),
            fg="#ffffff", bg=BTN_EXPORT, activebackground=BTN_EXPORT,
            activeforeground="#ffffff", relief=tk.FLAT,
            cursor="hand2", command=self._export_csv, padx=8, pady=4
        )
        self.btn_export.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(2, 0))

    # ── Range Table ──────────────────────────────────────────

    def _build_range_table(self, parent):
        """Build a compact safe-operating-ranges reference table."""
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                         highlightthickness=1)
        frame.pack(fill=tk.X, pady=(8, 0))

        tk.Label(frame, text="SAFE OPERATING RANGES", font=self.FONT_HEADER,
                 fg=TEXT_SECONDARY, bg=BG_CARD).pack(anchor="w", padx=12, pady=(10, 6))

        # Table header
        hdr = tk.Frame(frame, bg="#1e2236")
        hdr.pack(fill=tk.X, padx=8)

        hdr_cols = [("METRIC", 12), ("✅ SAFE", 12), ("⚠ WARNING", 12), ("🔴 CRITICAL", 12)]
        for text, w in hdr_cols:
            tk.Label(hdr, text=text, font=("Consolas", 9, "bold"),
                     fg=TEXT_DIM, bg="#1e2236", width=w, anchor="w"
                     ).pack(side=tk.LEFT, padx=4, pady=4)

        # Table rows
        ranges = [
            ("Signal",      "> 60%",     "30 – 60%",    "< 30%"),
            ("Latency",     "< 100 ms",  "100 – 200 ms", "> 200 ms"),
            ("Packet Loss", "< 5%",      "5 – 10%",     "> 10%"),
            ("Jitter",      "< 20 ms",   "20 – 40 ms",  "> 40 ms"),
        ]

        for i, (metric, safe, warn, crit) in enumerate(ranges):
            row_bg = BG_CARD if i % 2 == 0 else "#14162a"
            row = tk.Frame(frame, bg=row_bg)
            row.pack(fill=tk.X, padx=8)

            tk.Label(row, text=metric, font=("Consolas", 9, "bold"),
                     fg=TEXT_PRIMARY, bg=row_bg, width=12, anchor="w"
                     ).pack(side=tk.LEFT, padx=4, pady=3)
            tk.Label(row, text=safe, font=("Consolas", 9),
                     fg=ACCENT_GREEN, bg=row_bg, width=12, anchor="w"
                     ).pack(side=tk.LEFT, padx=4, pady=3)
            tk.Label(row, text=warn, font=("Consolas", 9),
                     fg=ACCENT_YELLOW, bg=row_bg, width=12, anchor="w"
                     ).pack(side=tk.LEFT, padx=4, pady=3)
            tk.Label(row, text=crit, font=("Consolas", 9),
                     fg=ACCENT_RED, bg=row_bg, width=12, anchor="w"
                     ).pack(side=tk.LEFT, padx=4, pady=3)

        # Bottom padding
        tk.Frame(frame, bg=BG_CARD, height=8).pack()

    # ── Log Panel ────────────────────────────────────────────

    def _build_log_panel(self, parent):
        frame = tk.Frame(parent, bg=BG_CARD, highlightbackground=BORDER_COLOR,
                         highlightthickness=1)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        header = tk.Frame(frame, bg=BG_CARD)
        header.pack(fill=tk.X, padx=16, pady=(14, 8))

        tk.Label(header, text="EVENT LOG", font=self.FONT_HEADER,
                 fg=TEXT_SECONDARY, bg=BG_CARD).pack(side=tk.LEFT)

        self.log_count_label = tk.Label(
            header, text="0 events", font=self.FONT_SMALL,
            fg=TEXT_DIM, bg=BG_CARD
        )
        self.log_count_label.pack(side=tk.RIGHT)

        # Column headers
        col_frame = tk.Frame(frame, bg="#1e2236")
        col_frame.pack(fill=tk.X, padx=8)

        cols = [
            ("#",        4),
            ("TIME",     19),
            ("SRC",      4),
            ("SIG %",    6),
            ("LAT ms",   7),
            ("LOSS %",   7),
            ("JIT ms",   7),
            ("HEALTH",   7),
            ("SEC",      5),
            ("THREAT",   16),
        ]

        for col_name, width in cols:
            tk.Label(
                col_frame, text=col_name, font=("Consolas", 9, "bold"),
                fg=TEXT_DIM, bg="#1e2236", width=width, anchor="w"
            ).pack(side=tk.LEFT, padx=2, pady=4)

        # Scrollable log area
        log_container = tk.Frame(frame, bg=BG_DARK)
        log_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.log_canvas = tk.Canvas(log_container, bg=BG_DARK,
                                    highlightthickness=0)
        scrollbar = tk.Scrollbar(log_container, orient=tk.VERTICAL,
                                 command=self.log_canvas.yview)

        self.log_inner = tk.Frame(self.log_canvas, bg=BG_DARK)
        self.log_inner.bind(
            "<Configure>",
            lambda e: self.log_canvas.configure(scrollregion=self.log_canvas.bbox("all"))
        )

        self.log_canvas.create_window((0, 0), window=self.log_inner, anchor="nw")
        self.log_canvas.configure(yscrollcommand=scrollbar.set)

        self.log_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Mouse wheel scrolling
        self.log_canvas.bind_all(
            "<MouseWheel>",
            lambda e: self.log_canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        )

    def _add_log_entry(self, data):
        """Add a row to the log panel."""
        row_bg = BG_DARK if len(self.log_rows) % 2 == 0 else "#14162a"
        row_frame = tk.Frame(self.log_inner, bg=row_bg)
        row_frame.pack(fill=tk.X)

        threat_color = severity_color(data["threat"])

        source_abbr = "SIM" if data.get("source") == "simulation" else "MON"
        source_color = ACCENT_ORANGE if source_abbr == "SIM" else ACCENT_CYAN

        values = [
            (str(data.get("event_id", "")), 4, TEXT_DIM),
            (data["time"],          19, TEXT_SECONDARY),
            (source_abbr,            4, source_color),
            (str(data["signal"]),   6,  metric_color(data["signal"], low_bad=True, warn=60, crit=30)),
            (str(data["latency"]),  7,  metric_color(data["latency"], low_bad=False, warn=100, crit=200)),
            (str(data["packet_loss"]), 7, metric_color(data["packet_loss"], low_bad=False, warn=5, crit=10)),
            (str(data["jitter"]),   7,  metric_color(data["jitter"], low_bad=False, warn=20, crit=40)),
            (str(data["health"]),   7,  metric_color(data["health"], low_bad=True, warn=70, crit=40)),
            (str(data["security"]), 5,  metric_color(data["security"], low_bad=True, warn=70, crit=40)),
            (data["threat"],        16, threat_color),
        ]

        for text, width, fg in values:
            tk.Label(
                row_frame, text=text, font=self.FONT_LOG,
                fg=fg, bg=row_bg, width=width, anchor="w"
            ).pack(side=tk.LEFT, padx=2, pady=1)

        self.log_rows.append(row_frame)
        self.log_count_label.config(text=f"{len(self.log_rows)} events")

        # Auto-scroll to bottom
        self.log_canvas.update_idletasks()
        self.log_canvas.yview_moveto(1.0)

    # ─────────────────────────────────────────────────────────
    #  MONITORING THREAD
    # ─────────────────────────────────────────────────────────

    def _monitor_loop(self):
        """Runs in a background thread."""
        previous_latency = None

        while self.monitoring:
            signal = get_signal()
            latency = get_latency()
            packet_loss = get_packet_loss()

            if signal is None or latency is None:
                self.data_queue.put({"type": "status", "msg": "Drone not responding..."})
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
                "jitter": jitter,
            }

            threat = detect_threat(metrics, self.baseline)
            response = generate_response(threat)


            latency_score = max(0, 100 - latency)
            packet_score = max(0, 100 - packet_loss)
            health = round(0.4 * latency_score + 0.3 * packet_score + 0.3 * signal)

            if threat != "Normal":
                penalty = 5 if threat in ("Latency Spike", "Signal Interference") else 10
                self.security_score = max(0, self.security_score - penalty)

            self.event_counter += 1
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

            data = {
                "type": "metric",
                "event_id": self.event_counter,
                "time": timestamp,
                "source": "monitor",
                "signal": signal,
                "latency": latency,
                "packet_loss": packet_loss,
                "jitter": jitter,
                "health": health,
                "security": self.security_score,
                "threat": threat,
                "response": response,
            }

            self.data_queue.put(data)

            # Write to CSV
            self._ensure_csv_header()
            with open("security_log.csv", "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    self.event_counter, timestamp, "monitor",
                    signal, latency, packet_loss,
                    jitter, health, self.security_score, threat, response
                ])

            time.sleep(3)

    # ─────────────────────────────────────────────────────────
    #  QUEUE POLLING (thread-safe UI updates)
    # ─────────────────────────────────────────────────────────

    def _poll_queue(self):
        """Check the queue for new data from the monitor thread."""
        try:
            while True:
                data = self.data_queue.get_nowait()

                if data["type"] == "status":
                    self.status_label.config(text=data["msg"], fg=ACCENT_YELLOW)
                    continue

                if data["type"] == "baseline_done":
                    self.status_label.config(text="BASELINE READY", fg=ACCENT_GREEN)
                    continue

                if data["type"] == "baseline_sample":
                    self.status_label.config(
                        text=f"LEARNING... {data['msg']}", fg=ACCENT_CYAN
                    )
                    continue

                # Metric update
                self._update_card("signal",      data["signal"],
                                  metric_color(data["signal"], low_bad=True, warn=60, crit=30))
                self._update_card("latency",     data["latency"],
                                  metric_color(data["latency"], low_bad=False, warn=100, crit=200))
                self._update_card("packet_loss", data["packet_loss"],
                                  metric_color(data["packet_loss"], low_bad=False, warn=5, crit=10))
                self._update_card("jitter",      data["jitter"],
                                  metric_color(data["jitter"], low_bad=False, warn=20, crit=40))
                self._update_card("health",      data["health"],
                                  metric_color(data["health"], low_bad=True, warn=70, crit=40))
                self._update_card("security",    data["security"],
                                  metric_color(data["security"], low_bad=True, warn=70, crit=40))

                # Threat panel
                tc = severity_color(data["threat"])
                self.threat_label.config(text=data["threat"], fg=tc)
                self.response_label.config(
                    text=f"⚡ {data['response']}", fg=TEXT_SECONDARY
                )

                # Recommended action panel
                metrics = {
                    "signal": data["signal"],
                    "latency": data["latency"],
                    "packet_loss": data["packet_loss"],
                    "jitter": data["jitter"],
                }
                self._update_action_panel(
                    data["threat"], data["security"], metrics
                )

                # Log
                self.threat_log.append(data["threat"])
                self._add_log_entry(data)
                self._update_report()

        except queue.Empty:
            pass

        self.root.after(200, self._poll_queue)

    # ─────────────────────────────────────────────────────────
    #  BUTTON ACTIONS
    # ─────────────────────────────────────────────────────────

    def _ensure_csv_header(self):
        """Write CSV header if the file doesn't exist or is empty."""
        header = [
            "event_id", "timestamp", "source", "signal", "latency",
            "packet_loss", "jitter", "health", "security_score",
            "threat", "response"
        ]
        if not os.path.exists("security_log.csv") or os.path.getsize("security_log.csv") == 0:
            with open("security_log.csv", "w", newline="") as f:
                csv.writer(f).writerow(header)

    def _start(self):
        if self.monitoring:
            return

        self.monitoring = True
        self.security_score = 100
        self.event_counter = 0
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status_dot.config(fg=ACCENT_GREEN)
        self.status_label.config(text="LEARNING BASELINE...", fg=ACCENT_CYAN)

        # Ensure CSV has a header (append mode — preserves previous data)
        self._ensure_csv_header()

        def _baseline_and_monitor():
            # Learn baseline with progress updates
            signals = []
            latencies = []
            samples = 5
            while len(signals) < samples and self.monitoring:
                signal = get_signal()
                latency = get_latency()
                if signal is not None and latency is not None:
                    signals.append(signal)
                    latencies.append(latency)
                    self.data_queue.put({
                        "type": "baseline_sample",
                        "msg": f"Sample {len(signals)}/{samples}  Sig:{signal}%  Lat:{latency}ms"
                    })
                time.sleep(1)

            if not self.monitoring:
                return

            self.baseline = {
                "signal": sum(signals) / len(signals),
                "latency": sum(latencies) / len(latencies),
            }
            self.data_queue.put({"type": "baseline_done"})
            time.sleep(0.5)

            # Start monitoring
            if self.monitoring:
                self.data_queue.put({
                    "type": "status",
                    "msg": "MONITORING"
                })
                # Update status to show monitoring
                self.root.after(0, lambda: self.status_label.config(
                    text="MONITORING", fg=ACCENT_GREEN
                ))
                self._monitor_loop()

        self.monitor_thread = threading.Thread(
            target=_baseline_and_monitor, daemon=True
        )
        self.monitor_thread.start()

    def _stop(self):
        self.monitoring = False
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status_dot.config(fg=ACCENT_RED)
        self.status_label.config(text="STOPPED", fg=ACCENT_RED)


    def _clear_log(self):
        for widget in self.log_inner.winfo_children():
            widget.destroy()
        self.log_rows.clear()
        self.threat_log.clear()
        self.log_count_label.config(text="0 events")
        self._update_report()

        # Reset metric cards
        for key in self.metric_cards:
            default = "100" if key == "security" else "—"
            self._update_card(key, default, TEXT_PRIMARY)

        self.threat_label.config(text="—", fg=TEXT_DIM)
        self.response_label.config(text="")
        self.risk_level_label.config(text="● NOMINAL", fg=ACCENT_GREEN)
        self.action_text_label.config(text="✅ Awaiting data…", fg=TEXT_SECONDARY)
        self.action_text_label.master.config(highlightbackground=ACCENT_CYAN)
        self.security_score = 100
        self.event_counter = 0

    def _export_csv(self):
        if not self.log_rows:
            messagebox.showinfo("Export", "No data to export.")
            return

        filename = f"drone_report_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        try:
            with open(filename, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "event_id", "timestamp", "source", "signal", "latency",
                    "packet_loss", "jitter", "health", "security_score",
                    "threat", "response"
                ])
                # Read from the existing log file
                if os.path.exists("security_log.csv"):
                    with open("security_log.csv", "r") as src:
                        reader = csv.reader(src)
                        next(reader)  # skip header
                        for row in reader:
                            writer.writerow(row)

            messagebox.showinfo("Export", f"Report saved to:\n{os.path.abspath(filename)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))


# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app = DroneSecurityApp(root)
    root.mainloop()
