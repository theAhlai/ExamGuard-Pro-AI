# ExamGuard Pro AI (ESP32-S3) — Passive Wi-Fi Monitoring for Examination Security

ExamGuard Pro AI is an **ESP32-S3 Arduino** project that provides **passive Wi-Fi spectrum monitoring** and **anomaly-based detection** to support examination invigilation in resource-constrained environments.

It creates a local Wi-Fi access point (`ExamGuard`) and hosts a **web dashboard at `http://192.168.4.1`**. The device periodically scans nearby Wi-Fi access points, compares observations against a captured **baseline**, and raises alerts when suspicious deviations occur. A lightweight on-device scoring/classification module (“TinyML-style AI”) produces **risk scores, confidence, and recommendations**.

> **Ethics & Privacy:** ExamGuard is designed for **metadata-only monitoring** (SSID/BSSID/channel/RSSI/encryption presence). It does **not** capture payload content or decrypt traffic. It is intended as **decision support** for invigilators (human-in-the-loop), not automated accusation or enforcement.

---

## Features

### Passive Monitoring (Metadata Only)
- Periodic Wi-Fi scanning (no active attacks, no jamming)
- Baseline capture (automatic after warmup or manual)
- Watchlist support for APs of interest
- History tracking for trend visibility

### Anomaly Detection Alerts
Detects conditions such as:
- **NEW_AP** — new access point not present in baseline  
- **EVIL_TWIN** — same SSID with different BSSID  
- **CHANNEL_CHANGE** — AP channel changed from baseline  
- **RSSI_ANOMALY** — significant signal strength deviation  
- **HIDDEN_AP** — hidden/cloaked network observed  
- **HIGH_POWER** — unusually strong RSSI  
- **ENCRYPTION_CHANGE** — security mode changed  
- **VENDOR_SPOOF** — vendor/OUI mismatch heuristics  

### Risk Scoring + Decision Support
- Risk score **0–100** and levels (LOW/MEDIUM/HIGH/CRITICAL)
- Alert deduplication + cooldown window
- “AI-assisted” insights (lightweight on-device scoring/classification)

### Web Dashboard + REST API
Runs fully offline via the ESP32 AP.
- Dashboard: `http://192.168.4.1`
- JSON endpoints for status, APs, alerts, history, export, configuration

---

## Hardware Requirements
- **ESP32-S3** development board (recommended)
- Optional external antenna (improves reception/coverage)

---

## Software Requirements
- Arduino IDE / PlatformIO
- ESP32 board support installed
- Libraries:
  - `WiFi` (ESP32 core)
  - `ESPAsyncWebServer`
  - `ArduinoJson`

> If you use PlatformIO, add these to `lib_deps`:
> - ottowinter/ESPAsyncWebServer
> - bblanchon/ArduinoJson

---

## Quick Start

1. Flash the firmware to your ESP32-S3.
2. Power the ESP32.
3. Connect your phone/laptop to the Wi-Fi network:
   - **SSID:** `ExamGuard`
   - **Password:** *(open network by default)*
4. Open:
   - **http://192.168.4.1**
5. Wait for auto-warmup baseline or capture baseline manually.
6. Start monitoring and review alerts/risk score.

---

## How It Works (High-Level)

1. **Scan:** ESP32 performs periodic Wi-Fi scans.
2. **Baseline:** Expected AP environment is saved (BSSID/SSID/channel/encryption/RSSI ranges).
3. **Detect:** New or changed conditions trigger anomaly alerts.
4. **Score:** A lightweight on-device scoring/classification routine generates risk score & suggestions.
5. **Human-in-the-loop:** Invigilators interpret alerts and decide actions using institutional policy.

---

## REST API (Endpoints)

### GET
- `/status` — system state, risk score/level
- `/aps` — latest scan results
- `/alerts` — active alert list
- `/stats` — session statistics
- `/config` — current configuration
- `/channels` — channel observations
- `/watchlist` — watchlist entries
- `/ai` — AI/risk outputs
- `/history` — history points
- `/export` — export data (JSON/CSV depending on implementation)
- `/demo` — demo status/info

### POST
- `/baseline` — capture baseline
- `/reset` — reset system state
- `/clearAlerts` — clear alerts
- `/acknowledgeAlerts` — acknowledge alerts
- `/addWatchlist` — add watchlist item
- `/removeWatchlist` — remove watchlist item
- `/demo/start` — start demo scenario
- `/demo/stop` — stop demo scenario
- `/demo/reset` — reset demo

---

## Configuration Defaults (in code)
- Scan interval: **5000 ms**
- Auto-baseline warmup: **20000 ms**
- Alert cooldown: **60000 ms**
- RSSI anomaly threshold: **20**
- High-power threshold: **-30 dBm** (strong signals above this are suspicious)

You can expose/adjust settings through the UI endpoints (depending on enabled controls).

---

## Demo Mode (Presentation-Friendly)
A built-in demo mode can simulate scenarios (useful for thesis defense and testing). Start/stop demo via:
- `POST /demo/start`
- `POST /demo/stop`

---

## Limitations
- Wi-Fi scans can miss short-lived signals (scan is periodic, not continuous capture).
- RSSI varies with movement, walls, device orientation → may produce false positives.
- This tool indicates **environmental anomalies**, not proof of cheating.
- Detection quality depends on antenna, placement, and local RF noise.

---

