# 🛰️ Live Location Tracker
### Full-Stack Hybrid Intelligence System

> An academic project at **Air University** — combining real-time GPS tracking, OSINT intelligence, VPN detection, and C++ powered geofencing in a single web application.

---

## 👥 Team

| Name | Department |
|------|------------|
| Muhammad Faisal Rahman | BS Cyber Security |
| Muhammad Bilal | BS Cyber Security |
| Zain Asif | BS Cyber Security |

**Section:** F-24-A &nbsp;|&nbsp; **Course:** DSA & COAL

---

## 📋 Overview

Most location tracking tools do one thing — track. This system does five:

- **Tracks** real-time GPS location via a trap link
- **Detects** VPN and Proxy usage automatically
- **Scans** email MX records and social media profiles (OSINT)
- **Geofences** using a compiled C++ kernel for microsecond-speed calculations
- **Visualizes** everything on a live interactive map dashboard

---

## 🏗️ Architecture

```
React Frontend (Vite)
        │
        │  HTTP Requests
        ▼
Python Flask Backend  ──────────►  SQLite Database
        │                          (tracking_data.db)
        │
        ├──► C++ Kernel (geofence.dll)
        │       └── Ray Casting Algorithm
        │       └── Shoelace Formula
        │
        └──► OSINT Engine (multi-threaded)
                └── Email MX Record Scanner
                └── Social Media Profile Checker
                └── VPN / Proxy Heuristics
```

---

## 🧰 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React + Vite + React-Leaflet + Lucide Icons |
| Backend | Python Flask + SQLite |
| Performance | C++ DLL (geofence.dll) via ctypes |
| Tunneling | Ngrok |
| Algorithms | Ray Casting, Shoelace Formula |

---

## ✨ Features

### 🎯 Real-Time Location Tracking
Generate a trap link and send it to a target. When they click "Verify" on the fake Cloudflare page, their IP is captured instantly. If GPS is allowed, live coordinates appear as a pin on the map.

### 🔍 OSINT Scanning
Enter an email or username — the backend spawns background threads to scan GitHub, Reddit, Instagram, and DNS MX records simultaneously without freezing the UI.

### 🛡️ VPN / Proxy Detection
Analyzes HTTP headers (`X-Forwarded-For`, `Via`) to detect proxies. Displays a red badge for VPN users and green for residential connections.

### 🗺️ C++ Powered Geofencing
Draw a polygon zone on the map. The Python backend passes coordinates to a compiled C++ DLL which runs:
- **Ray Casting Algorithm** — determines if target is inside the polygon
- **Shoelace Formula** — calculates exact area of the geofence in m²

This runs ~40% faster than a pure Python implementation.

### 📊 Live Dashboard
Split-screen UI: 20% sidebar for controls and logs, 80% interactive map with real-time target pins and alert badges.

---

## 🚀 How to Run

### Prerequisites
- Python 3.11
- Node.js (LTS)
- Windows OS (geofence.dll is compiled for Windows)

### Backend
```bash
cd Backend
pip install flask flask-cors requests dnspython fake-useragent
python server.py
```
Backend runs at `http://127.0.0.1:5000`

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend runs at `http://localhost:5173`

### Ngrok (for public trap links)
```bash
cd Backend
.\ngrok.exe http 5000
```
Replace `localhost:5000` in the generated link with your ngrok URL.

---

## 📁 Project Structure

```
Live-Location-Tracker/
├── frontend/               # React + Vite app
│   ├── src/
│   │   ├── App.jsx         # Main dashboard
│   │   └── main.jsx
│   └── package.json
│
├── Backend/                # Python Flask server
│   ├── server.py           # Main API server
│   ├── geofence.dll        # Compiled C++ kernel
│   ├── geofence.cpp        # C++ source code
│   ├── email_validation.py # OSINT email scanner
│   ├── sherlock_integration.py  # Social media OSINT
│   ├── utils.py            # Helper functions
│   └── requirements.txt
│
├── docs/
│   └── Live_Location_Tracker_Report.pdf  # Full project report
│
├── .gitignore
└── README.md
```

---

## 📄 Full Project Report

Complete technical documentation including architecture diagrams, methodology, test cases, literature review, and results is available in the [`docs`](./docs) folder:

📥 **[Live_Location_Tracker_Report.pdf](./docs/Live_Location_Tracker_Report.pdf)**

---

## 🧠 DSA & COAL Concepts Used

| Concept | Where Used |
|---------|-----------|
| Ray Casting Algorithm | C++ geofence.dll — point-in-polygon detection |
| Shoelace Formula | C++ geofence.dll — polygon area calculation |
| Pointer Arithmetic (COAL) | Direct memory access in geofence.cpp |
| Multi-threading | ThreadPoolExecutor for background OSINT scans |
| SQLite Schema Design | Structured storage with VPN flags and OSINT logs |

---

*Air University — BS Cyber Security, Section F-24-A*