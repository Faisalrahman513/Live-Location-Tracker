# Live Location Tracker

A full-stack hybrid intelligence system built as a 
academic project at Air University.

## Team
- Muhammad Faisal Rahman  
- Muhammad Bilal
- Zain Asif

## Tech Stack
- Frontend: React + Vite + Leaflet Maps
- Backend: Python Flask + SQLite
- Performance: C++ DLL (geofence.dll) for Ray Casting & Shoelace Algorithm
- OSINT: Multi-threaded email and social media scanning
- Tunneling: Ngrok

## Features
- Real-time GPS location tracking via trap links
- VPN and Proxy detection
- OSINT scanning (email MX records, social media)
- C++ powered geofencing with breach alerts
- SQLite database for target management

## How to Run

### Backend
cd Backend
pip install flask flask-cors requests dnspython fake-useragent
python server.py

### Frontend
cd frontend
npm install
npm run dev

Open http://localhost:5173 in your browser.