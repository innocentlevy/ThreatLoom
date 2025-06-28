# Wireshark SIEM Dashboard

A Security Information and Event Management (SIEM) system built using Wireshark (tshark) for packet capture with an interactive web dashboard.

## Features
- Real-time packet capture using Wireshark/tshark
- Interactive dashboard for network traffic analysis
- Real-time visualization of network events
- Threat detection and alerting
- Packet analysis and filtering

## Prerequisites
- Python 3.8+
- Node.js 16+
- Wireshark/tshark
- MongoDB (for storing events)

## Installation

1. Install Wireshark and tshark:
```bash
# For macOS using Homebrew
brew install wireshark
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
```

## Usage
1. Start the backend server:
```bash
python backend/app.py
```

2. Start the frontend development server:
```bash
cd frontend
npm start
```

3. Access the dashboard at http://localhost:3000

## Project Structure
```
wireshark_siem/
├── backend/           # Python backend
│   ├── app.py        # Main application
│   ├── capture.py    # Packet capture module
│   └── analyzer.py   # Packet analysis module
├── frontend/         # React frontend
└── requirements.txt  # Python dependencies
```
