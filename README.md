# PulseNet v3.0

Real-time network monitoring tool with a live web dashboard.

## What it does
- Monitors your internet connection in real-time
- Tracks latency, packet loss, and connection quality
- Scans for devices on your network
- Generates an HTML report when you're done
- Live web dashboard at http://localhost:5000

## Requirements
Python 3.x and these libraries:
pip install psutil flask

## How to run
python PULSE_NET.py

## Optional settings
--interval 5        (refresh every 5 seconds)
--no-web            (disable web dashboard)
--no-arp            (disable device scanning)
--no-color          (disable terminal colors)# PulseNet
Real-time network monitoring tool with a live web dashboard. Tracks latency, packet loss, connection quality, and connected devices.
