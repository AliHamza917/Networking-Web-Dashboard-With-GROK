# Ali Hamza Cisco Networking Dashboard

Web + Windows desktop GUI for **Cisco IOS / IOS-XE** switches over SSH (Netmiko).

**Author:** Ali Hamza · **Contact:** alihamza51326@gmail.com  
© 2026 Ali Hamza. All rights reserved.

## Features

| Feature | Description |
|---------|-------------|
| **Port Map** | Graphical ports · trunks highlighted · click for MAC/IP |
| **Network Topology** | Interactive CDP/LLDP neighbor map |
| **Track Route** | Traceroute with visual hop map |
| **IP Scanner** | Scan subnet or IP range |
| **Switch Monitor** | Continuous multi-switch ping · saved IPs · disconnect alerts |
| **Config Push** | Multi-line CLI apply + save |
| **VLAN / Interface** | Quick helpers |
| **Backup** | Download running-config |
| **Templates** | Ready-made config snippets |

## Quick start (Windows)

```cmd
python -m pip install -r requirements.txt
python -m pip install paramiko==2.12.0
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Open: **http://127.0.0.1:8000**

Desktop: `python desktop_app.py` or `run_desktop.bat`

## Project structure

```
├── app/main.py           # FastAPI + Netmiko backend
├── templates/index.html  # Dashboard UI
├── desktop_app.py        # Desktop window (pywebview)
├── requirements.txt
├── Dockerfile
└── .github/workflows/ci.yml
```

## Security

For lab / trusted networks. Do not expose to the public internet without auth and HTTPS. Always review CLI before production pushes.

## License / rights

Proprietary to **Ali Hamza** (alihamza51326@gmail.com). Unauthorized commercial redistribution without permission is prohibited.
# Networking-Web-Dashboard-With-GROK
