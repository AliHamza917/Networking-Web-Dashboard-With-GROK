"""
Cisco Switch Configuration Dashboard
Web GUI for configuring classic IOS / IOS-XE switches via SSH (Netmiko)
"""

from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional, List
import io
import tempfile
import os
from datetime import datetime
from pathlib import Path

# Re-enable older SSH KEX/host-key algorithms for classic Cisco IOS.
# New Paramiko rejects them; Termius still allows them.
try:
    from paramiko import Transport
    _extra_kex = (
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
    )
    _kex = list(getattr(Transport, "_preferred_kex", ()) or ())
    for k in _extra_kex:
        if k not in _kex:
            _kex.append(k)
    Transport._preferred_kex = tuple(_kex)
    for attr, extras in (
        ("_preferred_keys", ("ssh-rsa", "ssh-dss")),
        ("_preferred_pubkeys", ("ssh-rsa", "ssh-dss")),
        ("_preferred_ciphers", ("aes128-cbc", "3des-cbc", "aes192-cbc", "aes256-cbc")),
    ):
        cur = getattr(Transport, attr, None)
        if cur is not None:
            lst = list(cur)
            for e in extras:
                if e not in lst:
                    lst.append(e)
            setattr(Transport, attr, tuple(lst))
except Exception:
    pass

import netmiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

# Project root = parent of the "app" folder
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="Ali Hamza Cisco Networking Dashboard", version="1.0.0")

# Mount static & templates (absolute paths so it works from any working directory)
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class DeviceCredentials(BaseModel):
    host: str = ""  # IP for SSH, or COM port for console e.g. COM3
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    port: int = 22
    device_type: str = "cisco_ios"
    # ssh | console
    connection_type: str = "ssh"
    # Console serial settings
    serial_port: Optional[str] = None  # COM3 or /dev/ttyUSB0
    baudrate: int = 9600


class ShowCommand(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    command: str
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class ConfigPush(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    config_commands: List[str]
    port: int = 22
    save: bool = True
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class VlanConfig(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    vlan_id: int
    vlan_name: Optional[str] = None
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class InterfaceConfig(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    interface: str
    mode: str = "access"          # access | trunk
    vlan: Optional[int] = None
    description: Optional[str] = None
    shutdown: bool = False
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class PortDetailRequest(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    interface: str
    port: int = 22
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class TraceRouteRequest(BaseModel):
    host: str = ""
    username: str = ""
    password: str = ""
    secret: Optional[str] = None
    target: str
    port: int = 22
    probe: int = 3
    connection_type: str = "ssh"
    serial_port: Optional[str] = None
    baudrate: int = 9600


class PingRequest(BaseModel):
    target: str
    count: int = 2


class ScanRequest(BaseModel):
    subnet: str  # e.g. 192.168.4.0/24 or 192.168.4.1-50
    timeout: float = 1.0


# ------------------------------------------------------------------
# Helper
# ------------------------------------------------------------------

def expand_interface_name(name: str) -> str:
    """Expand short interface names for Cisco CLI."""
    n = name.strip()
    replacements = (
        ("Gi", "GigabitEthernet"),
        ("Fa", "FastEthernet"),
        ("Te", "TenGigabitEthernet"),
        ("Tw", "TwoGigabitEthernet"),
        ("Hu", "HundredGigE"),
        ("Eth", "Ethernet"),
        ("Po", "Port-channel"),
    )
    for short, full in replacements:
        if n.startswith(short) and len(n) > len(short) and n[len(short)].isdigit():
            return full + n[len(short):]
    return n

def get_connection(creds: dict):
    """
    Create Netmiko connection via SSH or console (serial) cable.
    """
    conn_type = (creds.get("connection_type") or "ssh").lower().strip()
    secret = (creds.get("secret") or "").strip()
    username = (creds.get("username") or "").strip()
    password = creds.get("password") or ""

    if conn_type in ("console", "serial"):
        serial_port = (creds.get("serial_port") or creds.get("host") or "").strip()
        if not serial_port:
            raise ValueError("Console mode requires a serial port (e.g. COM3)")
        device = {
            "device_type": "cisco_ios_serial",
            "username": username,
            "password": password,
            "secret": secret,
            "serial_settings": {
                "port": serial_port,
                "baudrate": int(creds.get("baudrate") or 9600),
                "bytesize": 8,
                "parity": "N",
                "stopbits": 1,
            },
            "timeout": 90,
            "fast_cli": False,
            "global_delay_factor": 3,
            "global_cmd_verify": False,
        }
    else:
        host = (creds.get("host") or "").strip()
        if not host:
            raise ValueError("SSH mode requires switch IP / hostname")
        device = {
            "device_type": creds.get("device_type", "cisco_ios"),
            "host": host,
            "username": username,
            "password": password,
            "port": int(creds.get("port") or 22),
            "secret": secret,
            "timeout": 90,
            "conn_timeout": 90,
            "auth_timeout": 90,
            "banner_timeout": 60,
            "fast_cli": False,
            "global_delay_factor": 3,
            "global_cmd_verify": False,
            "use_keys": False,
            "allow_agent": False,
        }

    conn = ConnectHandler(**device)
    try:
        if secret:
            conn.enable()
        else:
            prompt = conn.find_prompt()
            if prompt.strip().endswith(">"):
                conn.enable()
    except Exception:
        pass
    try:
        conn.send_command_timing("terminal length 0")
    except Exception:
        pass
    return conn


def run_cmd(conn, command: str, use_textfsm: bool = False, read_timeout: int = 120):
    """Run a show command with timing fallback (avoids echo verify timeouts)."""
    try:
        return conn.send_command(
            command,
            use_textfsm=use_textfsm,
            read_timeout=read_timeout,
            cmd_verify=False,
        )
    except Exception:
        # Fallback: timing-based (no echo check)
        out = conn.send_command_timing(command, read_timeout=read_timeout)
        if use_textfsm:
            return out  # raw text; caller handles non-list
        return out


def safe_connect(creds: dict):
    try:
        return get_connection(creds), None
    except NetmikoAuthenticationException:
        return None, "Authentication failed – check username / password / enable secret (same values that work in Termius)"
    except NetmikoTimeoutException:
        return None, (
            "SSH timed out in Netmiko (Termius works, so try):\n"
            "• Exact same IP, username, password as Termius\n"
            "• Enable secret if Termius uses it\n"
            "• Port 22 (or the port Termius uses)\n"
            "• Wait – first connect can take 15–30s across VLANs"
        )
    except Exception as e:
        err = str(e)
        low = err.lower()
        if "timed out" in low or "timeout" in low:
            return None, (
                "SSH timed out. Since Termius works:\n"
                "• Use the same IP/user/password as Termius\n"
                "• Leave Enable Secret empty if Termius does not use it\n"
                "• Confirm port matches Termius (usually 22)\n"
                f"Detail: {err}"
            )
        if "negotiation" in low or "kex" in low or "algorithm" in low:
            return None, (
                "SSH algorithm mismatch (common with old IOS + new Paramiko).\n"
                "Try: pip install 'paramiko<3'   then restart the app.\n"
                f"Detail: {err}"
            )
        return None, f"Connection error: {err}"


# ------------------------------------------------------------------
# Routes – Pages
# ------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    # Compatible with new Starlette (request first) and older versions
    try:
        return templates.TemplateResponse(request, "index.html")
    except TypeError:
        return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


# ------------------------------------------------------------------
# API – Connection test
# ------------------------------------------------------------------

@app.post("/api/test-connection")
async def test_connection(creds: DeviceCredentials):
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        prompt = conn.find_prompt()
        version = run_cmd(conn, "show version | include Cisco IOS Software|System image")
        hostname = prompt.replace("#", "").replace(">", "")
        conn.disconnect()
        return {
            "success": True,
            "hostname": hostname,
            "prompt": prompt,
            "version_snippet": version[:300] if version else "N/A"
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Show commands
# ------------------------------------------------------------------

@app.post("/api/show")
async def run_show(cmd: ShowCommand):
    conn, err = safe_connect(cmd.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        # Security: only allow show / display commands
        if not cmd.command.strip().lower().startswith(("show", "display")):
            return JSONResponse({"success": False, "error": "Only 'show' commands are allowed here"}, status_code=400)
        output = run_cmd(conn, cmd.command, read_timeout=120)
        conn.disconnect()
        return {"success": True, "output": output}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Free-form config push
# ------------------------------------------------------------------

@app.post("/api/config")
async def push_config(cfg: ConfigPush):
    conn, err = safe_connect(cfg.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        # Filter empty lines
        commands = [c.strip() for c in cfg.config_commands if c.strip()]
        if not commands:
            return JSONResponse({"success": False, "error": "No commands provided"}, status_code=400)

        output = conn.send_config_set(commands)
        if cfg.save:
            save_out = conn.save_config()
            output += "\n\n--- save ---\n" + save_out
        conn.disconnect()
        return {"success": True, "output": output}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – VLAN helper
# ------------------------------------------------------------------

@app.post("/api/vlan")
async def create_vlan(vlan: VlanConfig):
    conn, err = safe_connect(vlan.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        commands = [f"vlan {vlan.vlan_id}"]
        if vlan.vlan_name:
            commands.append(f"name {vlan.vlan_name}")
        commands.append("exit")
        output = conn.send_config_set(commands)
        conn.save_config()
        conn.disconnect()
        return {"success": True, "output": output}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Interface helper
# ------------------------------------------------------------------

@app.post("/api/interface")
async def configure_interface(iface: InterfaceConfig):
    conn, err = safe_connect(iface.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        commands = [f"interface {iface.interface}"]
        if iface.description:
            commands.append(f"description {iface.description}")
        if iface.mode == "access":
            commands.append("switchport mode access")
            if iface.vlan:
                commands.append(f"switchport access vlan {iface.vlan}")
        elif iface.mode == "trunk":
            commands.append("switchport mode trunk")
            if iface.vlan:
                commands.append(f"switchport trunk native vlan {iface.vlan}")
        if iface.shutdown:
            commands.append("shutdown")
        else:
            commands.append("no shutdown")
        commands.append("exit")

        output = conn.send_config_set(commands)
        conn.save_config()
        conn.disconnect()
        return {"success": True, "output": output}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Backup running-config
# ------------------------------------------------------------------

@app.post("/api/backup")
async def backup_config(creds: DeviceCredentials):
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        output = run_cmd(conn, "show running-config", read_timeout=180)
        hostname = conn.find_prompt().replace("#", "").replace(">", "")
        conn.disconnect()

        # Write to temp file
        filename = f"{hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cfg"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".cfg", mode="w")
        tmp.write(output)
        tmp.close()

        return FileResponse(
            tmp.name,
            media_type="text/plain",
            filename=filename,
            background=None  # caller should clean up later if needed
        )
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.post("/api/restore")
async def restore_config(
    file: UploadFile = File(...),
    host: str = Form(""),
    username: str = Form(""),
    password: str = Form(""),
    secret: str = Form(""),
    port: int = Form(22),
    connection_type: str = Form("ssh"),
    serial_port: str = Form(""),
    baudrate: int = Form(9600),
    save: bool = Form(True),
):
    """Upload a .cfg / text backup and apply lines to the switch."""
    try:
        raw = await file.read()
        text = raw.decode("utf-8", errors="ignore")
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Cannot read file: {e}"}, status_code=400)

    # Strip comments / empty; skip typical show-run headers
    commands = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("!") or s.startswith("#"):
            continue
        if s.lower().startswith(("building configuration", "current configuration", "version ")):
            continue
        if s.lower() in ("end", "exit"):
            continue
        commands.append(s)

    if not commands:
        return JSONResponse({"success": False, "error": "No usable config lines in file"}, status_code=400)
    if len(commands) > 5000:
        return JSONResponse({"success": False, "error": "File too large (max 5000 lines)"}, status_code=400)

    creds = {
        "host": host,
        "username": username,
        "password": password,
        "secret": secret or None,
        "port": port,
        "connection_type": connection_type,
        "serial_port": serial_port or None,
        "baudrate": baudrate,
    }
    conn, err = safe_connect(creds)
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        output = conn.send_config_set(commands)
        if save:
            output += "\n\n--- save ---\n" + str(conn.save_config())
        conn.disconnect()
        return {"success": True, "lines_applied": len(commands), "output": output}
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@app.get("/api/serial-ports")
async def list_serial_ports():
    """List COM / serial ports available on this PC (for console cable)."""
    ports = []
    try:
        from serial.tools import list_ports
        for p in list_ports.comports():
            ports.append({
                "device": p.device,
                "description": p.description or "",
                "hwid": getattr(p, "hwid", "") or "",
            })
    except Exception as e:
        return {"success": True, "ports": [], "note": f"pyserial list failed: {e}. Type COM3 manually."}
    return {"success": True, "ports": ports}


# ------------------------------------------------------------------
# API – Port map (graphical view)
# ------------------------------------------------------------------

@app.post("/api/ports")
async def get_ports(creds: DeviceCredentials):
    """
    Fetch interface status and return structured data for the graphical port map.
    Uses TextFSM (ntc-templates) when available.
    """
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        # Primary structured command
        raw = run_cmd(conn, "show interfaces status", use_textfsm=True, read_timeout=120)
        hostname = conn.find_prompt().replace("#", "").replace(">", "")

        # Extra trunk detection via switchport summary (more reliable)
        trunk_ports = set()
        try:
            sw = run_cmd(conn, "show interfaces switchport", read_timeout=120)
            if isinstance(sw, str):
                import re
                current_if = None
                for line in sw.splitlines():
                    m = re.match(r"Name:\s+(\S+)", line)
                    if m:
                        current_if = m.group(1)
                    if current_if and re.search(r"Operational Mode:\s*trunk", line, re.I):
                        trunk_ports.add(current_if.lower())
                        # also short form Gi1/0/1 style
                        short = current_if
                        for a, b in (("GigabitEthernet", "Gi"), ("FastEthernet", "Fa"),
                                     ("TenGigabitEthernet", "Te"), ("Ethernet", "Eth")):
                            short = short.replace(a, b)
                        trunk_ports.add(short.lower())
                        trunk_ports.add(current_if.lower())
        except Exception:
            pass

        ports = []
        if isinstance(raw, list) and raw:
            for row in raw:
                port_name = row.get("port") or row.get("interface") or row.get("Port") or ""
                status = (row.get("status") or row.get("Status") or "").lower()
                vlan = str(row.get("vlan") or row.get("Vlan") or "")
                duplex = row.get("duplex") or row.get("Duplex") or ""
                speed = row.get("speed") or row.get("Speed") or ""
                port_type = row.get("type") or row.get("Type") or ""
                name = row.get("name") or row.get("Name") or ""

                if status in ("connected", "up"):
                    state = "up"
                elif status in ("notconnect", "not connected", "down", "disabled"):
                    state = "down"
                elif "err" in status or "error" in status:
                    state = "error"
                else:
                    state = "unknown"

                vlan_l = vlan.lower().strip()
                is_trunk = (
                    vlan_l in ("trunk", "trnk", "tr")
                    or port_name.lower() in trunk_ports
                    or any(port_name.lower().endswith(t.replace("gi", "").replace("fa", "")) for t in trunk_ports if False)
                )
                # Match short/long names against trunk set
                if not is_trunk:
                    exp = expand_interface_name(port_name).lower()
                    if port_name.lower() in trunk_ports or exp in trunk_ports:
                        is_trunk = True
                    for t in trunk_ports:
                        if t.endswith(port_name.lower()) or port_name.lower() in t:
                            is_trunk = True
                            break

                mode = "trunk" if is_trunk else "access"

                ports.append({
                    "port": port_name,
                    "name": name,
                    "status": status,
                    "state": state,
                    "vlan": vlan,
                    "mode": mode,
                    "duplex": duplex,
                    "speed": speed,
                    "type": port_type,
                })
        else:
            raw_text = run_cmd(conn, "show interfaces status", read_timeout=120)
            ports = [{"port": "raw", "raw": raw_text, "state": "unknown", "mode": "access"}]

        conn.disconnect()
        return {
            "success": True,
            "hostname": hostname,
            "ports": ports,
            "count": len(ports),
            "trunk_count": sum(1 for p in ports if p.get("mode") == "trunk"),
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Port detail (MAC + IP on a port)
# ------------------------------------------------------------------

@app.post("/api/port-detail")
async def port_detail(req: PortDetailRequest):
    """MAC address table + ARP/IP for a specific interface."""
    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        import re
        iface = req.interface.strip()
        iface_full = expand_interface_name(iface)

        mac_entries = []
        # Try full then short name
        for ifname in (iface_full, iface):
            mac_raw = run_cmd(conn, f"show mac address-table interface {ifname}", read_timeout=60)
            if not isinstance(mac_raw, str):
                continue
            if "Invalid" in mac_raw or "not exist" in mac_raw.lower():
                continue
            for line in mac_raw.splitlines():
                # Typical: VLAN  MAC Address       Type        Ports
                # 10    0011.2233.4455    DYNAMIC     Gi1/0/1
                m = re.search(
                    r"(\d+)\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+(\S+)\s+(\S+)",
                    line,
                )
                if m:
                    mac_entries.append({
                        "vlan": m.group(1),
                        "mac": m.group(2).lower(),
                        "type": m.group(3),
                        "port": m.group(4),
                    })
            if mac_entries:
                break

        # Resolve IP from ARP for each MAC
        arp_raw = run_cmd(conn, "show ip arp", read_timeout=90)
        arp_map = {}
        if isinstance(arp_raw, str):
            for line in arp_raw.splitlines():
                # Internet  192.168.1.10  0   0011.2233.4455  ARPA  Vlan10
                am = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})",
                    line,
                )
                if am:
                    arp_map[am.group(2).lower()] = am.group(1)

        hosts = []
        for e in mac_entries:
            hosts.append({
                "vlan": e["vlan"],
                "mac": e["mac"],
                "type": e["type"],
                "ip": arp_map.get(e["mac"], ""),
            })

        # Optional: IP device tracking
        idt_raw = ""
        try:
            idt_raw = run_cmd(conn, f"show ip device tracking interface {iface_full}", read_timeout=30)
            if isinstance(idt_raw, str) and ("Invalid" in idt_raw or "not enabled" in idt_raw.lower()):
                idt_raw = ""
        except Exception:
            idt_raw = ""

        conn.disconnect()
        return {
            "success": True,
            "interface": iface,
            "interface_full": iface_full,
            "hosts": hosts,
            "host_count": len(hosts),
            "mac_table_raw": mac_raw if isinstance(mac_raw, str) else "",
            "device_tracking": idt_raw if isinstance(idt_raw, str) else "",
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Traceroute (track route)
# ------------------------------------------------------------------

def _parse_traceroute_hops(output: str, source: str, target: str) -> list:
    """Parse Cisco IOS traceroute text into structured hops for the visual map."""
    import re
    hops = [
        {
            "hop": 0,
            "ip": source or "Switch",
            "label": source or "Switch",
            "rtt_ms": [],
            "status": "source",
        }
    ]
    # Examples:
    #  1 10.0.0.1 4 msec 2 msec 2 msec
    #  2 * * *
    #  3 8.8.8.8 20 msec 18 msec 19 msec
    #  1 10.0.0.1 [AS 0] 1 msec 1 msec 1 msec
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.lower().startswith("tracing") or line.lower().startswith("type"):
            continue
        m = re.match(r"^(\d+)\s+(.*)$", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2).strip()
        if re.match(r"^[\*\s]+$", rest) or rest.replace("*", "").replace(" ", "") == "":
            hops.append({
                "hop": hop_num,
                "ip": "*",
                "label": "Timeout",
                "rtt_ms": [],
                "status": "timeout",
            })
            continue
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
        ip = ip_m.group(1) if ip_m else rest.split()[0]
        rtts = [float(x) for x in re.findall(r"(\d+(?:\.\d+)?)\s*msec", rest, re.I)]
        hops.append({
            "hop": hop_num,
            "ip": ip,
            "label": ip,
            "rtt_ms": rtts,
            "status": "ok" if rtts else "unknown",
        })
    # Destination marker
    hops.append({
        "hop": 999,
        "ip": target,
        "label": target,
        "rtt_ms": [],
        "status": "destination",
    })
    return hops


@app.post("/api/traceroute")
async def traceroute(req: TraceRouteRequest):
    """Run traceroute from the switch; return text + structured hops for visual map."""
    conn, err = safe_connect(req.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        target = req.target.strip()
        if not target or any(c in target for c in (";", "|", "\n", "`")):
            return JSONResponse({"success": False, "error": "Invalid target"}, status_code=400)

        cmd = f"traceroute {target}"
        try:
            output = conn.send_command_timing(cmd, read_timeout=180)
            if "Probe" in str(output) or "Numeric" in str(output):
                output = str(output) + conn.send_command_timing("\n", read_timeout=60)
        except Exception as e:
            output = str(e)

        output = output if isinstance(output, str) else str(output)
        hostname = conn.find_prompt().replace("#", "").replace(">", "")
        conn.disconnect()

        hops = _parse_traceroute_hops(output, hostname, target)
        return {
            "success": True,
            "hostname": hostname,
            "target": target,
            "output": output,
            "hops": hops,
            "hop_count": max(0, len(hops) - 2),  # exclude source + destination markers
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Network Topology (CDP / LLDP)
# ------------------------------------------------------------------

def _parse_cdp_fallback(raw: str) -> list:
    """Basic regex fallback when TextFSM is unavailable."""
    import re
    neighbors = []
    # Split on device blocks
    blocks = re.split(r"(?=\nDevice ID:)", "\n" + raw)
    for block in blocks:
        if "Device ID:" not in block:
            continue
        dev = re.search(r"Device ID:\s*(.+)", block)
        local = re.search(r"Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)", block)
        if not local:
            local = re.search(r"Interface:\s*(\S+).+Port ID.+:\s*(\S+)", block)
        plat = re.search(r"Platform:\s*([^,\n]+)", block)
        cap = re.search(r"Capabilities:\s*(.+)", block)
        ip = re.search(r"IP address:\s*(\S+)", block)
        if dev:
            neighbors.append({
                "neighbor": dev.group(1).strip().split(".")[0],
                "local_interface": local.group(1).strip() if local else "",
                "neighbor_interface": local.group(2).strip() if local else "",
                "platform": plat.group(1).strip() if plat else "",
                "capabilities": cap.group(1).strip() if cap else "",
                "mgmt_address": ip.group(1).strip() if ip else "",
                "protocol": "cdp",
            })
    return neighbors


@app.post("/api/topology")
async def get_topology(creds: DeviceCredentials):
    """
    Build a topology graph from CDP (preferred) and LLDP neighbors.
    Returns nodes + edges for interactive visualization.
    """
    conn, err = safe_connect(creds.dict())
    if err:
        return JSONResponse({"success": False, "error": err}, status_code=400)
    try:
        hostname = conn.find_prompt().replace("#", "").replace(">", "").strip()
        # Local management IP (best effort)
        local_ip = ""
        try:
            ip_out = run_cmd(conn, "show ip interface brief | include up")
            for line in ip_out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1].count(".") == 3 and not parts[1].startswith("unassigned"):
                    local_ip = parts[1]
                    break
        except Exception:
            pass

        neighbors = []

        # --- CDP ---
        try:
            cdp = run_cmd(conn, "show cdp neighbors detail", use_textfsm=True, read_timeout=120)
            if isinstance(cdp, list) and cdp:
                for row in cdp:
                    neighbors.append({
                        "neighbor": (row.get("destination_host") or row.get("device_id") or row.get("neighbor") or "").split(".")[0],
                        "local_interface": row.get("local_port") or row.get("local_interface") or "",
                        "neighbor_interface": row.get("remote_port") or row.get("neighbor_port") or row.get("port_id") or "",
                        "platform": row.get("platform") or "",
                        "capabilities": row.get("capabilities") or "",
                        "mgmt_address": row.get("management_ip") or row.get("ip") or "",
                        "protocol": "cdp",
                    })
            else:
                raw = run_cmd(conn, "show cdp neighbors detail", read_timeout=120)
                if isinstance(raw, str) and "CDP is not enabled" not in raw and "Invalid" not in raw:
                    neighbors.extend(_parse_cdp_fallback(raw))
        except Exception:
            try:
                raw = run_cmd(conn, "show cdp neighbors detail", read_timeout=120)
                if isinstance(raw, str):
                    neighbors.extend(_parse_cdp_fallback(raw))
            except Exception:
                pass

        # --- LLDP (add only if not already seen via CDP) ---
        seen = {(n["neighbor"].lower(), n["local_interface"].lower()) for n in neighbors}
        try:
            lldp = run_cmd(conn, "show lldp neighbors detail", use_textfsm=True, read_timeout=120)
            if isinstance(lldp, list) and lldp:
                for row in lldp:
                    neigh = (row.get("neighbor") or row.get("system_name") or row.get("chassis_id") or "").split(".")[0]
                    local_if = row.get("local_interface") or row.get("local_port") or ""
                    key = (neigh.lower(), local_if.lower())
                    if key in seen or not neigh:
                        continue
                    neighbors.append({
                        "neighbor": neigh,
                        "local_interface": local_if,
                        "neighbor_interface": row.get("neighbor_port") or row.get("port_id") or "",
                        "platform": row.get("system_description") or row.get("platform") or "",
                        "capabilities": row.get("capabilities") or "",
                        "mgmt_address": row.get("management_ip") or row.get("ip") or "",
                        "protocol": "lldp",
                    })
        except Exception:
            pass

        conn.disconnect()

        # Build graph
        nodes = [
            {
                "id": hostname,
                "label": hostname,
                "type": "local",
                "ip": local_ip,
                "platform": "Local Switch",
            }
        ]
        edges = []
        node_ids = {hostname.lower()}

        for n in neighbors:
            nid = n["neighbor"] or "Unknown"
            if nid.lower() not in node_ids:
                node_ids.add(nid.lower())
                # Guess device type from capabilities / platform
                caps = (n.get("capabilities") or "").lower()
                plat = (n.get("platform") or "").lower()
                if "switch" in caps or "switch" in plat or "catalyst" in plat or "nexus" in plat:
                    dtype = "switch"
                elif "router" in caps or "router" in plat:
                    dtype = "router"
                elif "phone" in caps or "phone" in plat:
                    dtype = "phone"
                elif "host" in caps or "workstation" in caps:
                    dtype = "host"
                else:
                    dtype = "device"
                nodes.append({
                    "id": nid,
                    "label": nid,
                    "type": dtype,
                    "ip": n.get("mgmt_address") or "",
                    "platform": n.get("platform") or "",
                })

            edges.append({
                "from": hostname,
                "to": nid,
                "local_interface": n.get("local_interface") or "",
                "neighbor_interface": n.get("neighbor_interface") or "",
                "protocol": n.get("protocol") or "cdp",
                "label": f"{n.get('local_interface', '')} ↔ {n.get('neighbor_interface', '')}",
            })

        return {
            "success": True,
            "hostname": hostname,
            "nodes": nodes,
            "edges": edges,
            "neighbor_count": len(neighbors),
        }
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


# ------------------------------------------------------------------
# API – Ping & IP Scanner (from the machine running this app)
# ------------------------------------------------------------------

def _guess_device_type(ttl: Optional[int], hostname: str = "") -> dict:
    """
    Heuristic end-host classification (not 100% accurate).
    TTL hints: Windows ~128, Linux/Android/iOS ~64, many network devices ~255.
    """
    hn = (hostname or "").lower()
    if any(x in hn for x in ("switch", "sw-", "catalyst", "nexus", "router", "rt-", "ap-", "wlc")):
        return {"device_class": "network", "device_label": "Likely switch/router/AP", "confidence": "medium"}
    if any(x in hn for x in ("iphone", "android", "galaxy", "pixel", "mobile", "phone")):
        return {"device_class": "mobile", "device_label": "Likely mobile phone", "confidence": "medium"}
    if any(x in hn for x in ("desktop", "laptop", "pc-", "win-", "workstation")):
        return {"device_class": "pc", "device_label": "Likely PC / workstation", "confidence": "medium"}

    if ttl is None:
        return {"device_class": "unknown", "device_label": "Unknown (alive)", "confidence": "low"}
    if 120 <= ttl <= 128:
        return {"device_class": "pc", "device_label": "Likely Windows PC", "confidence": "medium"}
    if 60 <= ttl <= 64:
        return {"device_class": "mobile_or_linux", "device_label": "Likely mobile / Linux / Mac", "confidence": "medium"}
    if ttl >= 250:
        return {"device_class": "network", "device_label": "Likely network device", "confidence": "low"}
    return {"device_class": "unknown", "device_label": f"Unknown (TTL={ttl})", "confidence": "low"}


def _ping_host(target: str, count: int = 2, timeout_sec: float = 2.0) -> dict:
    """ICMP ping using system ping (Windows / Linux) + TTL-based device hint."""
    import platform
    import re
    import socket
    import subprocess
    import time

    target = target.strip()
    if not target or any(c in target for c in (";", "|", "&", "`", "\n", " ")):
        return {"target": target, "alive": False, "error": "Invalid target", "rtt_ms": None, "ttl": None}

    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", str(max(1, min(count, 4))), "-w", str(int(timeout_sec * 1000)), target]
        else:
            cmd = ["ping", "-c", str(max(1, min(count, 4))), "-W", str(max(1, int(timeout_sec))), target]

        t0 = time.time()
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec * count + 5)
        elapsed = (time.time() - t0) * 1000
        out = (proc.stdout or "") + (proc.stderr or "")
        alive = proc.returncode == 0

        rtt = None
        m = re.search(r"time[=<](\d+(?:\.\d+)?)\s*ms", out, re.I)
        if m:
            rtt = float(m.group(1))
        elif alive:
            rtt = round(elapsed / max(count, 1), 1)

        ttl = None
        tm = re.search(r"\bTTL[=:](\d+)", out, re.I)
        if tm:
            ttl = int(tm.group(1))

        hostname = ""
        if alive:
            try:
                hostname = socket.getfqdn(target)
                if hostname == target:
                    hostname = ""
            except Exception:
                hostname = ""

        guess = _guess_device_type(ttl, hostname) if alive else {
            "device_class": "down", "device_label": "No reply", "confidence": "high"
        }

        return {
            "target": target,
            "alive": alive,
            "rtt_ms": rtt,
            "ttl": ttl,
            "hostname": hostname,
            "device_class": guess["device_class"],
            "device_label": guess["device_label"],
            "confidence": guess["confidence"],
            "error": None if alive else "Request timed out or host unreachable",
        }
    except subprocess.TimeoutExpired:
        return {"target": target, "alive": False, "rtt_ms": None, "ttl": None, "error": "Ping timed out",
                "device_class": "down", "device_label": "No reply", "confidence": "high"}
    except Exception as e:
        return {"target": target, "alive": False, "rtt_ms": None, "ttl": None, "error": str(e),
                "device_class": "down", "device_label": "Error", "confidence": "high"}


@app.post("/api/ping")
async def api_ping(req: PingRequest):
    """Ping a single host from the PC running the dashboard."""
    result = _ping_host(req.target, count=req.count)
    return {"success": True, **result}


@app.post("/api/scan")
async def api_scan(req: ScanRequest):
    """
    Simple IP scanner.
    Supports:
      - CIDR: 192.168.4.0/24 (scans .1–.254, capped)
      - Range: 192.168.4.1-50
    """
    import ipaddress
    import re
    from concurrent.futures import ThreadPoolExecutor, as_completed

    subnet = req.subnet.strip()
    hosts = []

    try:
        if "/" in subnet:
            net = ipaddress.ip_network(subnet, strict=False)
            # Cap to avoid huge scans
            hosts = [str(h) for h in list(net.hosts())[:256]]
        else:
            m = re.match(r"^(\d+\.\d+\.\d+)\.(\d+)\s*-\s*(\d+)$", subnet)
            if m:
                base, start, end = m.group(1), int(m.group(2)), int(m.group(3))
                if start > end:
                    start, end = end, start
                end = min(end, start + 255)
                hosts = [f"{base}.{i}" for i in range(start, end + 1)]
            else:
                # Single IP
                hosts = [subnet]
    except Exception as e:
        return JSONResponse({"success": False, "error": f"Invalid subnet/range: {e}"}, status_code=400)

    if not hosts:
        return JSONResponse({"success": False, "error": "No hosts to scan"}, status_code=400)

    alive = []
    dead_count = 0

    def one(ip):
        return _ping_host(ip, count=1, timeout_sec=req.timeout)

    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(one, ip): ip for ip in hosts}
        for fut in as_completed(futures):
            r = fut.result()
            if r.get("alive"):
                alive.append(r)
            else:
                dead_count += 1

    alive.sort(key=lambda x: tuple(int(p) for p in x["target"].split(".")))
    return {
        "success": True,
        "subnet": subnet,
        "scanned": len(hosts),
        "alive_count": len(alive),
        "dead_count": dead_count,
        "alive": alive,
    }


# ------------------------------------------------------------------
# API – Quick templates
# ------------------------------------------------------------------

@app.get("/api/templates")
async def get_templates():
    return {
        "templates": [
            {
                "name": "Basic Switch Setup",
                "description": "Hostname, domain, NTP, logging, AAA basics",
                "commands": [
                    "hostname SWITCH-NAME",
                    "ip domain-name example.com",
                    "ntp server 10.0.0.1",
                    "logging host 10.0.0.10",
                    "service password-encryption",
                    "no ip http server",
                    "no ip http secure-server"
                ]
            },
            {
                "name": "Create VLANs 10,20,30",
                "description": "Common VLAN set",
                "commands": [
                    "vlan 10",
                    "name DATA",
                    "vlan 20",
                    "name VOICE",
                    "vlan 30",
                    "name MANAGEMENT",
                    "exit"
                ]
            },
            {
                "name": "Access Port Template",
                "description": "Configure Gi1/0/1 as access port VLAN 10",
                "commands": [
                    "interface GigabitEthernet1/0/1",
                    "description ACCESS-PORT",
                    "switchport mode access",
                    "switchport access vlan 10",
                    "spanning-tree portfast",
                    "no shutdown",
                    "exit"
                ]
            },
            {
                "name": "Trunk Port Template",
                "description": "Configure Gi1/0/24 as trunk",
                "commands": [
                    "interface GigabitEthernet1/0/24",
                    "description UPLINK",
                    "switchport mode trunk",
                    "switchport trunk allowed vlan 10,20,30",
                    "no shutdown",
                    "exit"
                ]
            }
        ]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
