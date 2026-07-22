#!/usr/bin/env python3
"""
Fake SHELL iDRAC9 - CTF / Security Awareness Target
Deployed via ludus_fake_idrac Ansible role
"""

# eventlet monkey-patch must be first — before any other imports
import eventlet
eventlet.monkey_patch()

import os, re, random
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, disconnect
import paramiko

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "idrac9-lab-secret-do-not-use-in-prod")
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins="*")

# ── Core config ────────────────────────────────────────────────────────────────
CTF_FLAG          = os.environ.get("IDRAC_FLAG",        "CTF{d3f4ult_1DR4C_r00t_c4lv1n_4r3_n0t_s3cr3ts}")
IDRAC_HOSTNAME    = os.environ.get("IDRAC_HOSTNAME",    "SRV-PROD-DC01")
IDRAC_MODEL       = os.environ.get("IDRAC_MODEL",       "ShellEdge SX740")
IDRAC_SERVICE_TAG = os.environ.get("IDRAC_SERVICE_TAG", "7XK3M42")
IDRAC_FW_VERSION  = os.environ.get("IDRAC_FW_VERSION",  "5.10.00.00")
IDRAC_IP          = os.environ.get("IDRAC_IP",          "192.168.10.250")

# ── iDRAC credentials ─────────────────────────────────────────────────────────
VALID_USERS = {
    "root":  os.environ.get("IDRAC_ROOT_PASS",  "calvin"),
    "admin": os.environ.get("IDRAC_ADMIN_PASS", ""),
}
_login_attempts: dict = {}

# ── SOL (Serial Over LAN) / Virtual Console config ────────────────────────────
SOL_ENABLED   = os.environ.get("SOL_ENABLED",   "false").lower() == "true"
# Fake SSH prompt credentials shown in the terminal banner
SOL_FAKE_HOST = os.environ.get("SOL_FAKE_HOST", IDRAC_IP)
SOL_FAKE_USER = os.environ.get("SOL_FAKE_USER", "sysadmin")
SOL_FAKE_PASS = os.environ.get("SOL_FAKE_PASS", "")
# Real SSH target (connected after fake login succeeds)
SOL_SSH_HOST  = os.environ.get("SOL_SSH_HOST",  "")
SOL_SSH_PORT  = int(os.environ.get("SOL_SSH_PORT",  "22"))
SOL_SSH_USER  = os.environ.get("SOL_SSH_USER",  "")
SOL_SSH_PASS  = os.environ.get("SOL_SSH_PASS",  "")

# ── Fake server info ───────────────────────────────────────────────────────────
def _fake_mac():
    parts = ["B0","83","FE"] + [f"{random.randint(0,255):02X}" for _ in range(3)]
    return ":".join(parts)

SERVER_INFO = {
    "hostname":     IDRAC_HOSTNAME,
    "model":        IDRAC_MODEL,
    "service_tag":  IDRAC_SERVICE_TAG,
    "fw_version":   IDRAC_FW_VERSION,
    "idrac_ip":     IDRAC_IP,
    "bios_version": "2.14.1",
    "cpus":         "2x Intel Xeon Gold 6248R @ 3.00GHz",
    "cpu_cores":    "48 Cores / 96 Threads",
    "memory":       "256 GB DDR4 3200 MHz (16x 16 GB RDIMMs)",
    "nic_mac":      _fake_mac(),
    "power_state":  "On",
    "power_draw":   f"{random.randint(280,340)} W",
    "inlet_temp":   f"{random.randint(21,26)} °C",
    "exhaust_temp": f"{random.randint(34,44)} °C",
    "uptime":       "47 days, 11 hours, 23 minutes",
    "os":           "Windows Server 2022 Standard",
    "os_hostname":  IDRAC_HOSTNAME,
}

FAKE_SEL = [
    {"id":"1","severity":"Critical",     "date":"2025-07-18 02:14:33","message":"System Board CMOS Battery voltage is below lower critical threshold"},
    {"id":"2","severity":"Warning",      "date":"2025-07-17 19:05:11","message":"Physical Disk 0:0:2 state changed to Degraded"},
    {"id":"3","severity":"Informational","date":"2025-07-15 08:32:07","message":"iDRAC Firmware update completed successfully"},
    {"id":"4","severity":"Informational","date":"2025-07-12 14:17:59","message":"User root logged in from 10.10.10.41"},
    {"id":"5","severity":"Warning",      "date":"2025-07-08 21:44:16","message":"Fan 1A RPM is below lower critical threshold (2640 RPM)"},
    {"id":"6","severity":"Informational","date":"2025-07-01 00:00:01","message":"Default credentials in use — change factory settings immediately"},
]

STORAGE = [
    {"slot":"0:0:0","model":"SAMSUNG MZILT3T8HALS","size":"3.84 TB","state":"Online","health":"OK"},
    {"slot":"0:0:1","model":"SAMSUNG MZILT3T8HALS","size":"3.84 TB","state":"Online","health":"OK"},
    {"slot":"0:0:2","model":"TOSHIBA AL15SEB18EQ", "size":"1.80 TB","state":"Online","health":"Warning"},
    {"slot":"0:0:3","model":"TOSHIBA AL15SEB18EQ", "size":"1.80 TB","state":"Online","health":"OK"},
]

# ── Auth helper ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def g(*a, **kw):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return g

# ── HTTP routes ────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    remote_ip = request.remote_addr or "unknown"
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","")
        attempts = _login_attempts.get(remote_ip, 0)
        if attempts >= 10:
            error = "Too many login attempts. Account temporarily locked."
        elif u in VALID_USERS and VALID_USERS[u] and VALID_USERS[u] == p:
            _login_attempts.pop(remote_ip, None)
            session.clear()
            session["user"] = u
            session["login_ts"] = datetime.utcnow().isoformat()
            return redirect(url_for("dashboard"))
        else:
            _login_attempts[remote_ip] = attempts + 1
            error = "Invalid credentials"
    return render_template("login.html", error=error,
        hostname=SERVER_INFO["hostname"], model=SERVER_INFO["model"],
        service_tag=SERVER_INFO["service_tag"], fw_version=SERVER_INFO["fw_version"])

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    up = datetime.utcnow()
    return render_template("dashboard.html",
        info=SERVER_INFO, flag=CTF_FLAG, sel=FAKE_SEL, storage=STORAGE,
        user=session["user"], login_ts=session.get("login_ts",""),
        sol_enabled=SOL_ENABLED)

@app.route("/console")
@login_required
def console():
    if not SOL_ENABLED:
        return redirect(url_for("dashboard"))
    return render_template("console.html",
        hostname=IDRAC_HOSTNAME, fw_version=IDRAC_FW_VERSION,
        sol_fake_host=SOL_FAKE_HOST, sol_fake_user=SOL_FAKE_USER,
        sol_ssh_host=SOL_SSH_HOST or SOL_FAKE_HOST,
        user=session["user"])

@app.route("/api/health")
@login_required
def api_health():
    return jsonify({"status":"Warning","flag":CTF_FLAG,
        "sol_enabled":SOL_ENABLED,"sol_target":SOL_SSH_HOST})

@app.route("/api/sessions")
@login_required
def api_sessions():
    return jsonify({"sessions":[
        {"id":"1","user":session["user"],"ip":request.remote_addr,"type":"Web"}]})

# ── WebSocket — Virtual Console ────────────────────────────────────────────────
class _ConSession:
    """Per-WebSocket connection state for the SOL terminal."""
    def __init__(self):
        self.state   = "auth"   # "auth" | "connected"
        self.buf     = ""       # password buffer (auth phase)
        self.tries   = 0
        self.ssh     = None
        self.chan    = None

_cons: dict = {}  # sid -> _ConSession

def _sol_emit(sid, data):
    socketio.emit("out", data, namespace="/console", to=sid)

@socketio.on("connect", namespace="/console")
def sol_connect():
    if not session.get("user"):
        disconnect()
        return
    sid = request.sid
    _cons[sid] = _ConSession()
    # Emit banner lines to the ssh-log div (HTML, not xterm)
    def _banner():
        lines = [
            f'<span class="cmd">$ ssh {SOL_FAKE_USER}@{SOL_FAKE_HOST}</span>',
            "SSH_MSG_KEXINIT exchanged",
            "SSH_MSG_NEWKEYS",
            f"<span class=\"warn\">Warning: Permanently added '{SOL_FAKE_HOST}' "
            f"(ED25519) to the list of known hosts.</span>",
        ]
        for i, l in enumerate(lines):
            eventlet.sleep(0.15 if i > 0 else 0)
            socketio.emit("banner", l, namespace="/console", to=sid)
    eventlet.spawn(_banner)

@socketio.on("disconnect", namespace="/console")
def sol_disconnect():
    sid = request.sid
    sess = _cons.pop(sid, None)
    if sess:
        if sess.chan:
            try: sess.chan.close()
            except: pass
        if sess.ssh:
            try: sess.ssh.close()
            except: pass

@socketio.on("auth", namespace="/console")
def sol_auth(password):
    """Receive full password string from the HTML form (not char-by-char)."""
    sid = request.sid
    sess = _cons.get(sid)
    if not sess or sess.state != "auth":
        return
    if not SOL_FAKE_PASS or password == SOL_FAKE_PASS:
        sess.state = "connecting"
        emit("auth_ok")
        eventlet.spawn(_do_connect, sid, sess)
    else:
        sess.tries += 1
        tries_left = max(0, 3 - sess.tries)
        emit("auth_fail", {"tries_left": tries_left})
        if tries_left == 0:
            eventlet.sleep(0.5)
            disconnect()

@socketio.on("inp", namespace="/console")
def sol_input(data):
    sid = request.sid
    sess = _cons.get(sid)
    if sess and sess.state == "connected" and sess.chan:
        try:
            sess.chan.send(data)
        except Exception:
            pass

@socketio.on("resize", namespace="/console")
def sol_resize(data):
    sid = request.sid
    sess = _cons.get(sid)
    if sess and sess.chan and sess.state == "connected":
        try:
            sess.chan.resize_pty(
                width=int(data.get("cols", 80)),
                height=int(data.get("rows", 24)))
        except Exception:
            pass

def _do_connect(sid, sess):
    """Authenticate fake creds then proxy a real SSH connection."""
    _sol_emit(sid, "\033[32mAuthenticated.\033[0m\r\n")

    if not SOL_SSH_HOST:
        _sol_emit(sid,
            "\033[31mSOL_SSH_HOST not configured — "
            "no real target to connect to.\033[0m\r\n")
        return

    _sol_emit(sid, f"Opening SSH session to {SOL_SSH_HOST}:{SOL_SSH_PORT} ...\r\n")

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SOL_SSH_HOST, port=SOL_SSH_PORT,
                    username=SOL_SSH_USER, password=SOL_SSH_PASS,
                    timeout=10, banner_timeout=10,
                    look_for_keys=False, allow_agent=False)
        chan = ssh.invoke_shell(term="xterm-256color", width=220, height=50)
        sess.ssh  = ssh
        sess.chan = chan
        sess.state = "connected"

        # Background reader: pump SSH output → WebSocket
        def _reader():
            while True:
                try:
                    if chan.recv_ready():
                        chunk = chan.recv(4096)
                        if not chunk:
                            break
                        _sol_emit(sid,
                            chunk.decode("utf-8", errors="replace"))
                    elif chan.closed or chan.exit_status_ready():
                        break
                    else:
                        eventlet.sleep(0.01)
                except Exception:
                    break
            _sol_emit(sid,
                f"\r\n\033[33m[Connection to {SOL_SSH_HOST} closed]"
                "\033[0m\r\n")

        eventlet.spawn(_reader)

    except paramiko.AuthenticationException:
        _sol_emit(sid,
            f"\r\n\033[31mSSH authentication to {SOL_SSH_HOST} failed "
            f"(user: {SOL_SSH_USER}).\033[0m\r\n")
    except Exception as exc:
        _sol_emit(sid,
            f"\r\n\033[31mCannot connect to {SOL_SSH_HOST}:{SOL_SSH_PORT}"
            f" — {exc}\033[0m\r\n")

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0",
                 port=int(os.environ.get("IDRAC_PORT", 8443)), debug=False)
