# Ansible Role: fake_idrac ([Ludus](https://ludus.cloud))

Deploys a **fake SHELL EMC iDRAC9 web interface** in Docker on a Debian/Ubuntu host.
Built for **CTF ranges** and **security awareness training**.

Pairs with `ludus_fake_firewall` for a two-step challenge, and includes an optional
**Virtual Console (SOL)** that proxies a real SSH connection through the browser —
adding a third flag stage.

---

## Teaching objectives

> Out-of-band management interfaces (iDRAC, iLO, IPMI, BMC) are high-value targets.
> They bypass the OS, persist across reboots, and are often reachable from a dedicated
> management VLAN — or left on the production LAN with factory credentials.
> The Virtual Console feature further demonstrates that OOB systems give full server
> access once credentials are compromised.

---

## Architecture

```
Ludus VM (Debian 12)
  └── Docker  network_mode: host  (required — see note below)
        gunicorn (eventlet, -w 1) → 0.0.0.0:IDRAC_PORT
        Flask + Flask-SocketIO + paramiko
        Routes: /login  /dashboard  /console  /api/health  /api/sessions
        WS namespace: /console  (SOL virtual terminal)
```

`network_mode: host` is required so the companion `ludus_fake_firewall` role can
control access via iptables INPUT chain rules. With standard bridge networking Docker
DNAT's traffic through PREROUTING → FORWARD, bypassing INPUT entirely and making the
firewall block ineffective.

---

## Requirements

- Target OS: Debian 11/12 or Ubuntu 20.04/22.04
- Ansible collection: `community.docker` (for handlers only)

```bash
ansible-galaxy collection install community.docker
```

---

## Role variables

```yaml
# Port gunicorn binds on directly (no port mapping — network_mode: host)
ludus_fake_idrac_port: 8443

ludus_fake_idrac_install_dir: /opt/fake_idrac

# CTF flag shown after login and in GET /api/health JSON
ludus_fake_idrac_flag: "CTF{0OB_1DR4C_D3f4ult_R00t_C4lv1n_G3fund3n}"

# Fake server identity (display only — shown in the web UI)
ludus_fake_idrac_hostname:    "SRV-SAFTLADEN-DC01"
ludus_fake_idrac_model:       "ShellEdge SX740"
ludus_fake_idrac_service_tag: "SL42X99"
ludus_fake_idrac_fw_version:  "5.10.00.00"
ludus_fake_idrac_display_ip:  "10.XX.20.250"  # cosmetic only

# Credentials — root/calvin are SHELL EMC factory defaults (the lesson)
ludus_fake_idrac_root_pass:  "calvin"
ludus_fake_idrac_admin_pass: ""              # empty = account disabled

# ── Virtual Console / Serial Over LAN (SOL) ───────────────────────────────────
# Set true to enable the Virtual Console link in the sidebar.
ludus_fake_idrac_sol_enabled:   false

# Displayed in the fake SSH banner inside the terminal
ludus_fake_idrac_sol_fake_host: "192.168.10.11"

# Fake credentials the student must enter to pass the first gate
ludus_fake_idrac_sol_fake_user: "sysadmin"
ludus_fake_idrac_sol_fake_pass: "supersecret123"

# Real SSH target — session opened after fake login succeeds.
# Use 127.0.0.1 when the target is the same VM as the iDRAC container
# (the container runs with network_mode: host so 127.0.0.1 = the VM itself).
ludus_fake_idrac_sol_ssh_host: "127.0.0.1"
ludus_fake_idrac_sol_ssh_port: 22
ludus_fake_idrac_sol_ssh_user: "debian"
ludus_fake_idrac_sol_ssh_pass: "debian"

# Set true to force --no-cache Docker build on every role run
ludus_fake_idrac_force_rebuild: false
```

---

## Features

- SHELL EMC–branded iDRAC9 login page (dark theme, server info panel, health status)
- Realistic System Summary dashboard:
  - CPU, memory, storage, power and thermal metrics
  - Physical disk table with degraded drive (Warning state)
  - System Event Log with entries hinting at default credentials
- Flag banner displayed after successful authentication
- `GET /api/health` — returns flag in JSON (bonus for enumeration)
- `GET /api/sessions` — fake session list
- Soft IP-based login lockout after 10 failed attempts
- **Virtual Console / SOL** (when `sol_enabled: true`):
  - Browser-based SSH terminal (xterm.js + Flask-SocketIO + paramiko)
  - Two-phase UI: styled fake SSH login card → full xterm terminal
  - Fake login verifies `sol_fake_pass`, then proxies real SSH to `sol_ssh_host`
  - Terminal supports resize events, Ctrl+C, full ANSI colour

---

## SOL prerequisites

For the Virtual Console SSH proxy to work:

1. **Password auth must be enabled** on the SSH target:
   ```bash
   echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
   systemctl restart sshd
   passwd debian   # set a known password
   ```

2. **Use `127.0.0.1` as `sol_ssh_host`** when the target is the same VM.
   The container's `network_mode: host` means `127.0.0.1` is the VM itself.
   Do NOT use the VM's LAN IP for same-host connections — routing may fail.

---

## CTF flow

### Standalone (no firewall role)
```
nmap -p 8443 <target>
http://<target>:8443  →  root / calvin  →  Flag
```

### With fake_firewall (two flags)
```
nmap -p 8443,9443 <target>
:9443  mfa-sense firewall   admin / pfsense   → Flag 1
Firewall → Rules → add ACCEPT for your IP
:8443  SHELL EMC iDRAC9     root  / calvin    → Flag 2
```

### With fake_firewall + SOL (three flags)
```
nmap -p 8443,9443 <target>
:9443  mfa-sense firewall   admin / pfsense      → Flag 1
Firewall → Rules → add ACCEPT for your IP
:8443  SHELL EMC iDRAC9     root  / calvin        → Flag 2
Dashboard → Virtual Console
  SSH banner: sysadmin@<host>'s password: ***
  Enter supersecret123 → real SSH session on target → Flag 3 (on the host)
```

---

## Dependencies

None.

---

## Example playbook

```yaml
- hosts: ctf_targets
  roles:
    - mojeda101.fake_idrac
  vars:
    ludus_fake_idrac_flag:          "CTF{0OB_1DR4C_D3f4ult_R00t_C4lv1n_G3fund3n}"
    ludus_fake_idrac_hostname:      "SRV-SAFTLADEN-DC01"
    ludus_fake_idrac_port:          8443
    ludus_fake_idrac_sol_enabled:   true
    ludus_fake_idrac_sol_fake_host: "192.168.10.11"
    ludus_fake_idrac_sol_fake_user: "sysadmin"
    ludus_fake_idrac_sol_fake_pass: "supersecret123"
    ludus_fake_idrac_sol_ssh_host:  "127.0.0.1"
    ludus_fake_idrac_sol_ssh_user:  "debian"
    ludus_fake_idrac_sol_ssh_pass:  "debian"
```

---

## Example Ludus range config

```yaml
ludus:
  - vm_name: "{{ range_id }}-mgmt-sim-debian12"
    hostname: "{{ range_id }}-SL-MGMT"
    template: debian-12-x64-server-template
    vlan: 20
    ip_last_octet: 250
    ram_gb: 3
    cpus: 2
    linux: true
    testing:
      snapshot: true
      block_internet: false   # needed for Docker image pull on first deploy
    roles:
      - mojeda101.fake_idrac
      - mojeda101.fake_firewall
    role_vars:
      # fake_idrac
      ludus_fake_idrac_flag:          "CTF{0OB_1DR4C_D3f4ult_R00t_C4lv1n_G3fund3n}"
      ludus_fake_idrac_hostname:      "SRV-SAFTLADEN-DC01"
      ludus_fake_idrac_port:          8443
      ludus_fake_idrac_sol_enabled:   true
      ludus_fake_idrac_sol_fake_host: "192.168.10.11"
      ludus_fake_idrac_sol_fake_user: "sysadmin"
      ludus_fake_idrac_sol_fake_pass: "supersecret123"
      ludus_fake_idrac_sol_ssh_host:  "127.0.0.1"
      ludus_fake_idrac_sol_ssh_user:  "debian"
      ludus_fake_idrac_sol_ssh_pass:  "debian"
      # fake_firewall
      ludus_fake_firewall_flag:              "CTF{pfs3ns3_4dm1n_Mgmt_Pl4n3_N1cht_G3s1ch3rt}"
      ludus_fake_firewall_hostname:          "fw-saftladen.local"
      ludus_fake_firewall_idrac_host:        "127.0.0.1"
      ludus_fake_firewall_idrac_port:        8443
      ludus_fake_firewall_initial_block:     true
```

---

## Notes

- `python3-docker` installed via `apt` (not pip) — avoids Debian 12 PEP 668.
- Docker images always built `--no-cache` — prevents stale cached layers.
- `wait_for` (TCP port check) used for health checks — more robust than `uri`
  when iptables rules are active on the same host.
- gunicorn uses `eventlet` worker (`-w 1`) — required for WebSocket support.
- xterm.js `addon-fit` omitted — the scoped `@xterm` package returns `text/plain`
  from jsDelivr which browsers block with `nosniff`. Terminal uses fixed cols/rows.
- SOL `sol_ssh_host` must be `127.0.0.1` for same-VM targets. Using the VM's
  LAN IP from inside the container can fail depending on routing.

---

## CTF difficulty hints

| Level  | Hint |
|---|---|
| Easy   | "There is a server management interface on port 8443. Check the Virtual Console." |
| Medium | "The interface resembles an OOB management system. It has remote console access." |
| Hard   | No hints — full nmap discovery, credential research, three-stage chain. |

---

## License

MIT

## Author

This role was created by [mojeda101](https://github.com/mojeda101) for [Ludus](https://ludus.cloud/).
