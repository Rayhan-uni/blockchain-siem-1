"""
log_simulator.py
Generates realistic security events so the system has something to ingest,
hash, chain, and analyze. Includes both benign background traffic and
scripted attack scenarios (brute force, port scan, malware beacon,
data exfiltration, privilege escalation) so the AI detector and the
blockchain-integrity demo have real material to work with.
"""

import random
import time

DEVICES = ["FW-01", "WIN-DC01", "LNX-WEB01", "IDS-01", "VPN-01", "CLOUD-AWS"]
USERS = ["jsmith", "aomar", "rpatel", "svc_backup", "administrator", "mgarcia", "root"]
EXTERNAL_IPS = ["203.0.113.{}".format(i) for i in range(1, 40)]
INTERNAL_IPS = ["10.0.{}.{}".format(a, b) for a in range(1, 4) for b in range(1, 30)]
COMMON_PORTS = [22, 80, 443, 3389, 445, 3306, 5432, 8080]


def _base(device, event_type, severity, message, **kw):
    e = {
        "timestamp": time.time(),
        "device": device,
        "event_type": event_type,
        "severity": severity,
        "message": message,
        "src_ip": kw.get("src_ip"),
        "dest_ip": kw.get("dest_ip"),
        "dest_port": kw.get("dest_port"),
        "user": kw.get("user"),
    }
    return e


def normal_event():
    kind = random.choice(["auth_success", "web_request", "firewall_allow", "vpn_connect", "cloud_api_call"])
    device = random.choice(DEVICES)
    user = random.choice(USERS)
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    if kind == "auth_success":
        return _base(device, "auth_success", "info", f"Successful login for user {user}", src_ip=src, user=user)
    if kind == "web_request":
        return _base(device, "web_request", "info", f"GET /dashboard 200 from {src}", src_ip=src, dest_ip=dst, dest_port=443)
    if kind == "firewall_allow":
        return _base(device, "firewall_allow", "info", f"ALLOW {src} -> {dst}:{random.choice(COMMON_PORTS)}",
                     src_ip=src, dest_ip=dst, dest_port=random.choice(COMMON_PORTS))
    if kind == "vpn_connect":
        return _base(device, "vpn_connect", "info", f"VPN session established for {user}", src_ip=src, user=user)
    return _base(device, "cloud_api_call", "info", f"IAM API call ListBuckets by {user}", src_ip=src, user=user)


def brute_force_burst(device="WIN-DC01", user="administrator"):
    """A burst of failed logins from one external IP against one account."""
    src = random.choice(EXTERNAL_IPS)
    events = []
    for _ in range(random.randint(8, 15)):
        events.append(_base(device, "auth_failure", "high",
                             f"Failed login for user {user} (bad password)", src_ip=src, user=user))
    events.append(_base(device, "auth_success", "critical",
                         f"Login SUCCEEDED for user {user} after repeated failures", src_ip=src, user=user))
    return events


def port_scan_burst(device="IDS-01"):
    """One external host probing many ports on an internal target."""
    src = random.choice(EXTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    events = []
    ports = random.sample(range(1, 65535), 20)
    for p in ports:
        events.append(_base(device, "port_scan", "medium",
                             f"Sequential SYN probe {src} -> {dst}:{p}", src_ip=src, dest_ip=dst, dest_port=p))
    return events


def malware_alert_burst(device="LNX-WEB01"):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    events = [
        _base(device, "malware_alert", "critical",
              "AV signature match: Trojan.Generic.KD.44921 quarantined", src_ip=src),
        _base(device, "network_beacon", "high",
              f"Periodic C2-like beacon {src} -> {dst}:443 every 60s", src_ip=src, dest_ip=dst, dest_port=443),
    ]
    return events


def data_exfiltration_burst(device="CLOUD-AWS", user="svc_backup"):
    dst = random.choice(EXTERNAL_IPS)
    src = random.choice(INTERNAL_IPS)
    events = [
        _base(device, "privilege_escalation", "critical",
              f"User {user} added to Administrators group unexpectedly", user=user),
        _base(device, "large_data_transfer", "critical",
              f"Outbound transfer of 4.2GB from {src} to {dst}", src_ip=src, dest_ip=dst, dest_port=443, user=user),
    ]
    return events


ATTACK_SCENARIOS = [brute_force_burst, port_scan_burst, malware_alert_burst, data_exfiltration_burst]


def generate_batch(n_normal=6, attack_probability=0.25):
    """Returns a list of log-entry dicts: mostly normal traffic, occasionally an attack burst."""
    batch = [normal_event() for _ in range(n_normal)]
    if random.random() < attack_probability:
        scenario = random.choice(ATTACK_SCENARIOS)
        batch.extend(scenario())
    random.shuffle(batch)
    return batch
