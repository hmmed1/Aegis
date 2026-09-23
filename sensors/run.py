#!/usr/bin/env python3
"""
Aegis sensor worker.

Two background jobs, both purely local (no inbound listener):
  1. Packet capture -> flow aggregation -> POST /api/v1/ingest/flows every 1s.
     Idle flows are pruned locally before each snapshot is sent.
  2. Periodic ARP ping sweep over the configured subnet -> POST
     /api/v1/ingest/devices with the discovered IP/MAC/vendor rows.

Configuration is entirely via environment variables (see .env.example):
  SENSOR_ID          unique name for this sensor, e.g. "home-pc"
  SENSOR_KEY         shared secret, must match SENSOR_KEYS on the server
  SERVER_URL         base URL of the Aegis server, e.g. http://aegis-server:8000
  IFACE              network interface to sniff on (default: scapy's default)
  SUBNET             CIDR to ARP-sweep, e.g. 192.168.1.0/24
  FLOW_IDLE_TIMEOUT  seconds of inactivity before a flow is pruned (default 30)
  FLOW_POST_INTERVAL seconds between flow snapshots (default 1)
  ARP_SWEEP_INTERVAL seconds between ARP sweeps (default 30)
"""
import logging
import os
import sys
import threading
import time
from collections import defaultdict

import requests
from scapy.all import sniff, ARP, Ether, IP, IPv6, TCP, UDP, ICMP, srp, conf
from dotenv import load_dotenv  # 🔌 Added for reading local .env file

# --------------------------------------------------------------------------
# Initialize Environment Variables
# --------------------------------------------------------------------------
load_dotenv()  # 🔌 Added to load values into os.environ before config read

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("aegis-sensor")

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------
SENSOR_ID = os.environ["SENSOR_ID"]
SENSOR_KEY = os.environ["SENSOR_KEY"]
SERVER_URL = os.environ.get("SERVER_URL", "http://localhost:8000").rstrip("/")
IFACE = os.environ.get("IFACE") or conf.iface
SUBNET = os.environ.get("SUBNET", "192.168.1.0/24")
FLOW_IDLE_TIMEOUT = float(os.environ.get("FLOW_IDLE_TIMEOUT", "30"))
FLOW_POST_INTERVAL = float(os.environ.get("FLOW_POST_INTERVAL", "1"))
ARP_SWEEP_INTERVAL = float(os.environ.get("ARP_SWEEP_INTERVAL", "30"))

HEADERS = {"X-Sensor-Id": SENSOR_ID, "X-Sensor-Key": SENSOR_KEY, "Content-Type": "application/json"}

# --------------------------------------------------------------------------
# Flow aggregation
# --------------------------------------------------------------------------
_flows_lock = threading.Lock()
# key: (src_ip, dst_ip, src_port, dst_port, protocol) -> flow stats
_flows: dict[tuple, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "first_seen": None, "last_seen": None})


def _protocol_name(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    return "OTHER"


def _handle_packet(pkt):
    now = time.time()
    try:
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            key = (arp.psrc, arp.pdst, None, None, "ARP")
        elif pkt.haslayer(IP) or pkt.haslayer(IPv6):
            ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
            src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else None)
            dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else None)
            key = (ip_layer.src, ip_layer.dst, src_port, dst_port, _protocol_name(pkt))
        else:
            return

        with _flows_lock:
            f = _flows[key]
            f["packets"] += 1
            f["bytes"] += len(pkt)
            f["first_seen"] = f["first_seen"] or now
            f["last_seen"] = now
    except Exception:
        log.exception("Failed to process a packet")


def _prune_and_snapshot() -> list[dict]:
    now = time.time()
    snapshot = []
    with _flows_lock:
        for key in list(_flows.keys()):
            f = _flows[key]
            if now - f["last_seen"] > FLOW_IDLE_TIMEOUT:
                del _flows[key]
                continue
            src_ip, dst_ip, src_port, dst_port, proto = key
            snapshot.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "packets": f["packets"],
                "bytes": f["bytes"],
                "first_seen": f["first_seen"],
                "last_seen": f["last_seen"],
            })
    return snapshot


def flow_reporter_loop():
    url = f"{SERVER_URL}/api/v1/ingest/flows"
    while True:
        try:
            flows = _prune_and_snapshot()
            resp = requests.post(url, json={"flows": flows}, headers=HEADERS, timeout=5)
            if resp.status_code != 200:
                log.warning("Flow ingest rejected: %s %s", resp.status_code, resp.text[:200])
        except Exception as exc:
            log.warning("Failed to POST flow snapshot: %s", exc)
        time.sleep(FLOW_POST_INTERVAL)


def sniff_loop():
    log.info("Starting packet capture on interface: %s", IFACE)
    sniff(iface=IFACE, prn=_handle_packet, store=False)


# --------------------------------------------------------------------------
# ARP device discovery
# --------------------------------------------------------------------------
def _arp_sweep(subnet: str) -> list[dict]:
    log.info("Running ARP sweep over %s", subnet)
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(request, timeout=3, iface=IFACE, verbose=False)
    devices = []
    for _, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
            "vendor": _lookup_vendor(received.hwsrc),
        })
    return devices


def _lookup_vendor(mac: str) -> str:
    try:
        from scapy.all import conf as _conf
        return _conf.manufdb._get_manuf(mac) or "Unknown"
    except Exception:
        return "Unknown"


def device_discovery_loop():
    url = f"{SERVER_URL}/api/v1/ingest/devices"
    while True:
        try:
            devices = _arp_sweep(SUBNET)
            resp = requests.post(url, json={"devices": devices}, headers=HEADERS, timeout=5)
            if resp.status_code != 200:
                log.warning("Device ingest rejected: %s %s", resp.status_code, resp.text[:200])
            else:
                log.info("Reported %d discovered devices", len(devices))
        except Exception as exc:
            log.warning("ARP sweep / device POST failed: %s", exc)
        time.sleep(ARP_SWEEP_INTERVAL)


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------
def main():
    log.info("Aegis sensor '%s' starting, reporting to %s", SENSOR_ID, SERVER_URL)

    threading.Thread(target=flow_reporter_loop, daemon=True).start()
    threading.Thread(target=device_discovery_loop, daemon=True).start()

    # Sniffing blocks, so it owns the main thread.
    sniff_loop()


if __name__ == "__main__":
    main()
