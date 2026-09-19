"""Network flow capture and tracking engine.

Captures packets with scapy, aggregates them into flows keyed by
(src_ip, dst_ip, src_port, dst_port, protocol), and prunes idle flows
periodically. Exposes `active_flows` and `flows_lock` for the API layer.
"""

import os
import sys
import threading
import time

# --- Path setup ------------------------------------------------------

_PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
_BACKEND_DIR = os.path.join(_PROJECT_ROOT, "backend")

if _PROJECT_ROOT not in sys.path:
    sys.path.append(_PROJECT_ROOT)
if _BACKEND_DIR not in sys.path:
    sys.path.append(_BACKEND_DIR)

from app.config import settings
from scapy.all import conf, sniff
from scapy.data import IP_PROTOS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

# ---------------------------------------------------------------------
# INTERFACE DETECTION
# ---------------------------------------------------------------------

try:
    INTERFACE = conf.iface
    if not INTERFACE:
        raise RuntimeError("Scapy could not find any active default interface.")
except Exception as e:  # noqa: BLE001
    raise RuntimeError(f"Could not initialize network interface: {e}") from e


# ---------------------------------------------------------------------
# GLOBAL FLOW STATE
# ---------------------------------------------------------------------

active_flows = {}
flows_lock = threading.Lock()


# ---------------------------------------------------------------------
# PROTOCOL RESOLUTION
# ---------------------------------------------------------------------

def get_protocol_name(protocol):
    """Convert an IP protocol number into a readable name (6 → TCP)."""
    try:
        return IP_PROTOS[protocol]
    except KeyError:
        return f"UNKNOWN ({protocol})"


# ---------------------------------------------------------------------
# PACKET PARSER
# ---------------------------------------------------------------------

def universal_parser(pkt):
    """Parse incoming packets and extract key network properties."""
    src_ip = None
    dst_ip = None
    src_port = None
    dest_port = None
    protocol = None
    protocol_name = None

    if not pkt.haslayer(Ether):
        return

    # --- ARP ---------------------------------------------------------
    if pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        protocol_name = "ARP"

    # --- IPv4 --------------------------------------------------------
    elif pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = pkt[IP].proto
        protocol_name = get_protocol_name(protocol)

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dest_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dest_port = pkt[UDP].dport

    # --- IPv6 --------------------------------------------------------
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        protocol = pkt[IPv6].nh
        protocol_name = get_protocol_name(protocol)

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dest_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dest_port = pkt[UDP].dport

    if src_ip is None or dst_ip is None:
        return

    if src_ip < dst_ip:
        flow_key = (src_ip, dst_ip, src_port, dest_port, protocol_name)
    else:
        flow_key = (dst_ip, src_ip, dest_port, src_port, protocol_name)

    get_pkt_flow(flow_key, len(pkt))


# ---------------------------------------------------------------------
# FLOW TRACKING
# ---------------------------------------------------------------------

def get_pkt_flow(key, packet_size):
    """Aggregate packet data size and timestamps into active state dictionary."""
    current_time = time.time()
    with flows_lock:
        if key in active_flows:
            active_flows[key]["packet_count"] += 1
            active_flows[key]["total_bytes"] += packet_size
            active_flows[key]["last_active"] = current_time
        else:
            active_flows[key] = {
                "packet_count": 1,
                "total_bytes": packet_size,
                "first_seen": current_time,
                "last_active": current_time,
            }


# ---------------------------------------------------------------------
# FLOW JANITOR
# ---------------------------------------------------------------------

def flow_janitor():
    """Background worker loop to safely evict stagnant network connections."""
    while True:
        time.sleep(settings.janitor_interval_seconds)
        current_time = time.time()

        with flows_lock:
            expired_keys = [
                key
                for key, data in active_flows.items()
                if current_time - data["last_active"] > settings.flow_timeout_seconds
            ]
            for key in expired_keys:
                del active_flows[key]


# ---------------------------------------------------------------------
# ENGINE LIFECYCLE
# ---------------------------------------------------------------------

def start_sensor_engine():
    """Spawn the monitoring engine loop and janitor thread worker."""
    janitor_thread = threading.Thread(target=flow_janitor, daemon=True)
    janitor_thread.start()

    sniff_thread = threading.Thread(
        target=lambda: sniff(
            iface=INTERFACE,
            prn=universal_parser,
            store=False
        ),
        daemon=True
    )
    sniff_thread.start()
