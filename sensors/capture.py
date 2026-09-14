from scapy.all import sniff, Ether, IP, TCP, UDP, ARP, IPv6, conf
from scapy.layers.inet import IP_PROTOS
import time
import threading


# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------

TIMEOUT_LIMIT = 10
JANITOR_INTERVAL = 5


# --- FIXED AUTOMATIC INTERFACE SELECTION ---
try:
    # Use Scapy's automatically detected default loop/internet interface
    INTERFACE = conf.iface
    if not INTERFACE:
        raise RuntimeError("Scapy could not find any active default interface.")
except Exception as e:
    raise RuntimeError(f"Could not initialize network interface: {e}")


# ----------------------------------------------------------------------
# GLOBAL FLOW STATE
# ----------------------------------------------------------------------

active_flows = {}
flows_lock = threading.Lock()


# ----------------------------------------------------------------------
# PROTOCOL RESOLUTION
# ----------------------------------------------------------------------

def get_protocol_name(protocol):
    """
    Convert an IP protocol number into a readable protocol name.

    Example:
        6  -> TCP
        17 -> UDP
        1  -> ICMP
    """

    try:
        return IP_PROTOS[protocol]
    except KeyError:
        return f"UNKNOWN ({protocol})"


# ----------------------------------------------------------------------
# PACKET PARSER
# ----------------------------------------------------------------------

def universal_parser(pkt):

    src_ip = None
    dst_ip = None

    src_port = None
    dest_port = None

    protocol = None
    protocol_name = None

    mac_src = None
    mac_dst = None


    # --------------------------------------------------------------
    # ETHERNET
    # --------------------------------------------------------------

    if not pkt.haslayer(Ether):
        return

    mac_src = pkt[Ether].src
    mac_dst = pkt[Ether].dst


    # --------------------------------------------------------------
    # ARP
    # --------------------------------------------------------------

    if pkt.haslayer(ARP):

        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst

        protocol = "ARP"
        protocol_name = "ARP"

        src_port = None
        dest_port = None


    # --------------------------------------------------------------
    # IPv4
    # --------------------------------------------------------------

    elif pkt.haslayer(IP):

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        protocol = pkt[IP].proto

        protocol_name = get_protocol_name(protocol)

        src_port = None
        dest_port = None


        # TCP
        if pkt.haslayer(TCP):

            src_port = pkt[TCP].sport
            dest_port = pkt[TCP].dport


        # UDP
        elif pkt.haslayer(UDP):

            src_port = pkt[UDP].sport
            dest_port = pkt[UDP].dport


    # --------------------------------------------------------------
    # IPv6
    # --------------------------------------------------------------

    elif pkt.haslayer(IPv6):

        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

        protocol = pkt[IPv6].nh

        protocol_name = get_protocol_name(protocol)

        src_port = None
        dest_port = None


        # TCP
        if pkt.haslayer(TCP):

            src_port = pkt[TCP].sport
            dest_port = pkt[TCP].dport


        # UDP
        elif pkt.haslayer(UDP):

            src_port = pkt[UDP].sport
            dest_port = pkt[UDP].dport


    # --------------------------------------------------------------
    # Ignore packets without IP addresses
    # --------------------------------------------------------------

    if src_ip is None or dst_ip is None:
        return


    # --------------------------------------------------------------
    # NORMALIZE FLOW
    # --------------------------------------------------------------

    if src_ip < dst_ip:

        flow_key = (
            src_ip,
            dst_ip,
            src_port,
            dest_port,
            protocol_name
        )

    else:

        flow_key = (
            dst_ip,
            src_ip,
            dest_port,
            src_port,
            protocol_name
        )


    # --------------------------------------------------------------
    # UPDATE FLOW
    # --------------------------------------------------------------

    get_pkt_flow(
        flow_key,
        len(pkt)
    )


# ----------------------------------------------------------------------
# FLOW TRACKING
# ----------------------------------------------------------------------

def get_pkt_flow(key, packet_size):

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

                "last_active": current_time
            }


# ----------------------------------------------------------------------
# FLOW JANITOR
# ----------------------------------------------------------------------

def flow_janitor():

    while True:

        time.sleep(JANITOR_INTERVAL)

        current_time = time.time()

        with flows_lock:

            expired_keys = [

                key

                for key, data in active_flows.items()

                if current_time - data["last_active"] > TIMEOUT_LIMIT
            ]


            for key in expired_keys:

                del active_flows[key]


# ----------------------------------------------------------------------
# SENSOR ENGINE
# ----------------------------------------------------------------------

def start_sensor_engine():

    # Start janitor
    janitor_thread = threading.Thread(
        target=flow_janitor,
        daemon=True
    )

    janitor_thread.start()


    print(
        "AEGIS Network Sensor Thread Spawning. "
        "Monitoring network layer..."
    )

    print(
        f"[AEGIS] Capture interface: {INTERFACE}"
    )


    # --------------------------------------------------------------
    # PACKET CAPTURE
    # --------------------------------------------------------------

    sniff(
        iface=INTERFACE,
        prn=universal_parser,
        store=False
    )
