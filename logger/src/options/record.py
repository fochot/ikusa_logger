from scapy.all import get_if_list, sniff, wrpcap

from ..network import build_capture_filter, describe_endpoints, discover_game_endpoints


def record(output, all_interfaces=True):
    endpoints = discover_game_endpoints()
    capture_filter = build_capture_filter(endpoints)
    interfaces = get_if_list() if all_interfaces else None

    print("Recording Network...", flush=True)
    print("Black Desert endpoints: " + describe_endpoints(endpoints), flush=True)
    print("Capture filter: " + capture_filter, flush=True)
    sniff(
        filter=capture_filter,
        iface=interfaces or None,
        prn=lambda package: wrpcap(output + ".pcap", package, append=True),
        store=0,
    )
