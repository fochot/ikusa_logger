from __future__ import annotations

import os
import sys
from time import localtime, strftime

if sys.platform != "win32":
    import types

    sys.modules.setdefault("scapy.arch.windows", types.ModuleType("scapy.arch.windows"))

from scapy.all import get_if_list, rdpcap, sniff

from ..network import (
    GameEndpoint,
    build_capture_filter,
    describe_endpoints,
    discover_game_endpoints,
    packet_matches_endpoints,
)
from ..protocol import StreamScanner


_scanner = StreamScanner()
_game_endpoints: list[GameEndpoint] = []
_last_timestamp = ""


def _reset_scanner(endpoints: list[GameEndpoint] | None = None) -> None:
    global _scanner, _game_endpoints, _last_timestamp
    _scanner = StreamScanner()
    _game_endpoints = endpoints or []
    _last_timestamp = ""


def _ip_addresses(package) -> tuple[str, str] | None:
    if "IP" in package:
        return str(package["IP"].src), str(package["IP"].dst)
    if "IPv6" in package:
        return str(package["IPv6"].src), str(package["IPv6"].dst)
    return None


def _transport(package):
    if "TCP" in package:
        return "tcp", package["TCP"]
    return None


def package_handler(package, output="", ip_filter=False):
    global _last_timestamp
    addresses = _ip_addresses(package)
    transport = _transport(package)
    if addresses is None or transport is None:
        return

    source_ip, destination_ip = addresses
    protocol, layer = transport
    source_port = int(layer.sport)
    destination_port = int(layer.dport)

    # Always keep the original direction and world-server scope. The option is
    # retained only for CLI compatibility with existing UI builds.
    if not packet_matches_endpoints(
        source_ip,
        destination_ip,
        source_port,
        destination_port,
        _game_endpoints,
    ):
        return

    payload = bytes(layer.payload)
    if not payload:
        return

    # Direction is part of the key so server and client streams never share a
    # reassembly buffer. This fixes the old global last_payload corruption.
    flow = (
        protocol,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
    )
    timestamp = strftime("%I:%M:%S", localtime(int(float(package.time))))
    _last_timestamp = timestamp

    for candidate in _scanner.feed(flow, payload):
        print(candidate.to_event(timestamp), flush=True)


def _flush_scanner() -> None:
    timestamp = _last_timestamp or strftime("%I:%M:%S", localtime())
    for candidate in _scanner.flush():
        print(candidate.to_event(timestamp), flush=True)


def open_pcap(file, output, ip_filter=False):
    if file is None or not os.path.isfile(file):
        print("Invalid file", flush=True)
        return

    _reset_scanner()
    print("Reading " + file, flush=True)
    print("Capture mode: original BDO combat stream (incoming TCP 8889)", flush=True)

    if os.name == "nt":
        print("Loading file into ram. This may take a while.", flush=True)
        capture = rdpcap(file)
        for index, package in enumerate(capture):
            package_handler(package, output, ip_filter)
            if index % 10000 == 0:
                print(f"{index}/{len(capture)} packages analyzed.", flush=True)
    else:
        sniff(
            offline=file,
            filter=build_capture_filter([]),
            prn=lambda package: package_handler(package, output, ip_filter),
            store=0,
        )

    _flush_scanner()
    print("Network analysis complete. You can close this window now.", flush=True)


def read_network_interfaces():
    if sys.platform == "win32":
        from scapy.arch.windows import get_windows_if_list

        windows_interfaces = get_windows_if_list()
        return {entry["guid"]: entry["name"] for entry in windows_interfaces}

    return {interface: interface for interface in get_if_list()}


def _sniff_with_fallback(
    output,
    ip_filter,
    capture_filter,
    primary_interface,
    label,
):
    sniff_options = {
        "filter": capture_filter,
        "prn": lambda package: package_handler(package, output, ip_filter),
        "store": 0,
    }
    try:
        sniff(**sniff_options, iface=primary_interface)
    except Exception as error:
        print(f"{label} capture failed, falling back to the default interface.", flush=True)
        print(error, flush=True)
        try:
            sniff(**sniff_options, iface=None)
        except Exception as fallback_error:
            print("Error while reading network.", flush=True)
            print(fallback_error, flush=True)


def start_sniff(output, all_interfaces=True, ip_filter=False):
    endpoints = discover_game_endpoints()
    _reset_scanner(endpoints)
    capture_filter = build_capture_filter(endpoints)

    print("Reading Network...", flush=True)
    print("Black Desert endpoints: " + describe_endpoints(endpoints), flush=True)
    print("Capture filter: " + capture_filter, flush=True)

    if all_interfaces:
        interfaces = get_if_list()
        print("Network Interfaces: " + ", ".join(interfaces), flush=True)
        target = interfaces if interfaces else None
        _sniff_with_fallback(
            output,
            ip_filter,
            capture_filter,
            target,
            "Standard",
        )
    else:
        guid_to_name = read_network_interfaces()
        names = list(filter(None, [guid_to_name.get(entry) for entry in get_if_list()]))
        target = names if names else None
        _sniff_with_fallback(
            output,
            ip_filter,
            capture_filter,
            target,
            "Compatibility",
        )
