from __future__ import annotations

from dataclasses import dataclass
import socket
from typing import Iterable


DEFAULT_GAME_PORTS = (8889,)
GAME_PROCESS_NAMES = {
    "blackdesert64",
    "blackdesert64.exe",
    "blackdesert32",
    "blackdesert32.exe",
}


@dataclass(frozen=True, order=True)
class GameEndpoint:
    protocol: str
    remote_ip: str
    remote_port: int
    local_ip: str = ""
    local_port: int = 0
    pid: int = 0


def _address_parts(address) -> tuple[str, int]:
    if not address:
        return "", 0

    if hasattr(address, "ip"):
        return str(address.ip), int(address.port)

    return str(address[0]), int(address[1])


def discover_game_endpoints() -> list[GameEndpoint]:
    """Return active remote endpoints owned by a Black Desert game process.

    psutil is deliberately optional. Packaged builds include it, while source
    checkouts can still fall back to capture-time payload discovery.
    """

    try:
        import psutil
    except ImportError:
        return []

    endpoints: set[GameEndpoint] = set()

    for process in psutil.process_iter(["pid", "name"]):
        try:
            process_name = (process.info.get("name") or "").lower()
            if process_name not in GAME_PROCESS_NAMES:
                continue

            for connection in process.net_connections(kind="inet"):
                local_ip, local_port = _address_parts(connection.laddr)
                remote_ip, remote_port = _address_parts(connection.raddr)
                is_udp = connection.type == socket.SOCK_DGRAM
                if (not remote_ip or not remote_port) and not (is_udp and local_port):
                    continue

                protocol = "tcp" if connection.type == socket.SOCK_STREAM else "udp"
                endpoints.add(
                    GameEndpoint(
                        protocol=protocol,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        local_ip=local_ip,
                        local_port=local_port,
                        pid=process.pid,
                    )
                )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
            continue

    return sorted(endpoints)


def build_capture_filter(endpoints: Iterable[GameEndpoint]) -> str:
    """Build a BPF filter without relying on a hard-coded server IP range."""

    endpoint_list = list(endpoints)
    clauses = {f"port {port}" for port in DEFAULT_GAME_PORTS}

    for endpoint in endpoint_list:
        if endpoint.remote_ip and endpoint.remote_port:
            clauses.add(f"(host {endpoint.remote_ip} and port {endpoint.remote_port})")
        elif endpoint.protocol == "udp" and endpoint.local_port:
            clauses.add(f"(udp and port {endpoint.local_port})")

    if not endpoint_list:
        # If process discovery is unavailable, capture both transports. The
        # protocol scanner will discard traffic that has no BDO-like records.
        return "tcp or udp"

    return f"(tcp or udp) and ({' or '.join(sorted(clauses))})"


def packet_matches_endpoints(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    endpoints: Iterable[GameEndpoint],
) -> bool:
    endpoint_list = list(endpoints)
    if not endpoint_list:
        return True

    for endpoint in endpoint_list:
        if endpoint.remote_ip and endpoint.remote_port:
            remote_matches = endpoint.remote_ip in {source_ip, destination_ip}
            port_matches = endpoint.remote_port in {source_port, destination_port}
            if remote_matches and port_matches:
                return True
        elif endpoint.protocol == "udp" and endpoint.local_port in {
            source_port,
            destination_port,
        }:
            return True

    return destination_port in DEFAULT_GAME_PORTS or source_port in DEFAULT_GAME_PORTS


def describe_endpoints(endpoints: Iterable[GameEndpoint]) -> str:
    endpoint_list = list(endpoints)
    if not endpoint_list:
        return "no Black Desert process endpoints found; scanning TCP and UDP payloads"

    descriptions = []
    for endpoint in endpoint_list:
        if endpoint.remote_ip and endpoint.remote_port:
            descriptions.append(
                f"{endpoint.protocol.upper()} {endpoint.remote_ip}:{endpoint.remote_port}"
            )
        else:
            descriptions.append(
                f"{endpoint.protocol.upper()} local port {endpoint.local_port}"
            )
    return ", ".join(descriptions)
