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
    """Return active BDO world-server connections owned by the game process.

    psutil is deliberately optional. Packaged builds include it, while source
    checkouts can still fall back to the established TCP world-server port.
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
                # The original logger reads combat notifications from the BDO
                # world-server TCP stream. Other game-process connections are
                # launcher, authentication, web, or telemetry traffic and must
                # not be passed to the combat parser.
                if connection.type != socket.SOCK_STREAM:
                    continue

                local_ip, local_port = _address_parts(connection.laddr)
                remote_ip, remote_port = _address_parts(connection.raddr)
                if not remote_ip or remote_port not in DEFAULT_GAME_PORTS:
                    continue

                endpoints.add(
                    GameEndpoint(
                        protocol="tcp",
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
    """Capture only incoming packets from the active BDO world server."""

    clauses: set[str] = set()

    for endpoint in endpoints:
        if (
            endpoint.protocol != "tcp"
            or not endpoint.remote_ip
            or endpoint.remote_port not in DEFAULT_GAME_PORTS
        ):
            continue
        clause = f"(src host {endpoint.remote_ip} and src port {endpoint.remote_port}"
        if endpoint.local_port:
            clause += f" and dst port {endpoint.local_port}"
        clauses.add(clause + ")")

    if not clauses:
        return "tcp and src port 8889"

    return f"tcp and ({' or '.join(sorted(clauses))})"


def packet_matches_endpoints(
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    endpoints: Iterable[GameEndpoint],
) -> bool:
    endpoint_list = [
        endpoint
        for endpoint in endpoints
        if endpoint.protocol == "tcp"
        and endpoint.remote_ip
        and endpoint.remote_port in DEFAULT_GAME_PORTS
    ]
    if not endpoint_list:
        return source_port in DEFAULT_GAME_PORTS

    for endpoint in endpoint_list:
        remote_matches = source_ip == endpoint.remote_ip
        remote_port_matches = source_port == endpoint.remote_port
        local_port_matches = not endpoint.local_port or destination_port == endpoint.local_port
        if remote_matches and remote_port_matches and local_port_matches:
            return True

    return False


def describe_endpoints(endpoints: Iterable[GameEndpoint]) -> str:
    endpoint_list = list(endpoints)
    if not endpoint_list:
        return "game process not found; using incoming TCP port 8889 fallback"

    descriptions = []
    for endpoint in endpoint_list:
        descriptions.append(
            f"TCP {endpoint.remote_ip}:{endpoint.remote_port} -> local port {endpoint.local_port}"
        )
    return ", ".join(descriptions)
