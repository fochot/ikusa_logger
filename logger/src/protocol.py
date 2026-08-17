from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Hashable


EVENT_PREFIX = "IKUSA_EVENT "

COMBAT_HEADER = bytes.fromhex("720100fe1a")
NAME_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9_]{2,15}$")
RECORD_BYTES = 300
EXPECTED_NAMES = 5
MAX_NAME_LENGTH = 16
MAX_STREAM_BUFFER = RECORD_BYTES * 8
EXPECTED_NAME_OFFSETS = (5, 68, 137, 202, 264)
KILL_BYTE_OFFSET = 67
TCP_SEQUENCE_MODULUS = 1 << 32
TCP_SEQUENCE_HALF_RANGE = TCP_SEQUENCE_MODULUS >> 1
_ALLOWED_NAME_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
)


@dataclass(frozen=True)
class NameMatch:
    name: str
    offset: int
    byte_length: int


@dataclass(frozen=True)
class CandidateRecord:
    identifier: str
    names: tuple[NameMatch, ...]
    payload: bytes
    kill: bool

    def to_event(self, timestamp: str) -> str:
        event = {
            "type": "candidate",
            "identifier": self.identifier,
            "time": timestamp,
            "kill": self.kill,
            "names": [
                {"name": name.name, "offset": name.offset * 2} for name in self.names
            ],
            "hex": self.payload.hex(),
        }
        return EVENT_PREFIX + json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def extract_utf16le_names(payload: bytes) -> list[NameMatch]:
    """Extract names using the same rules as the original logger."""

    names: list[NameMatch] = []
    position = 0

    while position + 5 < len(payload):
        starts_name = (
            payload[position] in _ALLOWED_NAME_BYTES and payload[position + 1] == 0
        )
        previous_is_name = (
            position >= 2
            and payload[position - 2] in _ALLOWED_NAME_BYTES
            and payload[position - 1] == 0
        )
        if not starts_name or previous_is_name:
            position += 1
            continue

        end = position
        encoded = bytearray()
        while (
            end + 1 < len(payload)
            and len(encoded) < MAX_NAME_LENGTH
            and payload[end] in _ALLOWED_NAME_BYTES
            and payload[end + 1] == 0
        ):
            encoded.append(payload[end])
            end += 2

        terminated = end + 1 < len(payload) and payload[end : end + 2] == b"\0\0"
        value = encoded.decode("ascii", errors="ignore")
        if terminated and NAME_PATTERN.fullmatch(value):
            names.append(NameMatch(value, position, len(encoded) * 2))
            position = end + 2
        else:
            position += 1

    return names


def extract_candidate_records(payload: bytes, final: bool = False) -> list[CandidateRecord]:
    """Return complete records matching the original combat-data shape.

    Records are aligned only from the original combat header. TCP reassembly
    handles headers and records split across packets without widening the
    scanner to unrelated five-name payloads.
    """

    del final  # Incomplete records were never emitted by the original parser.
    candidates: list[CandidateRecord] = []
    next_allowed_start = 0

    start = payload.find(COMBAT_HEADER)
    while start >= 0:
        if start < next_allowed_start or len(payload) - start < RECORD_BYTES:
            start = payload.find(COMBAT_HEADER, start + 1)
            continue

        window = payload[start : start + RECORD_BYTES]
        names = extract_utf16le_names(window)
        if not _has_original_combat_layout(window, names):
            start = payload.find(COMBAT_HEADER, start + 1)
            continue

        candidates.append(_candidate_record(window, names))
        next_allowed_start = start + RECORD_BYTES
        start = payload.find(COMBAT_HEADER, start + RECORD_BYTES)

    return candidates


def _has_original_combat_layout(payload: bytes, names: list[NameMatch]) -> bool:
    if len(names) != EXPECTED_NAMES:
        return False

    if tuple(name.offset for name in names) != EXPECTED_NAME_OFFSETS:
        return False

    return payload[KILL_BYTE_OFFSET] in (0, 1)


def _candidate_record(payload: bytes, names: list[NameMatch]) -> CandidateRecord:
    return CandidateRecord(
        payload[:5].hex(),
        tuple(names),
        payload,
        payload[KILL_BYTE_OFFSET] == 1,
    )


class StreamScanner:
    """Reassemble each incoming TCP flow without broad payload discovery."""

    def __init__(self) -> None:
        self._buffers: dict[Hashable, bytes] = {}
        self._next_sequences: dict[Hashable, int] = {}

    def reset_flow(self, flow: Hashable) -> None:
        """Forget stream state when a new TCP connection starts."""

        self._buffers.pop(flow, None)
        self._next_sequences.pop(flow, None)

    def _unseen_payload(
        self,
        flow: Hashable,
        payload: bytes,
        sequence: int | None,
    ) -> bytes:
        if sequence is None:
            return payload

        next_sequence = self._next_sequences.get(flow)
        if next_sequence is None:
            self._next_sequences[flow] = sequence + len(payload)
            return payload

        # Scapy exposes the 32-bit wire value. Unwrap it around our monotonic
        # high-water mark so long-running connections survive a sequence wrap.
        sequence_base = next_sequence - (next_sequence % TCP_SEQUENCE_MODULUS)
        sequence = sequence_base + (sequence % TCP_SEQUENCE_MODULUS)
        if sequence - next_sequence > TCP_SEQUENCE_HALF_RANGE:
            sequence -= TCP_SEQUENCE_MODULUS
        elif next_sequence - sequence > TCP_SEQUENCE_HALF_RANGE:
            sequence += TCP_SEQUENCE_MODULUS

        if sequence > next_sequence:
            # Missing TCP bytes must never be bridged with unrelated payload.
            # Begin a fresh scan at the first observed byte after the gap.
            self._buffers.pop(flow, None)
            self._next_sequences[flow] = sequence + len(payload)
            return payload

        overlap = next_sequence - sequence
        if overlap >= len(payload):
            return b""

        unseen = payload[overlap:]
        self._next_sequences[flow] = next_sequence + len(unseen)
        return unseen

    def _scan_buffer(self, flow: Hashable) -> list[CandidateRecord]:
        buffer = self._buffers.get(flow, b"")
        candidates = extract_candidate_records(buffer)
        if not candidates:
            return []

        # A parsed record is complete. Remove it and everything before it so a
        # later packet cannot turn the same bytes into a shifted second record.
        consumed_until = 0
        search_from = 0
        for candidate in candidates:
            start = buffer.find(candidate.payload, search_from)
            if start < 0:
                continue
            consumed_until = start + len(candidate.payload)
            search_from = consumed_until

        if consumed_until:
            self._buffers[flow] = buffer[consumed_until:]
        return candidates

    def feed(
        self,
        flow: Hashable,
        payload: bytes,
        sequence: int | None = None,
    ) -> list[CandidateRecord]:
        if not payload:
            return []

        unseen = self._unseen_payload(flow, payload, sequence)
        if not unseen:
            return []

        buffer = self._buffers.get(flow, b"") + unseen
        if len(buffer) > MAX_STREAM_BUFFER:
            buffer = buffer[-MAX_STREAM_BUFFER:]
        self._buffers[flow] = buffer
        return self._scan_buffer(flow)

    def flush(self) -> list[CandidateRecord]:
        candidates: list[CandidateRecord] = []
        for flow in list(self._buffers):
            candidates.extend(self._scan_buffer(flow))
        return candidates
