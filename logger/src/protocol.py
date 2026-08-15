from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Hashable


EVENT_PREFIX = "IKUSA_EVENT "

# The opcode byte can change in a BDO patch. The stable 0x01/0x00 portion is
# preferred, while the exact five-name record shape remains authoritative.
HEADER_PATTERN = re.compile(rb".\x01\x00..", re.DOTALL)
NAME_PATTERN = re.compile(r"^[A-Z][A-Za-z0-9_]{2,15}$")
RECORD_BYTES = 300
EXPECTED_NAMES = 5
MAX_NAME_LENGTH = 16
MAX_STREAM_BUFFER = RECORD_BYTES * 8
MIN_NAME_SPAN = 120
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

    def to_event(self, timestamp: str) -> str:
        event = {
            "type": "candidate",
            "identifier": self.identifier,
            "time": timestamp,
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

    A patch may change the leading opcode. In that case the fallback aligns a
    window from the five widely spaced name fields that the original record
    contains. It does not accept arbitrary or short name groups.
    """

    del final  # Incomplete records were never emitted by the original parser.
    candidates: list[CandidateRecord] = []
    next_allowed_start = 0

    for header in HEADER_PATTERN.finditer(payload):
        start = header.start()
        if start < next_allowed_start or len(payload) - start < RECORD_BYTES:
            continue

        window = payload[start : start + RECORD_BYTES]
        names = extract_utf16le_names(window)
        if len(names) != EXPECTED_NAMES:
            continue

        candidates.append(
            CandidateRecord(window[:5].hex(), tuple(names), window)
        )
        next_allowed_start = start + RECORD_BYTES

    if candidates:
        return candidates

    # The stable header may also change. Keep this fallback limited to the
    # original record length, exact field count, and broad field distribution.
    all_names = extract_utf16le_names(payload)
    next_allowed_start = 0
    for first_name in all_names:
        start = max(0, first_name.offset - 6)
        if start < next_allowed_start or len(payload) - start < RECORD_BYTES:
            continue

        window = payload[start : start + RECORD_BYTES]
        names = extract_utf16le_names(window)
        if len(names) != EXPECTED_NAMES:
            continue
        if names[-1].offset - names[0].offset < MIN_NAME_SPAN:
            continue

        candidates.append(
            CandidateRecord(window[:5].hex(), tuple(names), window)
        )
        next_allowed_start = start + RECORD_BYTES

    return candidates


class StreamScanner:
    """Reassemble each incoming TCP flow without broad payload discovery."""

    def __init__(self) -> None:
        self._buffers: dict[Hashable, bytes] = {}
        self._recent_fingerprints: deque[str] = deque(maxlen=4096)
        self._fingerprint_set: set[str] = set()

    def _remember(self, fingerprint: str) -> bool:
        if fingerprint in self._fingerprint_set:
            return False

        if len(self._recent_fingerprints) == self._recent_fingerprints.maxlen:
            oldest = self._recent_fingerprints.popleft()
            self._fingerprint_set.discard(oldest)

        self._recent_fingerprints.append(fingerprint)
        self._fingerprint_set.add(fingerprint)
        return True

    def _deduplicate(self, candidates: list[CandidateRecord]) -> list[CandidateRecord]:
        unique_candidates: list[CandidateRecord] = []
        for candidate in candidates:
            fingerprint = hashlib.sha1(candidate.payload).hexdigest()
            if self._remember(fingerprint):
                unique_candidates.append(candidate)
        return unique_candidates

    def feed(self, flow: Hashable, payload: bytes) -> list[CandidateRecord]:
        if not payload:
            return []

        buffer = self._buffers.get(flow, b"") + payload
        if len(buffer) > MAX_STREAM_BUFFER:
            buffer = buffer[-MAX_STREAM_BUFFER:]
        self._buffers[flow] = buffer
        return self._deduplicate(extract_candidate_records(buffer))

    def flush(self) -> list[CandidateRecord]:
        candidates: list[CandidateRecord] = []
        for buffer in self._buffers.values():
            candidates.extend(extract_candidate_records(buffer))
        return self._deduplicate(candidates)
