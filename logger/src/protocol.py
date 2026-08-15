from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Hashable


EVENT_PREFIX = "IKUSA_EVENT "
HEADER_PATTERN = re.compile(rb".\x01\x00..", re.DOTALL)
MAX_NAME_LENGTH = 32
MAX_RECORD_BYTES = 512
MAX_STREAM_BUFFER = 8192
MIN_NAMES = 3
MAX_NAMES = 8
_ALLOWED_NAME_BYTES = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
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
    strategy: str

    def to_event(self, timestamp: str) -> str:
        event = {
            "type": "candidate",
            "identifier": self.identifier,
            "time": timestamp,
            "names": [
                {"name": name.name, "offset": name.offset * 2} for name in self.names
            ],
            "hex": self.payload.hex(),
            "strategy": self.strategy,
        }
        return EVENT_PREFIX + json.dumps(event, ensure_ascii=False, separators=(",", ":"))


def _is_valid_name(value: str) -> bool:
    if not 2 <= len(value) <= MAX_NAME_LENGTH:
        return False
    if not any(character.isalpha() for character in value):
        return False
    return all(ord(character) in _ALLOWED_NAME_BYTES for character in value)


def extract_utf16le_names(payload: bytes) -> list[NameMatch]:
    """Find ASCII-compatible BDO names stored as null-terminated UTF-16LE."""

    names: list[NameMatch] = []
    position = 0

    while position + 3 < len(payload):
        is_character = payload[position] in _ALLOWED_NAME_BYTES and payload[position + 1] == 0
        previous_is_character = (
            position >= 2
            and payload[position - 2] in _ALLOWED_NAME_BYTES
            and payload[position - 1] == 0
        )
        if not is_character or previous_is_character:
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

        terminated = end + 1 < len(payload) and payload[end] == 0 and payload[end + 1] == 0
        value = encoded.decode("ascii", errors="ignore")
        if _is_valid_name(value) and (terminated or len(encoded) == MAX_NAME_LENGTH):
            names.append(NameMatch(value, position, len(encoded) * 2))
            position = end + (2 if terminated else 0)
        else:
            position += 1

    return names


def _candidate_from_window(
    payload: bytes,
    start: int,
    end: int,
    names: list[NameMatch],
    strategy: str,
) -> CandidateRecord:
    window = payload[start:end][:MAX_RECORD_BYTES].ljust(MAX_RECORD_BYTES, b"\0")
    adjusted_names = tuple(
        NameMatch(name.name, name.offset - start, name.byte_length)
        for name in names[:MAX_NAMES]
        if name.offset >= start
    )
    return CandidateRecord(window[:5].hex(), adjusted_names, window, strategy)


def extract_candidate_records(payload: bytes, final: bool = False) -> list[CandidateRecord]:
    """Extract candidate combat records from a reassembled transport stream.

    The legacy header is still preferred, but the fallback aligns records to
    the first group of name fields. This makes the analyzer survive opcode,
    record-length, and field-count changes while names remain visible.
    """

    all_names = extract_utf16le_names(payload)
    if len(all_names) < MIN_NAMES:
        return []

    candidates: list[CandidateRecord] = []
    valid_headers: list[int] = []

    for header in HEADER_PATTERN.finditer(payload):
        start = header.start()
        if len(payload) - start < 300:
            continue
        window_names = [
            name for name in all_names if start <= name.offset < start + MAX_RECORD_BYTES
        ]
        if len(window_names) >= MIN_NAMES and window_names[0].offset - start <= 128:
            valid_headers.append(start)

    for index, start in enumerate(valid_headers):
        if index + 1 < len(valid_headers):
            end = valid_headers[index + 1]
        elif len(payload) - start >= MAX_RECORD_BYTES:
            end = start + MAX_RECORD_BYTES
        elif final:
            end = len(payload)
        else:
            # Wait for either the next record header or enough stream data to
            # make the padded candidate stable across subsequent packets.
            continue

        window_names = [name for name in all_names if start <= name.offset < end]
        if len(window_names) < MIN_NAMES:
            continue

        candidates.append(
            _candidate_from_window(payload, start, end, window_names[:MAX_NAMES], "header")
        )

    if candidates:
        return candidates

    index = 0
    while index < len(all_names):
        first = all_names[index]
        group = [first]
        next_index = index + 1
        while next_index < len(all_names) and len(group) < MAX_NAMES:
            name = all_names[next_index]
            if name.offset - first.offset >= MAX_RECORD_BYTES - 8:
                break
            group.append(name)
            next_index += 1

        if len(group) >= MIN_NAMES:
            start = max(0, first.offset - 6)
            if len(payload) - start < MAX_RECORD_BYTES and not final:
                break
            candidates.append(
                _candidate_from_window(
                    payload,
                    start,
                    min(len(payload), start + MAX_RECORD_BYTES),
                    group,
                    "name-group",
                )
            )
            index = next_index
        else:
            index += 1

    return candidates


class StreamScanner:
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
            fingerprint_data = candidate.payload + b"\0" + b"\0".join(
                name.name.encode("utf-8") for name in candidate.names
            )
            fingerprint = hashlib.sha1(fingerprint_data).hexdigest()
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
            candidates.extend(extract_candidate_records(buffer, final=True))
        return self._deduplicate(candidates)
