import json
import unittest

from src.protocol import EVENT_PREFIX, StreamScanner, extract_candidate_records


def make_record(names, header=bytes.fromhex("630100af12")):
    payload = bytearray(300)
    payload[:5] = header
    for offset, name in zip((6, 100, 170, 210, 270), names):
        encoded = name.encode("utf-16le") + b"\0\0"
        payload[offset : offset + len(encoded)] = encoded
    return bytes(payload)


class ProtocolScannerTests(unittest.TestCase):
    def setUp(self):
        self.names = ("Guild", "FamilyOne", "CharOne", "FamilyTwo", "CharTwo")

    def test_extracts_legacy_header_without_fixed_ip_or_payload_length(self):
        records = extract_candidate_records(make_record(self.names) + b"\0" * 212)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].identifier, "630100af12")
        self.assertEqual([name.name for name in records[0].names], list(self.names))
        self.assertEqual([name.offset for name in records[0].names], [6, 100, 170, 210, 270])

    def test_reassembles_fragmented_payload_per_flow(self):
        payload = make_record(self.names) + b"\0" * 212
        scanner = StreamScanner()

        self.assertEqual(scanner.feed("server-flow", payload[:190]), [])
        records = scanner.feed("server-flow", payload[190:])

        self.assertEqual(len(records), 1)
        self.assertEqual([name.name for name in records[0].names], list(self.names))
        self.assertEqual(scanner.feed("server-flow", b"noise"), [])

    def test_fallback_finds_name_group_when_header_changes(self):
        payload = make_record(self.names, header=bytes.fromhex("990203aabb")) + b"\0" * 212

        records = extract_candidate_records(payload)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].strategy, "name-group")
        self.assertEqual([name.name for name in records[0].names], list(self.names))

    def test_event_is_structured_json_with_hex_offsets(self):
        record = extract_candidate_records(make_record(self.names) + b"\0" * 212)[0]

        line = record.to_event("12:34:56")
        event = json.loads(line.removeprefix(EVENT_PREFIX))

        self.assertEqual(event["type"], "candidate")
        self.assertEqual(event["time"], "12:34:56")
        self.assertEqual(event["names"][0], {"name": "Guild", "offset": 12})

    def test_flush_emits_last_short_record_from_offline_capture(self):
        scanner = StreamScanner()
        scanner.feed("server-flow", make_record(self.names))

        records = scanner.flush()

        self.assertEqual(len(records), 1)
        self.assertEqual([name.name for name in records[0].names], list(self.names))


if __name__ == "__main__":
    unittest.main()
