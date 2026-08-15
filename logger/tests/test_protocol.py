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

    def test_extracts_original_300_byte_five_name_record(self):
        records = extract_candidate_records(make_record(self.names))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].identifier, "630100af12")
        self.assertEqual([name.name for name in records[0].names], list(self.names))
        self.assertEqual([name.offset for name in records[0].names], [6, 100, 170, 210, 270])
        self.assertEqual(len(records[0].payload), 300)

    def test_reassembles_fragmented_record_per_tcp_flow(self):
        payload = make_record(self.names)
        scanner = StreamScanner()

        self.assertEqual(scanner.feed("server-flow", payload[:190]), [])
        records = scanner.feed("server-flow", payload[190:])

        self.assertEqual(len(records), 1)
        self.assertEqual([name.name for name in records[0].names], list(self.names))
        self.assertEqual(scanner.feed("server-flow", b"noise"), [])

    def test_rejects_changed_headers_and_general_name_groups(self):
        payload = make_record(self.names, header=bytes.fromhex("990203aabb"))

        self.assertEqual(extract_candidate_records(payload), [])

    def test_requires_exactly_five_original_style_names(self):
        four_names = make_record(self.names[:4])
        lowercase_name = make_record(("guild", *self.names[1:]))

        self.assertEqual(extract_candidate_records(four_names), [])
        self.assertEqual(extract_candidate_records(lowercase_name), [])

    def test_event_keeps_original_hex_offsets(self):
        record = extract_candidate_records(make_record(self.names))[0]

        line = record.to_event("12:34:56")
        event = json.loads(line.removeprefix(EVENT_PREFIX))

        self.assertEqual(event["type"], "candidate")
        self.assertEqual(event["time"], "12:34:56")
        self.assertEqual(len(event["names"]), 5)
        self.assertEqual(event["names"][0], {"name": "Guild", "offset": 12})
        self.assertNotIn("strategy", event)

    def test_flush_does_not_emit_incomplete_records(self):
        scanner = StreamScanner()
        scanner.feed("server-flow", make_record(self.names)[:250])

        self.assertEqual(scanner.flush(), [])


if __name__ == "__main__":
    unittest.main()
