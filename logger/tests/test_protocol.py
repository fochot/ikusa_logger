import json
import unittest

from src.protocol import EVENT_PREFIX, StreamScanner, extract_candidate_records


def make_record(
    names,
    header=bytes.fromhex("630100af12"),
    offsets=(6, 100, 170, 210, 270),
):
    payload = bytearray(300)
    payload[:5] = header
    for offset, name in zip(offsets, names):
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

    def test_ignores_tcp_retransmissions_and_overlapping_bytes(self):
        payload = make_record(self.names)
        scanner = StreamScanner()

        self.assertEqual(scanner.feed("server-flow", payload[:190], sequence=1000), [])
        records = scanner.feed("server-flow", payload[190:], sequence=1190)

        self.assertEqual(len(records), 1)
        self.assertEqual(scanner.feed("server-flow", payload[150:], sequence=1150), [])
        self.assertEqual(scanner.feed("server-flow", payload, sequence=1000), [])

    def test_keeps_legitimate_identical_records_at_new_sequence_numbers(self):
        payload = make_record(self.names)
        scanner = StreamScanner()

        first = scanner.feed("server-flow", payload, sequence=1000)
        second = scanner.feed("server-flow", payload, sequence=1300)

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)

    def test_consumes_a_record_but_keeps_the_next_partial_record(self):
        first_payload = make_record(self.names)
        second_names = ("Guild", "FamilyNew", "CharNew", "EnemyNew", "EnemyChar")
        second_payload = make_record(second_names)
        scanner = StreamScanner()

        first = scanner.feed("server-flow", first_payload + second_payload[:150])
        second = scanner.feed("server-flow", second_payload[150:])

        self.assertEqual(len(first), 1)
        self.assertEqual(len(second), 1)
        self.assertEqual(
            [name.name for name in second[0].names],
            list(second_names),
        )

    def test_handles_tcp_sequence_number_wraparound(self):
        payload = make_record(self.names)
        scanner = StreamScanner()
        start = (1 << 32) - 150

        self.assertEqual(scanner.feed("server-flow", payload[:150], sequence=start), [])
        records = scanner.feed("server-flow", payload[150:], sequence=0)

        self.assertEqual(len(records), 1)

    def test_does_not_join_payload_across_a_tcp_gap(self):
        payload = make_record(self.names)
        scanner = StreamScanner()

        self.assertEqual(scanner.feed("server-flow", payload[:150], sequence=1000), [])
        self.assertEqual(scanner.feed("server-flow", payload[150:], sequence=1200), [])

    def test_reset_flow_accepts_a_reused_tcp_tuple(self):
        payload = make_record(self.names)
        scanner = StreamScanner()

        self.assertEqual(len(scanner.feed("server-flow", payload, sequence=1000)), 1)
        scanner.reset_flow("server-flow")

        self.assertEqual(len(scanner.feed("server-flow", payload, sequence=25)), 1)

    def test_accepts_changed_header_with_original_record_shape(self):
        payload = make_record(self.names, header=bytes.fromhex("990203aabb"))

        records = extract_candidate_records(payload)

        self.assertEqual(len(records), 1)
        self.assertEqual([name.name for name in records[0].names], list(self.names))

    def test_rejects_dense_general_name_groups(self):
        payload = make_record(
            self.names,
            header=bytes.fromhex("990203aabb"),
            offsets=(6, 30, 55, 80, 105),
        )

        self.assertEqual(extract_candidate_records(payload), [])

    def test_rejects_header_match_without_an_early_first_name(self):
        payload = make_record(
            self.names,
            offsets=(60, 105, 160, 215, 270),
        )

        self.assertEqual(extract_candidate_records(payload), [])

    def test_requires_exactly_five_original_style_names(self):
        four_names = make_record(self.names[:4])
        lowercase_name = make_record(("guild", *self.names[1:]))
        six_names = make_record(
            (*self.names, "ExtraName"),
            header=bytes.fromhex("990203aabb"),
            offsets=(6, 70, 125, 175, 225, 270),
        )

        self.assertEqual(extract_candidate_records(four_names), [])
        self.assertEqual(extract_candidate_records(lowercase_name), [])
        self.assertEqual(extract_candidate_records(six_names), [])

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
