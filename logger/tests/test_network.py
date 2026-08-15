import unittest

from src.network import (
    GameEndpoint,
    build_capture_filter,
    packet_matches_endpoints,
)


class NetworkDiscoveryTests(unittest.TestCase):
    def test_filter_uses_discovered_endpoint_and_default_game_port(self):
        endpoint = GameEndpoint("tcp", "20.222.139.220", 9999)

        capture_filter = build_capture_filter([endpoint])

        self.assertIn("host 20.222.139.220 and port 9999", capture_filter)
        self.assertIn("port 8889", capture_filter)
        self.assertIn("tcp or udp", capture_filter)

    def test_empty_discovery_scans_both_transports(self):
        self.assertEqual(build_capture_filter([]), "tcp or udp")

    def test_filter_supports_unconnected_game_udp_socket(self):
        endpoint = GameEndpoint("udp", "", 0, local_ip="0.0.0.0", local_port=54321)

        capture_filter = build_capture_filter([endpoint])

        self.assertIn("udp and port 54321", capture_filter)
        self.assertTrue(
            packet_matches_endpoints("10.0.0.5", "20.1.2.3", 54321, 40000, [endpoint])
        )

    def test_endpoint_filter_matches_both_directions(self):
        endpoint = GameEndpoint("tcp", "20.222.139.220", 8889)

        self.assertTrue(
            packet_matches_endpoints("20.222.139.220", "10.0.0.5", 8889, 53000, [endpoint])
        )
        self.assertTrue(
            packet_matches_endpoints("10.0.0.5", "20.222.139.220", 53000, 8889, [endpoint])
        )
        self.assertFalse(
            packet_matches_endpoints("10.0.0.5", "1.1.1.1", 53000, 443, [endpoint])
        )


if __name__ == "__main__":
    unittest.main()
