import unittest

from src.network import (
    GameEndpoint,
    build_capture_filter,
    packet_matches_endpoints,
)


class NetworkDiscoveryTests(unittest.TestCase):
    def test_filter_targets_only_discovered_incoming_world_stream(self):
        endpoint = GameEndpoint(
            "tcp",
            "20.222.139.220",
            8889,
            local_ip="10.0.0.5",
            local_port=53000,
        )

        capture_filter = build_capture_filter([endpoint])

        self.assertIn("src host 20.222.139.220", capture_filter)
        self.assertIn("src port 8889", capture_filter)
        self.assertIn("dst port 53000", capture_filter)
        self.assertNotIn("udp", capture_filter)

    def test_empty_discovery_uses_only_original_world_server_port(self):
        self.assertEqual(build_capture_filter([]), "tcp and src port 8889")

    def test_non_world_endpoints_are_not_added_to_capture(self):
        endpoints = [
            GameEndpoint("tcp", "20.1.2.3", 443, local_port=50000),
            GameEndpoint("udp", "20.1.2.4", 8889, local_port=50001),
        ]

        self.assertEqual(build_capture_filter(endpoints), "tcp and src port 8889")

    def test_endpoint_filter_accepts_only_server_to_client_direction(self):
        endpoint = GameEndpoint(
            "tcp",
            "20.222.139.220",
            8889,
            local_ip="10.0.0.5",
            local_port=53000,
        )

        self.assertTrue(
            packet_matches_endpoints(
                "20.222.139.220", "10.0.0.5", 8889, 53000, [endpoint]
            )
        )
        self.assertFalse(
            packet_matches_endpoints(
                "10.0.0.5", "20.222.139.220", 53000, 8889, [endpoint]
            )
        )
        self.assertFalse(
            packet_matches_endpoints(
                "20.222.139.220", "10.0.0.5", 8889, 53001, [endpoint]
            )
        )


if __name__ == "__main__":
    unittest.main()
