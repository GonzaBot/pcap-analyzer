import unittest

from pcap_analyzer import (
    find_suspicious_dns_queries,
    is_trusted_domain,
    looks_like_dns_tunnel_label,
)


class DNSHeuristicTests(unittest.TestCase):
    def test_known_legitimate_domains_are_trusted(self):
        self.assertTrue(is_trusted_domain("securitydomain-pa.googleapis.com"))
        self.assertTrue(is_trusted_domain("avatars.githubusercontent.com"))
        self.assertTrue(is_trusted_domain("beacons.gcp.gvt2.com"))

    def test_legitimate_long_service_labels_do_not_look_like_tunnels(self):
        legitimate_labels = [
            "securitydomain-pa",
            "safebrowsingohttpgateway",
            "optimizationguide-pa",
            "dns-tunnel-check",
        ]

        for label in legitimate_labels:
            with self.subTest(label=label):
                self.assertFalse(looks_like_dns_tunnel_label(label))

    def test_single_long_suspicious_query_is_not_enough(self):
        payload = "mfrggzdfmztwq2lkobsxg5dfon2ca3dbmjqxgzjrmvqw42lomnxw2zls"
        queries = [(f"{payload}.example.net", 1.0)]

        self.assertEqual(find_suspicious_dns_queries(queries), [])

    def test_multiple_encoded_payloads_on_same_base_domain_are_suspicious(self):
        payloads = [
            "mfrggzdfmztwq2lkobsxg5dfon2ca3dbmjqxgzjrmvqw42lomnxw2zls",
            "nbswy3dpeb3w64tmmqxxe5dfmjqxgzjrmvqw42lomnxw2zlsmfrg",
            "ob2gk43uebxw4zban5xw2ylsnf2ca3dbmjqxgzjrmvqw42lommrx",
        ]
        queries = [(f"{payload}.evil.test", i) for i, payload in enumerate(payloads)]

        suspicious = find_suspicious_dns_queries(queries)

        self.assertEqual(len(suspicious), 3)
        self.assertTrue(all(qname.endswith(".evil.test") for qname, _, _ in suspicious))

    def test_very_long_encoded_payload_is_suspicious_by_itself(self):
        payload = (
            "a1b2c3d4e5f6a7b8c9d0"
            "a1b2c3d4e5f6a7b8c9d0"
            "a1b2c3d4e5f6a7b8c9d0"
            "a1b2c3d4e5f6a7b8c9d0"
            "a1b2c3d4e5f6a7b8c9d0"
        )
        queries = [(f"{payload}.evil.test", 1.0)]

        suspicious = find_suspicious_dns_queries(queries)

        self.assertEqual(len(suspicious), 1)


if __name__ == "__main__":
    unittest.main()
