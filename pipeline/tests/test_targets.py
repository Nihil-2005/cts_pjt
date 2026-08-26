"""Unit tests for pipeline.targets — --target override parsing."""

import unittest

from pipeline.targets import (
    TargetOverrideError,
    any_remote,
    apply_targets,
    is_remote,
    parse_target,
)

PRODUCTS = {
    "juice_shop": "http://localhost:3000",
    "nodegoat": "http://localhost:4000",
    "bwapp": "http://localhost:8080",
}


class TestParseTarget(unittest.TestCase):
    def test_bare_host(self):
        self.assertEqual(parse_target("192.168.1.50"), (None, "192.168.1.50", None))

    def test_bare_host_with_port(self):
        self.assertEqual(parse_target("10.0.0.5:8080"), (None, "10.0.0.5", 8080))

    def test_keyed_host_port(self):
        self.assertEqual(
            parse_target("bwapp=192.168.1.1:8080"), ("bwapp", "192.168.1.1", 8080)
        )

    def test_keyed_with_scheme(self):
        self.assertEqual(
            parse_target("juice_shop=http://10.1.2.3:3000"),
            ("juice_shop", "10.1.2.3", 3000),
        )

    def test_invalid_raises(self):
        for bad in ("", "=host", "prod=", "not a target!!"):
            with self.assertRaises(TargetOverrideError):
                parse_target(bad)


class TestApplyTargets(unittest.TestCase):
    def test_no_overrides_returns_config(self):
        out = apply_targets([], PRODUCTS)
        self.assertEqual(out, PRODUCTS)

    def test_bare_host_moves_all_keeps_ports(self):
        out = apply_targets(["192.168.1.50"], PRODUCTS)
        self.assertEqual(out["juice_shop"], "http://192.168.1.50:3000")
        self.assertEqual(out["nodegoat"], "http://192.168.1.50:4000")
        self.assertEqual(out["bwapp"], "http://192.168.1.50:8080")

    def test_keyed_override_single_product(self):
        out = apply_targets(["bwapp=192.168.1.1"], PRODUCTS, selected=["bwapp"])
        self.assertEqual(out["bwapp"], "http://192.168.1.1")
        self.assertNotIn("juice_shop", out)  # scope limited by selection

    def test_keyed_port_wins(self):
        out = apply_targets(["bwapp=192.168.1.1:9999"], PRODUCTS)
        self.assertEqual(out["bwapp"], "http://192.168.1.1:9999")

    def test_unknown_product_rejected(self):
        with self.assertRaises(TargetOverrideError):
            apply_targets(["nope=1.2.3.4"], PRODUCTS)

    def test_two_bare_hosts_conflict(self):
        with self.assertRaises(TargetOverrideError):
            apply_targets(["1.1.1.1", "2.2.2.2"], PRODUCTS)

    def test_duplicate_keyed_rejected(self):
        with self.assertRaises(TargetOverrideError):
            apply_targets(["bwapp=1.1.1.1", "bwapp=2.2.2.2"], PRODUCTS)


class TestRemoteDetection(unittest.TestCase):
    def test_localhost_is_local(self):
        self.assertFalse(is_remote("http://localhost:3000"))
        self.assertFalse(is_remote("http://127.0.0.1:8080"))

    def test_lan_ip_is_remote(self):
        self.assertTrue(is_remote("http://192.168.1.50:3000"))

    def test_any_remote_mixed(self):
        self.assertTrue(
            any_remote(
                {
                    "a": "http://localhost:3000",
                    "b": "http://10.0.0.9:4000",
                }
            )
        )
        self.assertFalse(any_remote({"a": "http://localhost:3000"}))


if __name__ == "__main__":
    unittest.main()
