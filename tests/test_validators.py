import unittest
from utils.validators import TargetValidator


class TestTargetValidator(unittest.TestCase):
    def setUp(self):
        self.v = TargetValidator()

    def test_valid_domain(self):
        self.assertEqual(self.v.validate("example.com"), "example.com")

    def test_strips_scheme(self):
        self.assertEqual(self.v.validate("https://example.com/"), "example.com")

    def test_valid_ip(self):
        self.assertEqual(self.v.validate("93.184.216.34"), "93.184.216.34")

    def test_blocks_localhost(self):
        with self.assertRaises(ValueError):
            self.v.validate("localhost")

    def test_blocks_loopback(self):
        with self.assertRaises(ValueError):
            self.v.validate("127.0.0.1")

    def test_blocks_private_ip(self):
        for ip in ("10.0.0.5", "172.16.5.4", "192.168.1.1", "169.254.1.1"):
            with self.assertRaises(ValueError):
                self.v.validate(ip)

    def test_blocks_gov_and_mil(self):
        for d in ("agency.gov", "service.mil"):
            with self.assertRaises(ValueError):
                self.v.validate(d)

    def test_blocks_invalid_domain(self):
        for bad in ("not_a_domain", "...", ""):
            with self.assertRaises(ValueError):
                self.v.validate(bad)


if __name__ == "__main__":
    unittest.main()
