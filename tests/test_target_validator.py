import os
import tempfile
import unittest

from core.target_validator import TargetValidator


class TestTargetValidator(unittest.TestCase):
    def test_valid_domain(self):
        v = TargetValidator()
        self.assertEqual(v.validate_and_normalize("example.com"), "example.com")

    def test_strips_scheme(self):
        v = TargetValidator()
        self.assertEqual(v.validate_and_normalize("https://example.com/"), "example.com")

    def test_blocks_private_ip(self):
        v = TargetValidator()
        with self.assertRaises(ValueError):
            v.validate_and_normalize("192.168.1.1")

    def test_blocks_gov_tld(self):
        v = TargetValidator()
        with self.assertRaises(ValueError):
            v.validate_and_normalize("agency.gov")

    def test_scope_file_allows_in_scope(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("example.com\n")
            path = fh.name
        try:
            v = TargetValidator(scope_file=path)
            self.assertEqual(
                v.validate_and_normalize("api.example.com"), "api.example.com"
            )
        finally:
            os.unlink(path)

    def test_scope_file_blocks_out_of_scope(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("example.com\n")
            path = fh.name
        try:
            v = TargetValidator(scope_file=path)
            with self.assertRaises(ValueError):
                v.validate_and_normalize("other.com")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
