import unittest
from utils.output_parser import NmapParser, NiktoParser


class TestNmapParser(unittest.TestCase):
    def setUp(self):
        self.p = NmapParser()

    def test_parses_open_port_with_version(self):
        r = self.p.parse_line("80/tcp   open  http    Apache httpd 2.4.41")
        self.assertEqual(r["port"], 80)
        self.assertEqual(r["state"], "open")
        self.assertEqual(r["service"], "http")
        self.assertIn("Apache", r["version"])

    def test_parses_filtered_port(self):
        r = self.p.parse_line("22/tcp filtered ssh")
        self.assertEqual(r["state"], "filtered")
        self.assertEqual(r["service"], "ssh")

    def test_parses_udp(self):
        r = self.p.parse_line("53/udp   open  domain")
        self.assertEqual(r["proto"], "udp")
        self.assertIsNone(r["version"])

    def test_handles_malformed_line(self):
        self.assertIsNone(self.p.parse_line("not valid nmap output"))
        self.assertIsNone(self.p.parse_line(""))


class TestNiktoParser(unittest.TestCase):
    def setUp(self):
        self.p = NiktoParser()

    def test_parses_osvdb_finding(self):
        r = self.p.parse_line("+ OSVDB-3092: /admin/: This might be interesting...")
        self.assertEqual(r["osvdb"], "OSVDB-3092")
        self.assertIn("/admin", r["path"])

    def test_parses_missing_header(self):
        r = self.p.parse_line("+ The anti-clickjacking X-Frame-Options header is not present.")
        self.assertEqual(r["type"], "missing_header")

    def test_parses_exposed_file(self):
        r = self.p.parse_line("+ /.git/HEAD: .git directory found, source code may be exposed.")
        self.assertEqual(r["type"], "exposed_file")

    def test_ignores_non_plus_line(self):
        self.assertIsNone(self.p.parse_line("- Nikto v2.1.6"))


if __name__ == "__main__":
    unittest.main()
