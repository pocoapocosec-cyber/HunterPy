import os
import tempfile
import unittest
from argparse import Namespace

from config.settings import Settings


class TestSettings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _args(self, **kw):
        defaults = dict(
            target="example.com", target_list=None, scope=None,
            mode="standard", modules=None, threads=10, timeout=30,
            rate_limit=10, delay=0.1,
            auth_url=None, username=None, username_list=None, password_list=None,
            proxy=None, user_agent=None, cookies=None,
            output=self.tmp, format="json", verbose=False, no_color=False,
            headers=None,
            no_nvd=False, nvd_offline=False, nvd_api_key=None,
        )
        defaults.update(kw)
        return Namespace(**defaults)

    def test_quick_preset_picks_subset(self):
        s = Settings(self._args(mode="quick"))
        self.assertIn("nikto", s.modules)
        self.assertNotIn("sqlmap", s.modules)

    def test_user_modules_override_preset(self):
        s = Settings(self._args(mode="full", modules=["headers"]))
        self.assertEqual(s.modules, ["headers"])

    def test_creates_output_dir(self):
        path = os.path.join(self.tmp, "newdir")
        Settings(self._args(output=path))
        self.assertTrue(os.path.isdir(path))

    def test_headers_parsed(self):
        s = Settings(self._args(headers=["X-Token: abc", "X-Env: prod"]))
        self.assertEqual(s.custom_headers["X-Token"], "abc")
        self.assertEqual(s.custom_headers["X-Env"], "prod")


if __name__ == "__main__":
    unittest.main()
