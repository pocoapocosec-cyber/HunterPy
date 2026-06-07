"""Tests for ScanPersistence + ProgressTracker (the helpers extracted
out of ScannerEngine to break up the god-object)."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import MagicMock

from core.progress_tracker import ProgressTracker
from core.scan_persistence import ScanPersistence


class ScanPersistenceTests(unittest.TestCase):
    def test_save_checkpoint_passes_through_to_db(self):
        db = MagicMock()
        p = ScanPersistence(db=db)
        ok = p.save_checkpoint(42, "headers", "completed", {"x": 1})
        self.assertTrue(ok)
        db.save_checkpoint.assert_called_once_with(
            42, "headers", "completed", {"x": 1})

    def test_save_checkpoint_returns_false_when_scan_id_missing(self):
        db = MagicMock()
        p = ScanPersistence(db=db)
        self.assertFalse(p.save_checkpoint(None, "headers", "ok", {}))
        db.save_checkpoint.assert_not_called()

    def test_db_failure_does_not_raise(self):
        db = MagicMock()
        db.save_checkpoint.side_effect = RuntimeError("sqlite locked")
        logger = MagicMock()
        p = ScanPersistence(db=db, logger=logger)
        # Must NOT raise — checkpoint failures are observable but
        # never abort the scan.
        ok = p.save_checkpoint(1, "headers", "ok", {})
        self.assertFalse(ok)
        # And the failure was logged through the scan logger
        logger.log_error.assert_called_once()
        self.assertIn("headers", logger.log_error.call_args[0][0])

    def test_logger_optional(self):
        db = MagicMock()
        db.save_checkpoint.side_effect = RuntimeError("oops")
        p = ScanPersistence(db=db, logger=None)
        # Doesn't crash even without a logger
        self.assertFalse(p.save_checkpoint(1, "x", "y", {}))


class ProgressTrackerTests(unittest.TestCase):
    def test_starts_at_zero(self):
        p = ProgressTracker(total_modules=5)
        self.assertEqual(p.started_count, 0)
        self.assertEqual(p.completed_count, 0)
        self.assertEqual(p.percent, 0)

    def test_mark_started_increments_started_only(self):
        p = ProgressTracker(total_modules=3)
        p.mark_started("headers")
        self.assertEqual(p.started_count, 1)
        self.assertEqual(p.completed_count, 0)

    def test_mark_completed_includes_module_in_completed_list(self):
        p = ProgressTracker(total_modules=3)
        p.mark_started("headers")
        p.mark_completed("headers")
        self.assertEqual(p.completed_modules, ["headers"])

    def test_percent_caps_at_100(self):
        p = ProgressTracker(total_modules=2)
        p.mark_completed("a")
        p.mark_completed("b")
        p.mark_completed("c")     # over-count shouldn't break things
        self.assertEqual(p.percent, 100)

    def test_percent_zero_when_total_unknown(self):
        p = ProgressTracker(total_modules=0)
        p.mark_completed("anything")
        self.assertEqual(p.percent, 0)

    def test_failed_modules_records_reason(self):
        p = ProgressTracker(total_modules=2)
        p.mark_failed("nuclei", "tool not found")
        self.assertEqual(p.failed_modules, {"nuclei": "tool not found"})

    def test_snapshot_returns_serialisable_data(self):
        p = ProgressTracker(total_modules=4)
        p.mark_started("headers")
        p.mark_completed("headers")
        p.mark_started("nuclei")
        p.mark_failed("nuclei", "tool not found")
        snap = p.snapshot()
        self.assertEqual(snap["total_modules"], 4)
        self.assertEqual(snap["started_count"], 2)
        self.assertEqual(snap["completed_count"], 1)
        self.assertEqual(snap["failed_count"], 1)
        self.assertEqual(snap["completed"], ["headers"])
        self.assertIn("nuclei", snap["failed"])

    def test_thread_safe_under_concurrent_mark_completed(self):
        p = ProgressTracker(total_modules=200)

        def worker(start_idx):
            for i in range(start_idx, start_idx + 100):
                p.mark_started(f"m{i}")
                p.mark_completed(f"m{i}")

        threads = [threading.Thread(target=worker, args=(i * 100,))
                   for i in range(2)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(p.completed_count, 200)
        self.assertEqual(p.started_count, 200)


if __name__ == "__main__":
    unittest.main()
