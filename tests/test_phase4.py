"""
tests/test_phase4.py — Phase 4 unit tests.

Covers:
  1. Normal window acquire/release lifecycle
  2. Over-release guard (in_flight never goes negative)
  3. Window saturation: workers block when all slots taken
  4. Acquire timeout returns False without modifying in_flight
  5. RTTEstimator EWMA convergence
  6. SACK payload round-trip (build → parse)
  7. PING/PONG payload round-trip
  8. _chunks_to_ranges helper
  9. SACK sender correctly builds ranges from written_chunks
 10. Window release ONLY on ACK (not after send)
"""

import struct
import threading
import time
import unittest

from window import RTTEstimator, WindowController
from protocol import (
    build_sack_payload, parse_sack_payload,
    build_ping_payload, parse_ping_payload,
)
from receiver import FileReceiver


# ─── RTTEstimator ─────────────────────────────────────────────────────────────

class TestRTTEstimator(unittest.TestCase):

    def test_no_samples_returns_none(self):
        est = RTTEstimator()
        self.assertIsNone(est.srtt)
        self.assertEqual(est.rttvar, 0.0)

    def test_first_sample_initialises_srtt(self):
        est = RTTEstimator()
        est.update(0.010)
        self.assertAlmostEqual(est.srtt, 0.010, places=6)
        self.assertAlmostEqual(est.rttvar, 0.005, places=6)  # sample/2

    def test_ewma_converges(self):
        est = RTTEstimator(alpha=0.125)
        for _ in range(100):
            est.update(0.050)
        self.assertAlmostEqual(est.srtt, 0.050, places=4)

    def test_negative_sample_ignored(self):
        est = RTTEstimator()
        est.update(-1.0)
        self.assertIsNone(est.srtt)

    def test_zero_sample_ignored(self):
        est = RTTEstimator()
        est.update(0.0)
        self.assertIsNone(est.srtt)

    def test_alpha_clamped(self):
        est = RTTEstimator(alpha=5.0)
        self.assertLessEqual(est._alpha, 1.0)


# ─── WindowController ─────────────────────────────────────────────────────────

class TestWindowController(unittest.TestCase):

    def _make(self, size=4):
        return WindowController(window_size=size, rtt_estimator=RTTEstimator())

    # ── Basic acquire/release ──────────────────────────────────────────────────

    def test_acquire_increments_in_flight(self):
        w = self._make(4)
        self.assertTrue(w.acquire(timeout=0.1))
        self.assertEqual(w.in_flight, 1)

    def test_release_decrements_in_flight(self):
        w = self._make(4)
        w.acquire(timeout=0.1)
        w.release(1)
        self.assertEqual(w.in_flight, 0)

    def test_release_bulk(self):
        w = self._make(8)
        for _ in range(5):
            w.acquire(timeout=0.1)
        self.assertEqual(w.in_flight, 5)
        w.release(5)
        self.assertEqual(w.in_flight, 0)

    # ── Over-release guard ────────────────────────────────────────────────────

    def test_over_release_clamped_to_in_flight(self):
        """release(count > in_flight) must not go negative or raise."""
        w = self._make(4)
        w.acquire(timeout=0.1)   # in_flight = 1
        w.release(10)             # request 10, but only 1 in flight
        self.assertEqual(w.in_flight, 0)

    def test_release_zero_in_flight_is_noop(self):
        w = self._make(4)
        w.release(5)   # nothing in flight — must not raise
        self.assertEqual(w.in_flight, 0)

    # ── Window saturation ─────────────────────────────────────────────────────

    def test_window_full_blocks_acquire(self):
        """Acquire should fail (timeout) when window is saturated."""
        w = self._make(2)
        w.acquire(timeout=0.1)
        w.acquire(timeout=0.1)
        # Window is full — next acquire should time out
        result = w.acquire(timeout=0.05)
        self.assertFalse(result)
        self.assertEqual(w.in_flight, 2)

    def test_release_unblocks_waiting_thread(self):
        """A blocked acquire() should succeed after release() is called."""
        w = self._make(1)
        w.acquire(timeout=0.1)   # fill the single slot

        results = []

        def _worker():
            results.append(w.acquire(timeout=2.0))

        t = threading.Thread(target=_worker)
        t.start()
        time.sleep(0.05)   # let thread reach acquire()
        w.release(1)       # unblock it
        t.join(timeout=1.0)
        self.assertEqual(results, [True])
        self.assertEqual(w.in_flight, 1)   # re-acquired in worker

    # ── Timeout does not modify state ─────────────────────────────────────────

    def test_timeout_does_not_increment_in_flight(self):
        w = self._make(1)
        w.acquire(timeout=0.1)         # fill
        w.acquire(timeout=0.05)        # times out
        self.assertEqual(w.in_flight, 1)  # unchanged

    # ── Properties ────────────────────────────────────────────────────────────

    def test_max_window_property(self):
        w = self._make(16)
        self.assertEqual(w.max_window, 16)

    # ── RTT integration ───────────────────────────────────────────────────────

    def test_update_rtt_forwarded_to_estimator(self):
        est = RTTEstimator()
        w = WindowController(window_size=4, rtt_estimator=est)
        w.update_rtt(0.020)
        self.assertAlmostEqual(est.srtt, 0.020, places=6)

    def test_set_rtt_adaptive_noop(self):
        w = self._make(4)
        w.set_rtt_adaptive(True)   # must not raise or change window size
        self.assertEqual(w.max_window, 4)

    # ── in_flight never exceeds window_size ──────────────────────────────────

    def test_in_flight_never_exceeds_window(self):
        size = 8
        w = self._make(size)
        for _ in range(size):
            w.acquire(timeout=0.1)
        self.assertLessEqual(w.in_flight, size)

    # ── Release only via ACK (not in finally) — verified by contract ─────────

    def test_release_after_ack_not_after_send(self):
        """
        Verifies the window lifecycle contract:
          acquire → send (in_flight stays up) → ACK → release.

        We simulate 'send' by NOT calling release() immediately after acquire,
        then verify in_flight is still 1 before the simulated ACK.
        """
        w = self._make(4)
        w.acquire(timeout=0.1)
        # Simulate: chunk sent, no ACK yet
        self.assertEqual(w.in_flight, 1)
        # Simulate: SACK arrives — ACK handling
        w.release(1)
        self.assertEqual(w.in_flight, 0)


# ─── Protocol: SACK ───────────────────────────────────────────────────────────

class TestSACKProtocol(unittest.TestCase):

    def test_empty_sack_roundtrip(self):
        payload = build_sack_payload([])
        ranges  = parse_sack_payload(payload)
        self.assertEqual(ranges, [])

    def test_single_range_roundtrip(self):
        payload = build_sack_payload([(0, 100)])
        ranges  = parse_sack_payload(payload)
        self.assertEqual(ranges, [(0, 100)])

    def test_multiple_ranges_roundtrip(self):
        original = [(0, 100), (150, 50), (300, 200)]
        payload  = build_sack_payload(original)
        parsed   = parse_sack_payload(payload)
        self.assertEqual(parsed, original)

    def test_parse_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_sack_payload(b"\x00")   # too short for count field

    def test_parse_truncated_range_raises(self):
        # count=1 but no range bytes
        payload = struct.pack("!H", 1)
        with self.assertRaises(ValueError):
            parse_sack_payload(payload)

    def test_large_chunk_ids(self):
        ranges  = [(0, 1_000_000)]
        payload = build_sack_payload(ranges)
        parsed  = parse_sack_payload(payload)
        self.assertEqual(parsed, ranges)


# ─── Protocol: PING/PONG ──────────────────────────────────────────────────────

class TestPingPongProtocol(unittest.TestCase):

    def test_roundtrip(self):
        ts  = 1_234_567_890_123_456_789
        raw = build_ping_payload(ts)
        self.assertEqual(parse_ping_payload(raw), ts)

    def test_zero_timestamp(self):
        raw = build_ping_payload(0)
        self.assertEqual(parse_ping_payload(raw), 0)

    def test_parse_too_short_raises(self):
        with self.assertRaises(ValueError):
            parse_ping_payload(b"\x00\x01\x02")


# ─── FileReceiver._chunks_to_ranges ──────────────────────────────────────────

class TestChunksToRanges(unittest.TestCase):

    def test_empty(self):
        self.assertEqual(FileReceiver._chunks_to_ranges([]), [])

    def test_single(self):
        self.assertEqual(FileReceiver._chunks_to_ranges([5]), [(5, 1)])

    def test_contiguous(self):
        self.assertEqual(FileReceiver._chunks_to_ranges([0, 1, 2, 3]), [(0, 4)])

    def test_two_ranges(self):
        result = FileReceiver._chunks_to_ranges([0, 1, 2, 5, 6])
        self.assertEqual(result, [(0, 3), (5, 2)])

    def test_all_gaps(self):
        result = FileReceiver._chunks_to_ranges([0, 2, 4])
        self.assertEqual(result, [(0, 1), (2, 1), (4, 1)])

    def test_large_contiguous(self):
        ids    = list(range(10_000))
        result = FileReceiver._chunks_to_ranges(ids)
        self.assertEqual(result, [(0, 10_000)])

    def test_large_scattered(self):
        ids    = list(range(0, 100, 2))   # 0,2,4,...,98
        result = FileReceiver._chunks_to_ranges(ids)
        self.assertEqual(len(result), 50)
        for start, run in result:
            self.assertEqual(run, 1)

    # ── Verify ranges expand back to original IDs ────────────────────────────

    def test_roundtrip_arbitrary(self):
        ids     = sorted([0, 1, 2, 10, 11, 50, 100, 101, 102, 103])
        ranges  = FileReceiver._chunks_to_ranges(ids)
        rebuilt = []
        for start, run in ranges:
            rebuilt.extend(range(start, start + run))
        self.assertEqual(rebuilt, ids)


# ─── Packet loss simulation: window prevents over-send ───────────────────────

class TestWindowUnderPacketLoss(unittest.TestCase):
    """
    Simulates a scenario where ACKs arrive late.

    Verifies:
      - in_flight never exceeds window_size at any point
      - All slots are eventually released
    """

    def test_in_flight_ceiling_under_delayed_acks(self):
        window_size = 4
        w           = self._make(window_size)
        max_observed = [0]
        releases     = []

        def _sender():
            for _ in range(window_size * 2):
                w.acquire(timeout=2.0)
                with threading.Lock():
                    observed = w.in_flight
                    if observed > max_observed[0]:
                        max_observed[0] = observed

        def _ack_drip():
            # Slowly release one slot at a time
            for _ in range(window_size * 2):
                time.sleep(0.02)
                w.release(1)
                releases.append(1)

        t_send = threading.Thread(target=_sender)
        t_ack  = threading.Thread(target=_ack_drip)
        t_ack.start()
        t_send.start()
        t_send.join(timeout=5.0)
        t_ack.join(timeout=5.0)

        self.assertLessEqual(max_observed[0], window_size)
        self.assertEqual(len(releases), window_size * 2)

    @staticmethod
    def _make(size):
        return WindowController(window_size=size, rtt_estimator=RTTEstimator())


if __name__ == "__main__":
    unittest.main()
