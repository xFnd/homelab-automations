"""S51 (16/10): números do bloqueio lidos direto do nftables (o cscli metrics não funciona dentro do sandbox)."""
import unittest

from _load import load

col = load("collect", "vps1-relay", "collect.py")

V4 = {"nftables": [
    {"metainfo": {"version": "1.0.9"}},
    {"table": {"family": "ip", "name": "crowdsec"}},
    {"counter": {"family": "ip", "name": "processed", "table": "crowdsec", "packets": 999, "bytes": 1}},
    {"counter": {"family": "ip", "name": "crowdsec-blacklists-CAPI", "table": "crowdsec", "packets": 4730, "bytes": 284093}},
    {"counter": {"family": "ip", "name": "crowdsec-blacklists-crowdsec", "table": "crowdsec", "packets": 8781, "bytes": 577206}},
    {"counter": {"family": "ip", "name": "crowdsec-blacklists-cscli-import", "table": "crowdsec", "packets": 12, "bytes": 700}},
    {"set": {"family": "ip", "name": "crowdsec-blacklists-CAPI", "table": "crowdsec",
             "elem": [{"elem": {"val": "1.1.1.1", "timeout": 10, "expires": 5}}, {"elem": {"val": "2.2.2.2"}}]}},
    {"set": {"family": "ip", "name": "crowdsec-blacklists-crowdsec", "table": "crowdsec", "elem": [{"elem": {"val": "3.3.3.3"}}]}},
    {"set": {"family": "ip", "name": "crowdsec-blacklists-cscli-import", "table": "crowdsec"}},
    {"chain": {"family": "ip", "table": "crowdsec", "name": "crowdsec-chain-input"}},
]}
V6 = {"nftables": [
    {"counter": {"family": "ip6", "name": "crowdsec6-blacklists-CAPI", "table": "crowdsec6", "packets": 5, "bytes": 300}},
    {"set": {"family": "ip6", "name": "crowdsec6-blacklists-CAPI", "table": "crowdsec6", "elem": [{"elem": {"val": "2001:db8::1"}}]}},
]}


class ParseNft(unittest.TestCase):
    def test_counts_elements_and_counters_per_origin_merging_ipv4_and_ipv6(self):
        b = col.parse_nft([V4, V6])
        self.assertEqual(b["active"], {"CAPI": 3, "crowdsec": 1, "cscli-import": 0})
        self.assertEqual(b["dropped_packets"], {"CAPI": 4735, "crowdsec": 8781, "cscli-import": 12})
        self.assertEqual(b["dropped_bytes"]["CAPI"], 284393)
        self.assertNotIn("processed", b["dropped_packets"])

    def test_plain_string_elements_are_counted(self):
        b = col.parse_nft([{"nftables": [{"set": {"name": "crowdsec-blacklists-cscli", "elem": ["4.4.4.4", "5.5.5.5"]}}]}])
        self.assertEqual(b["active"], {"cscli": 2})

    def test_missing_tables_give_empty_numbers(self):
        b = col.parse_nft([None, {"nftables": []}])
        self.assertEqual((b["active"], b["dropped_packets"]), ({}, {}))


class Drops24h(unittest.TestCase):
    def test_first_sample_has_zero_window(self):
        delta, window_h, hist = col.drops_24h([], now=1000, current={"CAPI": 50})
        self.assertEqual((delta, window_h, len(hist)), ({"CAPI": 0}, 0.0, 1))

    def test_delta_against_the_oldest_sample_inside_24h(self):
        hist = [{"ts": 0, "p": {"CAPI": 100, "crowdsec": 10}}, {"ts": 3600, "p": {"CAPI": 150, "crowdsec": 20}}]
        delta, window_h, new = col.drops_24h(hist, now=7200, current={"CAPI": 200, "crowdsec": 25})
        self.assertEqual(delta, {"CAPI": 100, "crowdsec": 15})
        self.assertEqual(window_h, 2.0)
        self.assertEqual(len(new), 3)

    def test_samples_older_than_24h_are_discarded(self):
        hist = [{"ts": 0, "p": {"CAPI": 100}}, {"ts": 90000, "p": {"CAPI": 300}}]
        delta, window_h, new = col.drops_24h(hist, now=93600, current={"CAPI": 350})
        self.assertEqual(delta, {"CAPI": 50})
        self.assertEqual(window_h, 1.0)
        self.assertEqual([h["ts"] for h in new], [90000, 93600])

    def test_counter_reset_restarts_the_history(self):
        delta, window_h, new = col.drops_24h([{"ts": 0, "p": {"CAPI": 500}}], now=600, current={"CAPI": 20})
        self.assertEqual(delta, {"CAPI": 20})
        self.assertIsNone(window_h)
        self.assertEqual(len(new), 1)

    def test_reset_is_detected_against_the_latest_sample_not_the_oldest(self):
        # revisão de 16/10: base 100, última 50000, bouncer reiniciou e o contador voltou para 3000
        hist = [{"ts": 0, "p": {"CAPI": 100}}, {"ts": 3600, "p": {"CAPI": 50000}}]
        delta, window_h, new = col.drops_24h(hist, now=7200, current={"CAPI": 3000})
        self.assertEqual(delta, {"CAPI": 3000})
        self.assertIsNone(window_h)
        self.assertEqual(len(new), 1)

    def test_corrupt_history_is_ignored(self):
        for bad in ({"x": 1}, "lixo", [1, 2], [{"ts": "x", "p": {}}], [{"ts": 1}], None):
            self.assertEqual(col.clean_history(bad), [], bad)
        ok = [{"ts": 1.0, "p": {"CAPI": 3}}]
        self.assertEqual(col.clean_history(ok), ok)

    def test_new_origin_counts_from_zero(self):
        delta, _, _ = col.drops_24h([{"ts": 0, "p": {"CAPI": 1}}], now=60, current={"CAPI": 1, "cscli-import": 7})
        self.assertEqual(delta, {"CAPI": 0, "cscli-import": 7})


class SafeBlock(unittest.TestCase):
    def test_a_failing_block_does_not_kill_the_stats(self):
        def boom():
            raise TimeoutError("nft travou")
        self.assertEqual(col.safe_block(boom), {"ok": False, "error": "TimeoutError"})
        self.assertEqual(col.safe_block(lambda: {"ok": True}), {"ok": True})


if __name__ == "__main__":
    unittest.main()
