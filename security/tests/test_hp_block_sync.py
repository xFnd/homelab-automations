"""Testes do hp-block-sync (CT 106): o que vai da isca (VPS2) para o bloqueio preventivo do gateway (VPS1)."""
import datetime as dt, unittest

from _load import load

sync = load("hp_block_sync", "preventive-block", "ct106", "hp-block-sync.py")
NOW = dt.datetime(2026, 10, 16, 8, 0, tzinfo=dt.timezone.utc)


def env(ips, client="198.51.100.7", generated_at="2026-10-16T07:50:00Z"):
    return {"client": client, "data": {"generated_at": generated_at, "window": "24h", "ips": ips}}


class SelectIps(unittest.TestCase):
    def test_excludes_home_ip_own_vps_and_non_global(self):
        ips = sync.select_ips(env(["8.8.8.8", "198.51.100.7", "203.0.113.10", "203.0.113.20", "10.1.1.1", "x"]), NOW)
        self.assertEqual(ips, ["8.8.8.8"])

    def test_dedupes_and_caps(self):
        ips = sync.select_ips(env(["1.1.1.1", "1.1.1.1"] + [f"9.9.9.{i}" for i in range(1, 50)]), NOW, cap=5)
        self.assertEqual(ips[0], "1.1.1.1")
        self.assertEqual(len(ips), 5)

    def test_stale_list_is_refused(self):
        with self.assertRaises(ValueError):
            sync.select_ips(env(["8.8.8.8"], generated_at="2026-10-16T05:00:00Z"), NOW)

    def test_malformed_envelope_is_refused(self):
        for bad in ({}, {"client": "1.1.1.1"}, {"client": "1.1.1.1", "data": {"ips": "8.8.8.8"}}, {"error": "sem dados"}):
            with self.assertRaises(ValueError):
                sync.select_ips(bad, NOW)


class ParseResult(unittest.TestCase):
    def test_reads_the_gateway_summary(self):
        r = sync.parse_result('{"ok": true, "imported": 3, "already_active": 90, "protected": 1, "active_after": 93}')
        self.assertEqual(r["imported"], 3)

    def test_error_from_gateway_raises(self):
        for out in ('{"ok": false, "error": "desligado", "disabled": true}', '{"error":"comando nao permitido"}', 'não é json'):
            with self.assertRaises(RuntimeError):
                sync.parse_result(out)


if __name__ == "__main__":
    unittest.main()
