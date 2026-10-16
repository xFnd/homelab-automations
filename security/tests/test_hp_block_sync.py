"""Testes do hp-block-sync (CT 106): o que vai da isca (VPS2) para o bloqueio preventivo do gateway (VPS1).
Revisão de 16/10: a isca é não confiável por definição, então o IP de casa vem da VPS1 (relay autenticado), e volume
anormal não é enviado (aviso imediato no Discord)."""
import datetime as dt, unittest

from _load import load

sync = load("hp_block_sync", "preventive-block", "ct106", "hp-block-sync.py")
NOW = dt.datetime(2026, 10, 16, 8, 0, tzinfo=dt.timezone.utc)
HOME = "177.10.20.30"  # IP público neutro (o teste não depende do IP real de casa)


def env(ips, client="198.51.100.250", generated_at="2026-10-16T07:50:00Z"):
    return {"client": client, "data": {"generated_at": generated_at, "window": "24h", "ips": ips}}


class SelectIps(unittest.TestCase):
    def test_excludes_home_ip_from_vps1_own_vps_and_non_global(self):
        ips = sync.select_ips(env(["45.130.10.20", HOME, "203.0.113.10", "203.0.113.20", "10.1.1.1", "x"]), NOW, home=HOME)
        self.assertEqual(ips, ["45.130.10.20"])

    def test_home_ip_is_excluded_even_if_the_bait_lies_about_client(self):
        ips = sync.select_ips(env(["45.130.10.20", HOME], client="203.0.113.77"), NOW, home=HOME)
        self.assertEqual(ips, ["45.130.10.20"])

    def test_ipv4_mapped_home_is_excluded_and_zones_are_dropped(self):
        ips = sync.select_ips(env([f"::ffff:{HOME}", "2606:4700::1111%a", "45.130.10.20"]), NOW, home=HOME)
        self.assertEqual(ips, ["45.130.10.20"])

    def test_dedupes(self):
        ips = sync.select_ips(env(["45.130.10.20", "45.130.10.20", "91.200.30.40"]), NOW, home=HOME)
        self.assertEqual(ips, ["45.130.10.20", "91.200.30.40"])

    def test_stale_list_is_refused(self):
        with self.assertRaises(ValueError):
            sync.select_ips(env(["45.130.10.20"], generated_at="2026-10-16T05:00:00Z"), NOW, home=HOME)

    def test_malformed_envelope_is_refused(self):
        for bad in ({}, {"client": "1.1.1.1"}, {"client": "1.1.1.1", "data": {"ips": "45.130.10.20"}}, {"error": "sem dados"}):
            with self.assertRaises(ValueError):
                sync.select_ips(bad, NOW, home=HOME)

    def test_missing_home_ip_is_refused(self):
        with self.assertRaises(ValueError):
            sync.select_ips(env(["45.130.10.20"]), NOW, home=None)


class Volume(unittest.TestCase):
    def test_normal_volume_passes(self):
        sync.check_volume(["45.130.10.20"] * 150)

    def test_abnormal_volume_is_refused(self):
        with self.assertRaises(sync.Anomaly):
            sync.check_volume(["45.130.10.20"] * (sync.MAX_SEND + 1))


class HomeIp(unittest.TestCase):
    def test_reads_client_from_vps1_ping(self):
        self.assertEqual(sync.home_from_ping('{"client":"177.10.20.30","data":{"pong":"x"}}'), HOME)

    def test_rejects_non_public_or_garbage(self):
        for out in ('{"client":"10.0.0.1"}', '{"error":"x"}', "não é json"):
            with self.assertRaises(ValueError):
                sync.home_from_ping(out)


class ParseResult(unittest.TestCase):
    def test_reads_the_gateway_summary(self):
        r = sync.parse_result('{"ok": true, "imported": 3, "already_active": 90, "protected": 1, "active_after": 93}')
        self.assertEqual(r["imported"], 3)

    def test_error_from_gateway_raises(self):
        for out in ('{"ok": false, "error": "desligado", "disabled": true}', '{"error":"comando nao permitido"}', 'não é json'):
            with self.assertRaises(RuntimeError):
                sync.parse_result(out)

    def test_cap_refusal_is_an_anomaly(self):
        with self.assertRaises(sync.Anomaly):
            sync.parse_result('{"ok": false, "error": "acima do teto de 400 IPs por chamada: nada importado"}')


if __name__ == "__main__":
    unittest.main()
