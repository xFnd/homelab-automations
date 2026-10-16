"""Testes do crowdsec-block-apply (VPS1): validação, proteção (allowlists/hosts próprios), deduplicação e tetos."""
import datetime as dt, unittest

from _load import load

apply = load("crowdsec_block_apply", "preventive-block", "vps1", "crowdsec-block-apply")
UTC = dt.timezone.utc


class FakeDeps:
    """Substitui as chamadas ao cscli e ao disco."""
    def __init__(self, allowlists=None, active=None, disabled=False, import_out="Parsing values\nImported {n} decisions"):
        self._allow, self._active, self._disabled, self._out = allowlists or [], active or [], disabled, import_out
        self.imported = None

    def allowlists(self):
        return self._allow

    def active(self):
        return self._active

    def disabled(self):
        return self._disabled

    def do_import(self, ips):
        self.imported = list(ips)
        return self._out.format(n=len(ips))


class ParseCandidates(unittest.TestCase):
    def test_accepts_public_ipv4_and_ipv6_and_counts_duplicates(self):
        r = apply.parse_candidates("8.8.8.8\n2001:4860:4860::8888\n8.8.8.8\n", cap=10)
        self.assertEqual(r["valid"], ["8.8.8.8", "2001:4860:4860::8888"])
        self.assertEqual(r["duplicates"], 1)

    def test_rejects_private_reserved_and_garbage(self):
        r = apply.parse_candidates("10.0.0.1\n192.168.0.31\n127.0.0.1\n203.0.113.5\nnao-e-ip\n1.2.3.4/24\n; rm -rf /\n", cap=10)
        self.assertEqual(r["valid"], [])
        self.assertEqual(r["not_global"], 4)
        self.assertEqual(r["invalid"], 3)

    def test_ignores_blank_lines_and_surrounding_spaces(self):
        r = apply.parse_candidates("\n  1.1.1.1  \n\n", cap=10)
        self.assertEqual(r["valid"], ["1.1.1.1"])
        self.assertEqual(r["received"], 1)

    def test_cap_limits_the_valid_list(self):
        r = apply.parse_candidates("\n".join(f"1.1.1.{i}" for i in range(1, 21)), cap=5)
        self.assertEqual(len(r["valid"]), 5)
        self.assertEqual(r["over_cap"], 15)

    def test_ipv6_is_canonicalized(self):
        r = apply.parse_candidates("2001:4860:4860:0:0:0:0:8888\n", cap=10)
        self.assertEqual(r["valid"], ["2001:4860:4860::8888"])


class Protection(unittest.TestCase):
    def test_allowlist_matches_exact_ip_and_cidr(self):
        nets = apply.networks(["198.51.100.7", "160.79.104.0/21"])
        keep, protected = apply.split_protected(["198.51.100.7", "160.79.106.163", "8.8.8.8"], nets)
        self.assertEqual(keep, ["8.8.8.8"])
        self.assertEqual(protected, 2)

    def test_own_vps_ips_are_never_blocked_even_without_allowlist(self):
        keep, protected = apply.split_protected(["203.0.113.10", "203.0.113.20", "9.9.9.9"], apply.NEVER)
        self.assertEqual(keep, ["9.9.9.9"])
        self.assertEqual(protected, 2)

    def test_invalid_allowlist_values_are_ignored(self):
        self.assertEqual(len(apply.networks(["lixo", "1.2.3.4"])), 1)


class AllowlistValues(unittest.TestCase):
    NOW = dt.datetime(2026, 10, 16, tzinfo=UTC)

    def test_keeps_never_expiring_and_future_items_drops_expired(self):
        data = [{"name": "casa", "items": [{"value": "198.51.100.7", "expiration": "0001-01-01T00:00:00.000Z"}]},
                {"name": "tmp", "items": [{"value": "5.5.5.5", "expiration": "2000-01-01T00:00:00Z"},
                                          {"value": "6.6.6.0/24", "expiration": "2999-01-01T00:00:00.000Z"}]}]
        self.assertEqual(sorted(apply.allowlist_values(data, self.NOW)), ["198.51.100.7", "6.6.6.0/24"])

    def test_null_cscli_output_means_no_allowlist(self):
        self.assertEqual(apply.allowlist_values(None, self.NOW), [])


class ActiveValues(unittest.TestCase):
    def test_only_decisions_with_our_reason_count(self):
        alerts = [{"decisions": [{"value": "1.1.1.1", "scenario": apply.REASON, "origin": "cscli-import"},
                                 {"value": "2.2.2.2", "scenario": "outro-motivo", "origin": "cscli-import"}]},
                  {"decisions": None}]
        self.assertEqual(apply.active_values(alerts), {"1.1.1.1"})


class Plan(unittest.TestCase):
    def test_skips_already_active_and_respects_max_active(self):
        p = apply.plan(["1.1.1.1", "2.2.2.2", "3.3.3.3"], active={"1.1.1.1"}, max_active=2)
        self.assertEqual(p["to_import"], ["2.2.2.2"])
        self.assertEqual(p["already_active"], 1)
        self.assertEqual(p["over_max_active"], 1)


class ImportedCount(unittest.TestCase):
    def test_reads_the_number_from_cscli_output(self):
        self.assertEqual(apply.imported_count("Parsing values\nImported 37 decisions"), 37)
        self.assertIsNone(apply.imported_count("erro qualquer"))


class HandleImport(unittest.TestCase):
    def test_full_flow_imports_only_new_unprotected_ips(self):
        deps = FakeDeps(allowlists=[{"name": "casa", "items": [{"value": "198.51.100.7", "expiration": "0001-01-01T00:00:00Z"}]}],
                        active=[{"decisions": [{"value": "1.1.1.1", "scenario": apply.REASON}]}])
        r = apply.handle_import(b"1.1.1.1\n198.51.100.7\n8.8.8.8\n10.0.0.1\n203.0.113.10\n", deps)
        self.assertTrue(r["ok"])
        self.assertEqual(deps.imported, ["8.8.8.8"])
        self.assertEqual((r["imported"], r["already_active"]), (1, 1))
        # casa e VPS1 ficam fora por allowlist/NEVER (IPs reais) ou por não serem globais (na cópia pública, sanitizada
        # para faixas de documentação); 10.0.0.1 é privado. O que importa: nenhum dos três é importado.
        self.assertEqual(r["protected"] + r["not_global"], 3)

    def test_nothing_new_does_not_call_cscli(self):
        deps = FakeDeps(active=[{"decisions": [{"value": "8.8.8.8", "scenario": apply.REASON}]}])
        r = apply.handle_import(b"8.8.8.8\n", deps)
        self.assertTrue(r["ok"])
        self.assertIsNone(deps.imported)
        self.assertEqual(r["imported"], 0)

    def test_input_bigger_than_limit_is_refused_whole(self):
        deps = FakeDeps()
        r = apply.handle_import(b"8.8.8.8\n" * 9000, deps)  # > 64 KiB
        self.assertFalse(r["ok"])
        self.assertIn("grande", r["error"])
        self.assertIsNone(deps.imported)

    def test_kill_switch_refuses_everything(self):
        deps = FakeDeps(disabled=True)
        r = apply.handle_import(b"8.8.8.8\n", deps)
        self.assertFalse(r["ok"])
        self.assertTrue(r["disabled"])
        self.assertIsNone(deps.imported)

    def test_cscli_output_without_count_is_an_error(self):
        deps = FakeDeps(import_out="level=fatal msg=algo deu errado")
        r = apply.handle_import(b"8.8.8.8\n", deps)
        self.assertFalse(r["ok"])


if __name__ == "__main__":
    unittest.main()
