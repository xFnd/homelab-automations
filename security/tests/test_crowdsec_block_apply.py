"""Testes do crowdsec-block-apply (VPS1): validação, proteção (allowlists/hosts próprios/dependências críticas),
deduplicação, tetos com recusa total e trava. Os IPs "importáveis" daqui são públicos e neutros (não são de ninguém
do homelab); resolvedores DNS e Cloudflare viraram dependências protegidas (revisão de 16/10)."""
import datetime as dt, os, tempfile, unittest

from _load import load

apply = load("crowdsec_block_apply", "preventive-block", "vps1", "crowdsec-block-apply")
UTC = dt.timezone.utc
A, B, C = "45.130.10.20", "91.200.30.40", "77.240.5.6"  # IPs públicos neutros para os testes


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


def active_alerts(*ips):
    return [{"decisions": [{"value": ip, "scenario": apply.REASON, "duration": "40h"} for ip in ips]}]


class ParseCandidates(unittest.TestCase):
    def test_accepts_public_ipv4_and_ipv6_and_counts_duplicates(self):
        r = apply.parse_candidates(f"{A}\n2a01:4f8:1:2::3\n{A}\n", cap=10)
        self.assertEqual(r["valid"], [A, "2a01:4f8:1:2::3"])
        self.assertEqual(r["duplicates"], 1)

    def test_rejects_private_reserved_and_garbage(self):
        r = apply.parse_candidates("10.0.0.1\n192.168.50.31\n127.0.0.1\n203.0.113.5\nnao-e-ip\n1.2.3.4/24\n; rm -rf /\n", cap=10)
        self.assertEqual(r["valid"], [])
        self.assertEqual(r["not_global"], 4)
        self.assertEqual(r["invalid"], 3)

    def test_ignores_blank_lines_and_surrounding_spaces(self):
        r = apply.parse_candidates(f"\n  {A}  \n\n", cap=10)
        self.assertEqual(r["valid"], [A])
        self.assertEqual(r["received"], 1)

    def test_cap_counts_what_is_over(self):
        r = apply.parse_candidates("\n".join(f"45.130.10.{i}" for i in range(1, 21)), cap=5)
        self.assertEqual(len(r["valid"]), 5)
        self.assertEqual(r["over_cap"], 15)

    def test_ipv6_is_canonicalized(self):
        r = apply.parse_candidates("2a01:4f8:1:2:0:0:0:3\n", cap=10)
        self.assertEqual(r["valid"], ["2a01:4f8:1:2::3"])

    def test_ipv4_mapped_ipv6_becomes_ipv4(self):
        r = apply.parse_candidates(f"::ffff:{A}\n", cap=10)
        self.assertEqual(r["valid"], [A])

    def test_ipv6_with_zone_is_invalid(self):
        r = apply.parse_candidates("2606:4700::1111%a\n", cap=10)
        self.assertEqual((r["valid"], r["invalid"]), ([], 1))


class Protection(unittest.TestCase):
    def test_allowlist_matches_exact_ip_and_cidr(self):
        nets = apply.networks(["198.51.100.7", "160.79.104.0/21"])
        keep, protected = apply.split_protected(["198.51.100.7", "160.79.106.163", A], nets)
        self.assertEqual(keep, [A])
        self.assertEqual(protected, 2)

    def test_own_vps_ips_are_never_blocked_even_without_allowlist(self):
        keep, protected = apply.split_protected(["203.0.113.10", "203.0.113.20", A], apply.NEVER)
        self.assertEqual(keep, [A])
        self.assertEqual(protected, 2)

    def test_critical_dependencies_are_never_blocked(self):
        # Discord e Let's Encrypt atrás da Cloudflare, DNS público usado pelo Gatus
        crit = ["162.159.135.232", "172.65.32.248", "1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"]
        keep, protected = apply.split_protected(crit + [A], apply.NEVER)
        self.assertEqual(keep, [A])
        self.assertEqual(protected, len(crit))

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
        alerts = [{"decisions": [{"value": A, "scenario": apply.REASON, "duration": "40h"},
                                 {"value": B, "scenario": "outro-motivo", "duration": "40h"}]},
                  {"decisions": None}]
        self.assertEqual(apply.active_values(alerts), {A})

    def test_expired_or_deleted_decisions_do_not_count(self):
        alerts = [{"decisions": [{"value": A, "scenario": apply.REASON, "duration": "-3m12s"},
                                 {"value": B, "scenario": apply.REASON, "duration": "47h59m"},
                                 {"value": C, "scenario": apply.REASON, "duration": "0s"}]}]  # recém-apagada (visto em 16/10)
        self.assertEqual(apply.active_values(alerts), {B})


class Plan(unittest.TestCase):
    def test_skips_already_active(self):
        p = apply.plan([A, B, C], active={A}, max_active=10)
        self.assertEqual(p["to_import"], [B, C])
        self.assertEqual(p["already_active"], 1)
        self.assertEqual(p["over_max_active"], 0)

    def test_reports_how_much_would_pass_the_active_cap(self):
        p = apply.plan([A, B, C], active={A}, max_active=2)
        self.assertEqual(p["over_max_active"], 1)


class ImportedCount(unittest.TestCase):
    def test_reads_the_number_from_cscli_output(self):
        self.assertEqual(apply.imported_count("Parsing values\nImported 37 decisions"), 37)
        self.assertIsNone(apply.imported_count("erro qualquer"))


class HandleImport(unittest.TestCase):
    def test_full_flow_imports_only_new_unprotected_ips(self):
        deps = FakeDeps(allowlists=[{"name": "casa", "items": [{"value": "198.51.100.7", "expiration": "0001-01-01T00:00:00Z"}]}],
                        active=active_alerts(B))
        r = apply.handle_import(f"{B}\n198.51.100.7\n{A}\n10.0.0.1\n203.0.113.10\n".encode(), deps)
        self.assertTrue(r["ok"])
        self.assertEqual(deps.imported, [A])
        self.assertEqual((r["imported"], r["already_active"]), (1, 1))
        # casa e VPS1 ficam fora por allowlist/NEVER (IPs reais) ou por não serem globais (na cópia pública, sanitizada
        # para faixas de documentação); 10.0.0.1 é privado. O que importa: nenhum dos três é importado.
        self.assertEqual(r["protected"] + r["not_global"], 3)

    def test_ipv4_mapped_form_of_own_vps_is_never_imported(self):
        deps = FakeDeps()
        r = apply.handle_import(b"::ffff:203.0.113.10\n::ffff:203.0.113.20\n", deps)
        self.assertTrue(r["ok"])
        self.assertIsNone(deps.imported)

    def test_nothing_new_does_not_call_cscli(self):
        deps = FakeDeps(active=active_alerts(A))
        r = apply.handle_import(f"{A}\n".encode(), deps)
        self.assertTrue(r["ok"])
        self.assertIsNone(deps.imported)
        self.assertEqual(r["imported"], 0)

    def test_list_over_the_per_call_cap_is_refused_whole(self):
        deps = FakeDeps()
        many = "\n".join(f"45.{i // 250}.{i % 250}.7" for i in range(apply.MAX_PER_CALL + 1))
        r = apply.handle_import(many.encode(), deps)
        self.assertFalse(r["ok"])
        self.assertIn("teto", r["error"])
        self.assertIsNone(deps.imported)

    def test_passing_the_active_cap_is_refused_whole(self):
        deps = FakeDeps(active=active_alerts(*[f"45.9.{i // 250}.{i % 250}" for i in range(apply.MAX_ACTIVE - 1)]))
        r = apply.handle_import(f"{A}\n{B}\n".encode(), deps)
        self.assertFalse(r["ok"])
        self.assertIn("teto", r["error"])
        self.assertIsNone(deps.imported)

    def test_input_bigger_than_limit_is_refused_whole(self):
        deps = FakeDeps()
        r = apply.handle_import(f"{A}\n".encode() * 6000, deps)  # 78 KB > 64 KiB
        self.assertFalse(r["ok"])
        self.assertIn("grande", r["error"])
        self.assertIsNone(deps.imported)

    def test_kill_switch_refuses_everything(self):
        deps = FakeDeps(disabled=True)
        r = apply.handle_import(f"{A}\n".encode(), deps)
        self.assertFalse(r["ok"])
        self.assertTrue(r["disabled"])
        self.assertIsNone(deps.imported)

    def test_cscli_output_without_count_is_an_error(self):
        deps = FakeDeps(import_out="level=fatal msg=algo deu errado")
        r = apply.handle_import(f"{A}\n".encode(), deps)
        self.assertFalse(r["ok"])


@unittest.skipIf(os.name == "nt", "flock só existe no Linux (roda no CT106/VPS1)")
class Lock(unittest.TestCase):
    def test_second_holder_is_refused(self):
        path = os.path.join(tempfile.mkdtemp(), "x.lock")
        first = apply.acquire_lock(path)
        self.assertIsNotNone(first)
        self.assertIsNone(apply.acquire_lock(path))
        first.close()
        self.assertIsNotNone(apply.acquire_lock(path))


if __name__ == "__main__":
    unittest.main()
