"""Testes do coletor da VPS1 (collect.py) para o bloqueio preventivo: alertas de import fora das estatísticas de
detecção, resumo do preventivo e logins da chave de bloqueio fora da lista de logins humanos."""
import datetime as dt, unittest

from _load import load

col = load("collect", "vps1-relay", "collect.py")
REASON = "fnd/isca-vps2-login"


def imp(id_, n, created, reason=REASON):
    return {"id": id_, "scenario": f"import stdin: {n} IPs", "created_at": created, "source": {"scope": "", "value": ""},
            "decisions": [{"type": "ban", "origin": "cscli-import", "scenario": reason, "value": f"9.9.9.{i}"} for i in range(n)]}


def det(id_, ip):
    return {"id": id_, "scenario": "crowdsecurity/ssh-bf", "created_at": "2026-10-16T05:00:00Z",
            "source": {"scope": "Ip", "value": ip, "ip": ip}, "decisions": [{"type": "ban", "origin": "crowdsec"}]}


class SplitAlerts(unittest.TestCase):
    def test_import_alerts_are_separated_from_detections(self):
        detections, imports = col.split_alerts([det(1, "1.1.1.1"), imp(2, 3, "2026-10-16T06:00:00Z"), det(3, "2.2.2.2")])
        self.assertEqual([a["id"] for a in detections], [1, 3])
        self.assertEqual([a["id"] for a in imports], [2])


class PreventiveStats(unittest.TestCase):
    def test_counts_only_our_reason_and_reports_last_import(self):
        p = col.preventive_stats([imp(2, 3, "2026-10-16T06:00:00Z"), imp(5, 2, "2026-10-16T07:00:00Z"),
                                  imp(6, 4, "2026-10-16T07:30:00Z", reason="outro")], REASON)
        self.assertEqual(p["imported_24h"], 5)
        self.assertEqual(p["imports_24h"], 2)
        self.assertEqual(p["last_import_at"], "2026-10-16T07:00:00Z")
        self.assertEqual(p["reason"], REASON)

    def test_no_imports(self):
        p = col.preventive_stats([], REASON)
        self.assertEqual((p["imported_24h"], p["imports_24h"], p["last_import_at"]), (0, 0, None))


class ParseSsh(unittest.TestCase):
    LOG = "\n".join([
        "Accepted publickey for ubuntu from 198.51.100.7 port 1 ssh2: ED25519 SHA256:x",
        "Accepted publickey for crowdsec-relay from 198.51.100.7 port 2 ssh2: ED25519 SHA256:y",
        "Accepted publickey for crowdsec-block from 198.51.100.7 port 3 ssh2: ED25519 SHA256:z",
        "Accepted publickey for crowdsec-block from 198.51.100.7 port 4 ssh2: ED25519 SHA256:z",
        # o parser legado conta a linha "Connection closed by invalid user" (uma por tentativa); a "Invalid user … from"
        # nunca casa no regex original (anotado no ledger como menor)
        "Connection closed by invalid user admin 45.1.1.1 port 5 [preauth]",
    ])

    def test_automation_keys_do_not_show_up_as_human_logins(self):
        s = col.parse_ssh(self.LOG)
        self.assertEqual([a["user"] for a in s["accepted"]], ["ubuntu"])
        self.assertEqual(s["relay_logins"], 1)
        self.assertEqual(s["block_logins"], 2)
        self.assertEqual(s["failure_lines"], 1)


if __name__ == "__main__":
    unittest.main()
