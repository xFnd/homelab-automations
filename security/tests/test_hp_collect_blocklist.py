"""Testes da lista de bloqueio preventivo gerada pelo coletor da isca (VPS2, hp-collect.py)."""
import unittest

from _load import load

hp = load("hp_collect", "honeypot", "hp-collect.py")


def ev(eventid, ip, ts):
    return {"eventid": eventid, "src_ip": ip, "timestamp": ts}


class NoteLogin(unittest.TestCase):
    def test_only_login_attempts_count_connect_alone_does_not(self):
        seen = {}
        for e in (ev("cowrie.session.connect", "8.8.8.8", "2026-10-16T01:00:00Z"),
                  ev("cowrie.login.failed", "1.1.1.1", "2026-10-16T01:00:00Z"),
                  ev("cowrie.login.success", "9.9.9.9", "2026-10-16T02:00:00Z"),
                  ev("cowrie.command.input", "4.4.4.4", "2026-10-16T03:00:00Z")):
            hp.note_login(seen, e)
        self.assertEqual(sorted(seen), ["1.1.1.1", "9.9.9.9"])

    def test_keeps_the_most_recent_timestamp(self):
        seen = {}
        hp.note_login(seen, ev("cowrie.login.failed", "1.1.1.1", "2026-10-16T05:00:00Z"))
        hp.note_login(seen, ev("cowrie.login.failed", "1.1.1.1", "2026-10-16T01:00:00Z"))
        self.assertEqual(seen["1.1.1.1"], "2026-10-16T05:00:00Z")


class BuildBlocklist(unittest.TestCase):
    def test_most_recent_first_without_private_or_garbage(self):
        seen = {"1.1.1.1": "2026-10-16T01:00:00Z", "9.9.9.9": "2026-10-16T05:00:00Z",
                "10.0.0.5": "2026-10-16T06:00:00Z", "lixo": "2026-10-16T07:00:00Z"}
        bl = hp.build_blocklist(seen, cap=10, generated_at="2026-10-16T08:00:00Z")
        self.assertEqual(bl["ips"], ["9.9.9.9", "1.1.1.1"])
        self.assertEqual(bl["count"], 2)
        self.assertFalse(bl["truncated"])
        self.assertEqual(bl["window"], "24h")
        self.assertEqual(bl["generated_at"], "2026-10-16T08:00:00Z")

    def test_cap_keeps_the_newest_and_flags_truncation(self):
        seen = {f"1.1.1.{i}": f"2026-10-16T{i:02d}:00:00Z" for i in range(1, 11)}
        bl = hp.build_blocklist(seen, cap=3, generated_at="x")
        self.assertEqual(bl["ips"], ["1.1.1.10", "1.1.1.9", "1.1.1.8"])
        self.assertTrue(bl["truncated"])


if __name__ == "__main__":
    unittest.main()
