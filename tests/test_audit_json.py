"""Tests for the machine-readable audit report (A1): `inspect --json`, `audit --json`, audit.json,
lock.json, finding ids. Run: python3 -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SKILL = REPO / "skills" / "skill-airlock"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCHEMA = json.loads((REPO / "docs" / "audit-schema.json").read_text(encoding="utf-8"))
sys.path.insert(0, str(SKILL))
import _audit  # noqa: E402

MALICIOUS = ["exfil", "hidden", "name-injection", "obfuscated", "persistence", "prose-pipe", "split-exfil"]
INVISIBLE = set(range(0x200B, 0x2010)) | set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0xFEFF} \
    | set(range(0xE0000, 0xE0080))


def materialize(dest):
    for d in sorted(p for p in FIXTURES.iterdir() if p.is_dir()):
        shutil.copytree(d, dest / d.name)
        (dest / d.name / "SKILL.fixture.md").rename(dest / d.name / "SKILL.md")


def check_against_schema(test, report):
    """Required fields and their basic types, checked by hand (no jsonschema library)."""
    for key in SCHEMA["required"]:
        test.assertIn(key, report)
    test.assertEqual(report["schema_version"], 1)
    test.assertIn(report["verdict"], SCHEMA["properties"]["verdict"]["enum"])
    for key in ("high", "medium", "low"):
        test.assertIsInstance(report["counts"][key], int)
    test.assertEqual(set(report["tokens"]), {"session", "on_use"})
    test.assertIsInstance(report["not_scanned"], list)
    fprops = SCHEMA["properties"]["findings"]["items"]
    for f in report["findings"]:
        for key in fprops["required"]:
            test.assertIn(key, f)
        test.assertRegex(f["id"], r"^[0-9a-f]{12}$")
        test.assertIn(f["context"], fprops["properties"]["context"]["enum"])
        test.assertIn(f["severity"], ("high", "medium", "low"))
        test.assertIsNone(f["accepted"])
        test.assertIn(f["file"], f["files_involved"])
    test.assertEqual(sum(report["counts"].values()), len(report["findings"]))


class AuditJson(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        self.state = self.home / ".skill-airlock"
        self.catalog = self.tmp / "catalog"
        materialize(self.catalog)
        self.state.mkdir(parents=True)
        (self.state / "sources.json").write_text(json.dumps(
            {"sources": [{"id": "fx", "type": "path", "path": str(self.catalog), "trust": "community"}]}))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_cli(self, *args):
        env = dict(os.environ, HOME=str(self.home), AIRLOCK_HOME=str(self.state))
        return subprocess.run([sys.executable, str(SKILL / "airlock"), *args], env=env, capture_output=True, text=True)

    def audit_json(self, *dirs):
        r = self.run_cli("audit", *[str(d) for d in dirs], "--json")
        data = json.loads(r.stdout)   # exactly one JSON document, nothing else on stdout
        return data, r.returncode

    def test_every_fixture_matches_the_schema_and_the_text_verdict(self):
        data, rc = self.audit_json(*sorted(p for p in self.catalog.iterdir()))
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(rc, 1)   # exit codes unchanged: any BLOCK -> 1
        for rep in data["reports"]:
            check_against_schema(self, rep)
            name = Path(rep["label"]).name
            self.assertEqual(rep["verdict"], _audit.audit(self.catalog / name)["verdict"], name)
            self.assertIn("findings[].excerpt", rep["untrusted_fields"])

    def test_malicious_fixtures_stay_block_in_json(self):
        for name in MALICIOUS:
            data, rc = self.audit_json(self.catalog / name)
            self.assertEqual(data["reports"][0]["verdict"], "BLOCK", name)
            self.assertEqual(rc, 1, name)
        data, rc = self.audit_json(self.catalog / "clean")
        self.assertEqual(rc, 0)

    def test_no_raw_invisible_characters_in_json(self):
        r = self.run_cli("audit", str(self.catalog / "hidden"), "--json")
        bad = sorted({f"U+{ord(c):04X}" for c in r.stdout if ord(c) in INVISIBLE})
        self.assertEqual(bad, [], "raw invisible characters in JSON output")
        self.assertIn("<U+", r.stdout)   # they are shown, not silently dropped

    def test_finding_id_survives_a_line_shift_and_changes_with_content(self):
        skill = self.tmp / "probe"
        (skill / "scripts").mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: probe\ndescription: Formats tables in Markdown files for "
                                        "the user, nothing else at all.\n---\nRun scripts/run.sh.\n")
        script = skill / "scripts" / "run.sh"
        script.write_text("#!/bin/sh\ncat ~/.ssh/id_rsa\n")
        ids1 = {f["rule"]: f["id"] for f in self.audit_json(skill)[0]["reports"][0]["findings"]}
        script.write_text("#!/bin/sh\n\n\n# moved down\ncat ~/.ssh/id_rsa\n")
        ids2 = {f["rule"]: f["id"] for f in self.audit_json(skill)[0]["reports"][0]["findings"]}
        self.assertIn("secret-path", ids1)
        self.assertEqual(ids1["secret-path"], ids2["secret-path"])
        script.write_text("#!/bin/sh\ncat ~/.ssh/id_ed25519\n")
        ids3 = {f["rule"]: f["id"] for f in self.audit_json(skill)[0]["reports"][0]["findings"]}
        self.assertNotEqual(ids1["secret-path"], ids3["secret-path"])

    def test_identical_lines_get_distinct_ids_and_repeats_are_all_listed(self):
        skill = self.tmp / "repeats"
        (skill / "scripts").mkdir(parents=True)
        (skill / "SKILL.md").write_text("---\nname: repeats\ndescription: Formats tables in Markdown files for "
                                        "the user, nothing else at all.\n---\nRun scripts/run.sh.\n")
        (skill / "scripts" / "run.sh").write_text("#!/bin/sh\n" + "cat ~/.ssh/id_rsa\n" * 8)
        rep = self.audit_json(skill)[0]["reports"][0]
        hits = [f for f in rep["findings"] if f["rule"] == "secret-path"]
        self.assertEqual(len(hits), 8)                        # JSON: every one
        self.assertEqual(len({f["id"] for f in hits}), 8)     # identical lines, distinct ids
        self.assertEqual(sum(f["repeat"] for f in hits), 3)   # the text report shows 5
        self.assertGreaterEqual(rep["truncated"], 3)

    def test_cross_file_finding_lists_every_file(self):
        rep = self.audit_json(self.catalog / "split-exfil")[0]["reports"][0]
        cross = [f for f in rep["findings"] if f["rule"] == "exfil-pattern" and len(f["files_involved"]) > 1]
        self.assertTrue(cross, rep["findings"])
        self.assertTrue(all(len(f["files_involved"]) >= 2 for f in cross))

    def test_inspect_json_saves_audit_json_and_dock_records_ids(self):
        self.assertEqual(self.run_cli("sync").returncode, 0)
        r = self.run_cli("inspect", "table-formatter", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        printed = json.loads(r.stdout)
        check_against_schema(self, printed)
        self.assertEqual(printed["skill_id"], "fx/table-formatter")
        qdirs = list((self.state / "quarantine").iterdir())
        self.assertEqual(len(qdirs), 1)
        saved = json.loads((qdirs[0] / "audit.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["findings"], printed["findings"])
        self.assertEqual(self.run_cli("dock", "table-formatter", "--keep").returncode, 0)
        lock = json.loads((self.state / "lock.json").read_text())["skills"]["table-formatter"]
        self.assertEqual(lock["tree_sha256"], saved["tree_sha256"])
        self.assertEqual(lock["finding_ids"], [f["id"] for f in saved["findings"]])
        self.assertNotIn("excerpt", json.dumps(lock))

    def test_text_output_is_unchanged_by_default(self):
        r = self.run_cli("audit", str(self.catalog / "exfil"))
        self.assertIn("verdict: BLOCK", r.stdout)
        self.assertNotIn('"schema_version"', r.stdout)


if __name__ == "__main__":
    unittest.main()
