"""验证离线审计对合成更换包与组合上线的判断。"""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import audit_data
from audit_data import load_evidence, normalize
from audit_engine import audit


ROOT = Path(__file__).with_name("records")


def _codes(result, target=None):
    return {item["code"] for item in result["findings"]
            if target is None or item["target"] == target}


def _base():
    evidence, _ = load_evidence([ROOT])
    return copy.deepcopy(evidence)


class RealRecordsTests(unittest.TestCase):
    def setUp(self):
        self.evidence, self.origins = load_evidence([ROOT])
        self.result = audit(self.evidence, origins=self.origins)

    def test_real_package_is_blocking(self):
        self.assertTrue(self.result["blocking"])

    def test_combination_scope_not_covered(self):
        bundle = "packages/bundle-2"
        self.assertIn("combination_unsigned", _codes(self.result, bundle))
        analysis = next(b for b in self.result["bundles"] if b["id"] == "bundle-2")
        self.assertFalse(analysis["groups"][0]["available"])
        self.assertEqual(analysis["groups"][0]["roles"], ["app", "migration"])

    def test_single_item_proof_does_not_cover_combination(self):
        self.assertIn("proof_item_absent", _codes(self.result, "packages/bundle-2"))
        self.assertIn("combination_not_covered_by_proof",
                      _codes(self.result, "packages/bundle-2"))

    def test_replacement_bundle_keeps_old_component(self):
        finding = next(item for item in self.result["findings"]
                       if item["code"] == "stale_component")
        self.assertEqual(finding["evidence"]["component"], "mig1")
        self.assertEqual(finding["evidence"]["old_digest"], "combo-1")

    def test_withdrawal_invalidates_old_bundle(self):
        self.assertIn("bundle_revoked", _codes(self.result, "packages/old-bundle"))
        rollback = next(row for row in self.result["rollback"]
                        if row["bundle"] == "old-bundle")
        self.assertFalse(rollback["available"])
        self.assertIn("撤销", rollback["reason"])

    def test_independent_role_remains_usable(self):
        trusted = next(row for row in self.result["trusted"]
                       if row["bundle"] == "bundle-2")
        self.assertEqual(trusted["independent_roles"], ["catalogue"])
        self.assertTrue(trusted["usable"])

    def test_field_partial_reports_completed_pending_and_held(self):
        unit = next(row for row in self.result["units"] if row["id"] == "seen-a")
        self.assertEqual(unit["completed"], ["app"])
        self.assertEqual(unit["awaiting_confirmation"], ["catalogue"])
        self.assertEqual(unit["held"], ["migration"])
        self.assertIn("combination_incomplete", _codes(self.result, "field/seen-a"))

    def test_installed_old_digest_is_flagged(self):
        unit = next(row for row in self.result["units"] if row["id"] == "seen-b")
        self.assertIn("registered_bundle_revoked", unit["blockers"])

    def test_history_exposes_approvals_and_digests(self):
        history = self.result["history"]
        self.assertEqual({row["id"] for row in history["approvals"]},
                         {"release-P", "approval-m"})
        digest = next(row for row in history["digests"] if row["digest"] == "combo-1")
        self.assertEqual(digest["revoked_by"], ["withdraw-1"])


class RuleTests(unittest.TestCase):
    def test_unknown_registry_digest_is_error(self):
        evidence = _base()
        evidence["field"][0]["registered_bundle"] = "combo-x"
        result = audit(evidence)
        self.assertIn("registry_digest_unknown", _codes(result, "field/seen-a"))

    def test_approval_group_mismatch_is_detected(self):
        evidence = _base()
        evidence["field"][0] = {
            "id": "seen-c", "unit": "third-a", "group": "third",
            "registered_bundle": "combo-2", "actual_items": [],
            "state": "partial",
        }
        result = audit(evidence)
        self.assertIn("approval_group_mismatch", _codes(result, "field/seen-c"))

    def test_group_is_not_inferred_when_unmatched(self):
        evidence = _base()
        evidence["field"][0]["unit"] = "unrecognised-unit"
        result = audit(evidence)
        unit = next(row for row in result["units"] if row["id"] == "seen-a")
        self.assertIsNone(unit["group"])
        self.assertIn("unit_group_unverified", _codes(result, "field/seen-a"))

    def test_digest_conflict_between_bundles(self):
        evidence = _base()
        evidence["packages"][0]["digest"] = "combo-1"
        result = audit(evidence)
        self.assertIn("digest_conflict", _codes(result, "packages/bundle-2"))

    def test_signer_issuer_must_match_approval(self):
        evidence = _base()
        evidence["packages"][0]["signed_by"] = {"migration": "vendor"}
        result = audit(evidence)
        self.assertIn("signer_issuer_mismatch", _codes(result, "packages/bundle-2"))

    def test_withdrawal_after_day_keeps_bundle_usable(self):
        evidence = _base()
        evidence["authorities"][2]["day"] = 10
        result = audit(evidence, at=5)
        self.assertNotIn("bundle_revoked", _codes(result, "packages/old-bundle"))

    def test_fields_are_required(self):
        evidence = _base()
        del evidence["packages"][0]["signed_scope"]
        with self.assertRaises(ValueError):
            normalize(evidence)

    def test_must_pair_unknown_role_is_rejected(self):
        evidence = _base()
        evidence["packages"][0]["must_pair"] = ["app", "ghost"]
        with self.assertRaises(ValueError):
            normalize(evidence)


class EvidenceMergeTests(unittest.TestCase):
    def test_second_directory_adds_new_records(self):
        sources = {name: json.loads((ROOT / f"{name}.json").read_text())
                   for name in audit_data.KNOWN_SOURCES}
        with tempfile.TemporaryDirectory() as directory:
            for name, rows in sources.items():
                (Path(directory) / f"{name}.json").write_text(
                    json.dumps(rows, ensure_ascii=False))
            extra = Path(directory) / "extra"
            extra.mkdir()
            (extra / "field.json").write_text(json.dumps([{
                "id": "seen-c", "unit": "second-c", "group": "second",
                "registered_bundle": "combo-2", "actual_items": ["app2"],
                "state": "partial",
            }]))
            evidence, origins = load_evidence([Path(directory), extra])
        self.assertIn("seen-c", [row["id"] for row in evidence["field"]])
        self.assertEqual(origins["field"]["seen-c"], str(extra))

    def test_conflicting_duplicate_across_directories_is_rejected(self):
        sources = {name: json.loads((ROOT / f"{name}.json").read_text())
                   for name in audit_data.KNOWN_SOURCES}
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            for name, rows in sources.items():
                (Path(first) / f"{name}.json").write_text(json.dumps(rows))
                (Path(second) / f"{name}.json").write_text(json.dumps(rows))
            tampered = sources["field"][0]
            tampered = dict(tampered, actual_items=["app2", "mig2"])
            (Path(second) / "field.json").write_text(
                json.dumps([tampered] + sources["field"][1:]))
            with self.assertRaises(ValueError):
                load_evidence([Path(first), Path(second)])


if __name__ == "__main__":
    unittest.main()
