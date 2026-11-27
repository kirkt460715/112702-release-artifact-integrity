"""离线审核规则测试：夹具均写在临时目录，内置资料保持只读事实。"""
import json
import tempfile
import unittest
from pathlib import Path

from offline_audit import (approval_history, audit_bundle, component_lineage,
                           evaluate_field, load_material, main,
                           trusted_combinations)


def _write(directory, name, rows):
    (Path(directory) / f"{name}.json").write_text(
        json.dumps(rows, ensure_ascii=False), encoding="utf-8")


def _material(directory, *, authorities, packages, field=None):
    _write(directory, "authorities", authorities)
    _write(directory, "packages", packages)
    if field is not None:
        _write(directory, "field", field)
    sources, _ = load_material([directory])
    return sources


VENDOR = {"id": "q-vendor", "issuer": "vendor",
          "scopes": ["app", "catalogue"], "groups": ["g2"]}
COOP = {"id": "q-coop", "issuer": "cooperative",
        "scopes": ["migration"], "groups": ["g2"]}
COOP_G1 = {"id": "q-coop-g1", "issuer": "cooperative",
           "scopes": ["migration"], "groups": ["g1"]}
REVOKE = {"id": "w1", "digest": "d-old", "state": "revoked", "day": 10}

BUNDLE_NEW = {"id": "b-new", "digest": "d-new",
              "items": {"app": "app2", "migration": "mig1",
                        "catalogue": "cat2"},
              "must_pair": ["app", "migration"],
              "signed_scope": ["app", "catalogue"]}
PROOF_WRONG_ITEM = {"id": "p-mig", "item": "mig2",
                    "issuer": "cooperative", "state": "valid",
                    "bound_bundle": "d-new"}
BUNDLE_OLD = {"id": "b-old", "digest": "d-old",
              "items": {"app": "app1", "migration": "mig1"},
              "signed_scope": ["app", "migration"]}


def _codes(findings):
    return {f["code"] for f in findings}


class BundleAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_synthetic_bundle_flags_old_component_partial_signature_and_pair(self):
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP, REVOKE],
            packages=[BUNDLE_NEW, PROOF_WRONG_ITEM, BUNDLE_OLD])
        result = audit_bundle(sources, "b-new", "g2")

        self.assertEqual(result["verdict"], "rejected")
        self.assertIn("revoked_lineage_component", _codes(result["findings"]))
        # 单件证明签的是 mig2，包内实有 mig1：不采信名称，按真实组件对应。
        self.assertIn("proof_component_mismatch", _codes(result["findings"]))
        self.assertIn("unsigned_scope", _codes(result["findings"]))
        self.assertIn("combination_uncovered", _codes(result["findings"]))
        self.assertEqual(set(result["covered"]), {"app", "catalogue"})

    def test_revoked_rollback_bundle_cannot_reuse_old_approval(self):
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP, REVOKE],
            packages=[BUNDLE_OLD])
        result = audit_bundle(sources, "b-old", "g2")
        self.assertEqual(result["verdict"], "rejected")
        self.assertIn("revoked_bundle", _codes(result["findings"]))

    def test_approval_covering_wrong_device_group_is_rejected(self):
        sources = _material(
            self.tmp.name,
            authorities=[COOP_G1],
            packages=[{"id": "b1", "digest": "d1",
                       "items": {"migration": "mx"},
                       "signed_scope": ["migration"]}])
        result = audit_bundle(sources, "b1", "g2")
        self.assertEqual(result["verdict"], "rejected")
        self.assertIn("wrong_group", _codes(result["findings"]))
        self.assertIn("unsigned_scope", _codes(result["findings"]))

    def test_fully_qualified_independent_and_paired_updates_are_trusted(self):
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP],
            packages=[
                {"id": "b-ok", "digest": "d-ok",
                 "items": {"app": "a", "migration": "m", "catalogue": "c"},
                 "must_pair": [["app", "migration"]],
                 "signed_scope": ["app", "migration", "catalogue"]}])
        result = audit_bundle(sources, "b-ok", "g2")
        self.assertEqual(result["verdict"], "trusted", result["findings"])
        self.assertEqual(set(result["covered"]),
                         {"app", "migration", "catalogue"})

    def test_single_item_proof_does_not_cover_combination_commitment(self):
        # 单件证明真实对应包内组件，但 app 段无覆盖，组合承诺仍不成立。
        sources = _material(
            self.tmp.name,
            authorities=[COOP],
            packages=[
                {"id": "b1", "digest": "d1",
                 "items": {"app": "a", "migration": "m"},
                 "must_pair": ["app", "migration"],
                 "signed_scope": []},
                {"id": "p1", "item": "m", "issuer": "cooperative",
                 "state": "valid", "bound_bundle": "d1"}])
        result = audit_bundle(sources, "b1", "g2")
        self.assertEqual(result["verdict"], "rejected")
        self.assertIn("combination_uncovered", _codes(result["findings"]))
        self.assertIn("unsigned_scope", _codes(result["findings"]))

    def test_stale_component_without_revocation_is_warning_not_block(self):
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP],
            packages=[
                {"id": "b1", "digest": "d1",
                 "items": {"app": "shared", "migration": "m1"},
                 "signed_scope": ["app", "migration"]},
                {"id": "b2", "digest": "d2",
                 "items": {"app": "shared", "migration": "m2"},
                 "signed_scope": ["app", "migration"]}])
        result = audit_bundle(sources, "b2", "g2")
        stale = [f for f in result["findings"] if f["code"] == "stale_component"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["severity"], "warn")
        self.assertEqual(stale[0]["subject"], "shared")
        self.assertEqual(result["verdict"], "trusted")

    def test_missing_pair_member_blocks_rollout(self):
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP],
            packages=[{"id": "b1", "digest": "d1",
                       "items": {"app": "a"},
                       "must_pair": ["app", "migration"],
                       "signed_scope": ["app"]}])
        result = audit_bundle(sources, "b1", "g2")
        self.assertIn("missing_pair_component", _codes(result["findings"]))
        self.assertEqual(result["verdict"], "rejected")


class LineageTests(unittest.TestCase):
    def test_component_lineage_tracks_all_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            sources = _material(
                tmp, authorities=[VENDOR],
                packages=[BUNDLE_NEW, BUNDLE_OLD])
            lineage = component_lineage(sources["packages"])
            self.assertEqual(lineage["mig1"], {"d-new", "d-old"})
            self.assertEqual(lineage["app2"], {"d-new"})


class FieldEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_partial_update_separates_completed_pending_and_held(self):
        field = [
            {"id": "f-a", "unit": "g2-a", "registered_bundle": "d-new",
             "actual_items": ["app2"], "state": "partial"}]
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP],
            packages=[BUNDLE_NEW, PROOF_WRONG_ITEM],
            field=field)
        report, = evaluate_field(sources)
        self.assertEqual(report["completed"], [])
        self.assertEqual(report["pending_confirmation"], ["app2"])
        self.assertEqual(report["pending_install"], ["cat2"])
        self.assertEqual(report["blocked"][0]["held_components"], ["app2"])
        self.assertEqual(report["blocked"][0]["missing"]["migration"], "mig1")
        self.assertEqual(report["verdict"], "rejected")

    def test_full_install_is_completed_and_revoked_one_is_rejected(self):
        field = [
            {"id": "f-a", "unit": "g2-a", "registered_bundle": "d-new",
             "actual_items": ["app2", "mig1", "cat2"], "state": "installed"},
            {"id": "f-b", "unit": "g2-b", "registered_bundle": "d-old",
             "state": "installed"}]
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP, REVOKE],
            packages=[BUNDLE_NEW, PROOF_WRONG_ITEM, BUNDLE_OLD],
            field=field)
        reports = {r["id"]: r for r in evaluate_field(sources)}
        self.assertEqual(reports["f-a"]["verdict"], "rejected")
        self.assertEqual(reports["f-a"]["completed"],
                         ["app2", "cat2", "mig1"])
        self.assertEqual(reports["f-b"]["verdict"], "rejected")
        self.assertIn("revoked_bundle",
                      _codes(reports["f-b"]["findings"]))

    def test_held_offline_when_only_pair_member_is_absent(self):
        field = [{"id": "f-a", "unit": "g2-a",
                  "registered_bundle": "d1",
                  "actual_items": ["appA"], "state": "partial"}]
        sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP],
            packages=[{"id": "b1", "digest": "d1",
                       "items": {"app": "appA", "migration": "migA"},
                       "must_pair": ["app", "migration"],
                       "signed_scope": ["app", "migration"]}],
            field=field)
        report, = evaluate_field(sources)
        self.assertEqual(report["verdict"], "held_offline")
        self.assertEqual(report["blocked"][0]["held_components"], ["appA"])
        self.assertEqual(report["pending_install"], [])


class TrustedAndHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sources = _material(
            self.tmp.name,
            authorities=[VENDOR, COOP, REVOKE],
            packages=[BUNDLE_NEW, PROOF_WRONG_ITEM, BUNDLE_OLD])

    def test_no_trusted_combination_when_all_are_blocked(self):
        self.assertEqual(trusted_combinations(self.sources, "g2"), [])

    def test_trusted_listing_includes_clean_bundle(self):
        extra = tempfile.TemporaryDirectory()
        self.addCleanup(extra.cleanup)
        sources = _material(
            extra.name,
            authorities=[VENDOR, COOP],
            packages=[{"id": "b-ok", "digest": "d-ok",
                       "items": {"app": "a", "catalogue": "c"},
                       "signed_scope": ["app", "catalogue"]}])
        trusted = trusted_combinations(sources, "g2")
        self.assertEqual([row["digest"] for row in trusted], ["d-ok"])

    def test_history_records_proofs_and_revocation_day(self):
        history = {row["digest"]: row
                   for row in approval_history(self.sources)}
        self.assertEqual(history["d-old"]["revocations"],
                         [{"id": "w1", "state": "revoked", "day": 10}])
        self.assertEqual(history["d-new"]["item_proofs"][0]["item"], "mig2")
        self.assertEqual(history["d-new"]["bundle_signed_scopes"],
                         ["app", "catalogue"])


class EvidenceMergeTests(unittest.TestCase):
    def test_resealed_evidence_overrides_by_record_id_without_mutating_source(self):
        base = tempfile.TemporaryDirectory()
        self.addCleanup(base.cleanup)
        _write(base.name, "authorities", [VENDOR, COOP])
        _write(base.name, "packages", [BUNDLE_NEW])

        extra = tempfile.TemporaryDirectory()
        self.addCleanup(extra.cleanup)
        fixed = dict(BUNDLE_NEW, signed_scope=["app", "migration", "catalogue"])
        _write(extra.name, "packages", [fixed])

        sources, provenance = load_material([base.name, extra.name])
        bundle = next(row for row in sources["packages"] if row["id"] == "b-new")
        self.assertEqual(bundle["signed_scope"],
                         ["app", "migration", "catalogue"])
        self.assertTrue(provenance["packages/b-new"].endswith(
            Path(extra.name).name) or provenance["packages/b-new"] == extra.name)

        result = audit_bundle(sources, "b-new", "g2")
        self.assertEqual(result["verdict"], "trusted", result["findings"])

        # 原始资料目录未被工具改写。
        untouched = json.loads(
            (Path(base.name) / "packages.json").read_text(encoding="utf-8"))
        self.assertEqual(untouched[0]["signed_scope"], ["app", "catalogue"])

    def test_unknown_source_directory_is_rejected(self):
        good = tempfile.TemporaryDirectory()
        self.addCleanup(good.cleanup)
        _write(good.name, "authorities", [VENDOR])
        bad = tempfile.TemporaryDirectory()
        self.addCleanup(bad.cleanup)
        _write(bad.name, "mystery", [{"id": "x"}])
        with self.assertRaises(ValueError):
            load_material([good.name, bad.name])


class BuiltinMaterialTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).with_name("records")
        self.sources, _ = load_material([self.root])

    def test_builtin_bundle_two_is_rejected_for_all_three_design_flaws(self):
        result = audit_bundle(self.sources, "bundle-2", "second")
        codes = _codes(result["findings"])
        self.assertEqual(result["verdict"], "rejected")
        self.assertIn("revoked_lineage_component", codes)
        self.assertIn("proof_component_mismatch", codes)
        self.assertIn("unsigned_scope", codes)
        self.assertIn("combination_uncovered", codes)

    def test_builtin_field_reports_match_actual_states(self):
        reports = {r["id"]: r for r in evaluate_field(self.sources)}
        self.assertEqual(reports["seen-a"]["pending_confirmation"], ["app2"])
        self.assertTrue(reports["seen-a"]["blocked"])
        self.assertEqual(reports["seen-a"]["pending_install"], ["cat2"])
        self.assertEqual(reports["seen-b"]["verdict"], "rejected")

    def test_no_trusted_combination_and_history_contains_revocation(self):
        self.assertEqual(trusted_combinations(self.sources, "second"), [])
        history = {r["digest"]: r for r in approval_history(self.sources)}
        self.assertEqual(history["combo-1"]["revocations"][0]["id"],
                         "withdraw-1")


class CommandLineTests(unittest.TestCase):
    def test_audit_command_exit_code_reflects_verdict(self):
        self.assertEqual(main(["audit", "bundle-2", "--group", "second"]), 1)

    def test_trusted_command_exit_code_zero(self):
        self.assertEqual(main(["trusted", "--group", "second"]), 0)

    def test_history_command_runs(self):
        self.assertEqual(main(["history", "--digest", "combo-1"]), 0)


if __name__ == "__main__":
    unittest.main()
