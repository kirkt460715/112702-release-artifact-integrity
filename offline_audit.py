"""离线审核合成升级包：只读取证，不制作、不传输、不执行升级包。

核对依据仅限摘要绑定、组件标识对应、发布方资格与撤销记录，
不采信文件名、版本号或介质标签。所有资料目录均以只读方式打开，
重新开封后的新证据通过追加资料目录并入，同标识记录由新证据覆盖。
"""
import argparse
import copy
import json
import sys
from pathlib import Path

# -I 隐含 -P，脚本目录不会自动进入 sys.path；只加入工具自身目录，
# 资料目录绝不加入，避免资料中的同名模块被解释器加载。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from records_view import load_sources  # noqa: E402

BLOCK, WARN = "block", "warn"
# 三个独立来源分别对应发布方资格、维护端目录清单与现场观察；
# 重新开封的证据只能补充同名来源，不接受来源不明的材料混入。
KNOWN_SOURCES = frozenset(("authorities", "packages", "field"))


def _finding(code, severity, subject, detail, evidence):
    return {"code": code, "severity": severity, "subject": subject,
            "detail": detail, "evidence": list(evidence)}


def load_material(directories):
    """合并多个只读资料目录；后给目录中的同标识记录覆盖旧记录。

    返回 (sources, provenance)，provenance 记录每条证据来自哪个目录，
    便于区分原始登记与重新开封后补交的证据。
    """
    merged, provenance = {}, {}
    for directory in directories:
        for name, rows in load_sources(Path(directory)).items():
            if name not in KNOWN_SOURCES:
                raise ValueError(
                    f"{directory} 含未知来源 {name}.json；"
                    f"只接受 {sorted(KNOWN_SOURCES)}")
            table = merged.setdefault(name, {})
            for row in rows:
                table[row["id"]] = copy.deepcopy(row)
                provenance[f"{name}/{row['id']}"] = str(directory)
    if not merged:
        raise ValueError("没有本地资料")
    sources = {name: list(rows.values()) for name, rows in merged.items()}
    return sources, provenance


def _bundles(packages):
    return [row for row in packages if isinstance(row.get("items"), dict)]


def _proofs(packages):
    return [row for row in packages if "bound_bundle" in row]


def _revocations(authorities):
    return [row for row in authorities if "digest" in row]


def _qualifications(authorities):
    return [row for row in authorities if "issuer" in row]


def _pair_sets(bundle):
    """must_pair 既支持扁平列表（一个组合承诺），也支持列表的列表。"""
    raw = bundle.get("must_pair", [])
    if raw and all(isinstance(item, list) for item in raw):
        return [list(item) for item in raw]
    return [list(raw)] if raw else []


def _in_pair(bundle, scope):
    return any(scope in pair for pair in _pair_sets(bundle))


def resolve_group(unit, groups):
    """设备编号到设备组：取与编号前缀一致的最长组名（如 second-a -> second）。"""
    fits = [group for group in groups
            if unit == group or unit.startswith(group + "-")]
    return max(fits, key=len) if fits else None


def component_lineage(packages):
    """组件编号 -> 出现过该编号的全部组合摘要，用于识别混入的旧组件。"""
    lineage = {}
    for bundle in _bundles(packages):
        for component in bundle["items"].values():
            lineage.setdefault(component, set()).add(bundle["digest"])
    return lineage


def audit_bundle(sources, bundle_id, group):
    """核对单个组合包对指定设备组的完整性与签署覆盖，给出阻断/告警级发现。"""
    packages = sources.get("packages", [])
    authorities = sources.get("authorities", [])
    bundle = next((row for row in _bundles(packages) if row["id"] == bundle_id), None)
    if bundle is None:
        raise ValueError(f"升级包不存在: {bundle_id}")

    digest = bundle["digest"]
    items = bundle["items"]
    quals = _qualifications(authorities)
    known_groups = {g for q in quals for g in q.get("groups", [])}
    findings = []

    if group not in known_groups:
        findings.append(_finding(
            "unknown_group", BLOCK, group,
            "没有发布方资格覆盖该设备组", []))

    # 1. 撤销优先：撤销报告一旦命中，旧审批立即失效，不得复用。
    revoked = [row for row in _revocations(authorities)
               if row["digest"] == digest and row.get("state") == "revoked"]
    if revoked:
        findings.append(_finding(
            "revoked_bundle", BLOCK, digest,
            "组合已被撤销，旧审批不得复用",
            [row["id"] for row in revoked]))
    revoked_digests = {row["digest"] for row in _revocations(authorities)
                       if row.get("state") == "revoked"}

    # 2. 旧组件编号：同一组件编号出现在其他组合中即告警；
    #    若来源组合已被撤销，属于撤销血脉回流，阻断。
    lineage = component_lineage(packages)
    bundle_ids = {component: [b["id"] for b in _bundles(packages)
                              if component in b["items"].values()]
                  for component in set(items.values())}
    for scope, component in items.items():
        origins = lineage.get(component, set()) - {digest}
        dead = sorted(origins & revoked_digests)
        if dead:
            findings.append(_finding(
                "revoked_lineage_component", BLOCK, component,
                {"scope": scope, "from_revoked": dead,
                 "other_origins": sorted(origins - revoked_digests)},
                bundle_ids[component]))
        elif origins:
            findings.append(_finding(
                "stale_component", WARN, component,
                {"scope": scope, "origins": sorted(origins)},
                bundle_ids[component]))

    # 3. 单件证明逐条核验：必须与包内真实组件标识一一对应，
    #    签发人须具备对应段范围与设备组资格，且证明绑定本组合摘要。
    exact_proof = {}
    for proof in (p for p in _proofs(packages)
                  if p.get("bound_bundle") == digest):
        pid = proof["id"]
        if proof.get("state") != "valid":
            findings.append(_finding(
                "invalid_proof", BLOCK, pid,
                {"state": proof.get("state")}, [pid]))
            continue
        issuer_quals = [q for q in quals if q["issuer"] == proof.get("issuer")]
        if not issuer_quals:
            findings.append(_finding(
                "unqualified_issuer", BLOCK, pid,
                {"issuer": proof.get("issuer")}, [pid]))
            continue
        scope = next((s for s, c in items.items() if c == proof.get("item")), None)
        if scope is None:
            packaged = {s: c for s, c in items.items()
                        if any(s in q.get("scopes", []) for q in issuer_quals)}
            findings.append(_finding(
                "proof_component_mismatch", BLOCK, pid,
                {"signed_item": proof.get("item"), "packaged": packaged},
                [pid]))
            continue
        if not any(group in q.get("groups", []) and scope in q.get("scopes", [])
                   for q in issuer_quals):
            findings.append(_finding(
                "wrong_group", BLOCK, pid,
                {"issuer": proof.get("issuer"), "group": group, "scope": scope},
                [q["id"] for q in issuer_quals]))
            continue
        exact_proof.setdefault(scope, []).append(pid)

    # 4. 逐段覆盖：组合级签署范围或单件证明，二者须真正覆盖包内组件。
    covered = {}
    for scope, component in items.items():
        if scope in bundle.get("signed_scope", []):
            matched = [q for q in quals
                       if scope in q.get("scopes", [])
                       and group in q.get("groups", [])]
            if matched:
                covered[scope] = {"via": "bundle_scope",
                                  "evidence": [q["id"] for q in matched]}
                continue
            findings.append(_finding(
                "wrong_group", BLOCK, f"{digest}:{scope}",
                {"signed_scope": scope, "group": group},
                [q["id"] for q in quals if scope in q.get("scopes", [])]))
        if scope in exact_proof:
            covered[scope] = {"via": "item_proof",
                              "evidence": exact_proof[scope]}
        else:
            findings.append(_finding(
                "unsigned_scope", BLOCK, f"{digest}:{scope}",
                {"scope": scope, "component": component}, []))

    # 5. 组合承诺：must_pair 内各段须同时被覆盖，单件签署不等于组合核准。
    for pair in _pair_sets(bundle):
        absent = [scope for scope in pair if scope not in items]
        if absent:
            findings.append(_finding(
                "missing_pair_component", BLOCK, digest,
                {"pair": pair, "absent": absent}, []))
            continue
        uncovered = [scope for scope in pair if scope not in covered]
        if uncovered:
            findings.append(_finding(
                "combination_uncovered", BLOCK, digest,
                {"pair": pair, "uncovered": uncovered}, []))

    verdict = ("trusted" if not any(f["severity"] == BLOCK for f in findings)
               else "rejected")
    return {"bundle_id": bundle_id, "digest": digest, "group": group,
            "verdict": verdict, "covered": covered, "findings": findings}


def evaluate_field(sources):
    """汇总现场观察：已完成、安装待确认、受组合限制未上线及合规结论。"""
    packages = sources.get("packages", [])
    authorities = sources.get("authorities", [])
    groups = sorted({g for q in _qualifications(authorities)
                     for g in q.get("groups", [])})
    by_digest = {b["digest"]: b for b in _bundles(packages)}
    reports = []

    for observation in sources.get("field", []):
        digest = observation.get("registered_bundle")
        group = resolve_group(observation.get("unit", ""), groups)
        report = {"id": observation["id"], "unit": observation.get("unit"),
                  "group": group, "digest": digest,
                  "state": observation.get("state"),
                  "completed": [], "pending_confirmation": [],
                  "pending_install": [], "blocked": [],
                  "verdict": "in_progress", "findings": []}
        bundle = by_digest.get(digest)
        if bundle is None:
            report["verdict"] = "rejected"
            report["findings"].append(_finding(
                "unknown_bundle", BLOCK, digest,
                "现场登记的组合不在目录清单内", [observation["id"]]))
            reports.append(report)
            continue

        audit = audit_bundle(sources, bundle["id"], group)
        report["findings"].extend(audit["findings"])
        items = bundle["items"]
        actual = observation.get("actual_items")
        if actual is None:
            actual = list(items.values())
        present = {s: c for s, c in items.items() if c in actual}
        missing = {s: c for s, c in items.items() if c not in actual}

        bucket = ("completed" if observation.get("state") == "installed"
                  else "pending_confirmation")
        report[bucket] = sorted(present.values())
        report["pending_install"] = sorted(
            c for s, c in missing.items() if not _in_pair(bundle, s))
        for pair in _pair_sets(bundle):
            lost = [s for s in pair if s in missing]
            held = [present[s] for s in pair if s in present]
            if lost and held:
                report["blocked"].append(
                    {"pair": pair, "held_components": held,
                     "missing": {s: missing[s] for s in lost}})

        if any(f["severity"] == BLOCK for f in report["findings"]):
            report["verdict"] = "rejected"
        elif report["blocked"]:
            report["verdict"] = "held_offline"
        elif missing:
            report["verdict"] = "in_progress"
        else:
            report["verdict"] = "completed"
        reports.append(report)
    return reports


def trusted_combinations(sources, group):
    """值班员查询：当前对该设备组真正可用的受信组合。"""
    result = []
    for bundle in _bundles(sources.get("packages", [])):
        audit = audit_bundle(sources, bundle["id"], group)
        if audit["verdict"] == "trusted":
            result.append({"digest": bundle["digest"],
                           "bundle_id": bundle["id"],
                           "components": bundle["items"]})
    return result


def approval_history(sources):
    """历史核准摘要：组合组件、签署范围、单件证明与撤销事件。"""
    packages = sources.get("packages", [])
    authorities = sources.get("authorities", [])
    entries = []
    for digest in sorted({b["digest"] for b in _bundles(packages)}):
        bundles = [b for b in _bundles(packages) if b["digest"] == digest]
        proofs = [p for p in _proofs(packages) if p.get("bound_bundle") == digest]
        entries.append({
            "digest": digest,
            "bundle_ids": [b["id"] for b in bundles],
            "components": {s: c for b in bundles
                           for s, c in b["items"].items()},
            "bundle_signed_scopes": sorted(
                {s for b in bundles for s in b.get("signed_scope", [])}),
            "item_proofs": [{"id": p["id"], "item": p.get("item"),
                             "issuer": p.get("issuer"),
                             "state": p.get("state")} for p in proofs],
            "revocations": [{"id": r["id"], "state": r.get("state"),
                             "day": r.get("day")}
                            for r in _revocations(authorities)
                            if r["digest"] == digest],
        })
    return entries


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    default_records = Path(__file__).with_name("records")
    parser.add_argument("--records", type=Path, action="append",
                        help="只读资料目录，可重复指定；缺省为内置 records/")
    parser.add_argument("--evidence", type=Path, action="append", default=[],
                        help="重新开封后补交的证据目录，可重复指定")
    sub = parser.add_subparsers(dest="command", required=True)

    audit_cmd = sub.add_parser("audit", help="核对单个组合包")
    audit_cmd.add_argument("bundle_id")
    audit_cmd.add_argument("--group", required=True, help="目标设备组")

    field_cmd = sub.add_parser("field", help="汇总现场更新状态")
    field_cmd.add_argument("--unit")

    trusted_cmd = sub.add_parser("trusted", help="查询当前受信组合")
    trusted_cmd.add_argument("--group", required=True)

    history_cmd = sub.add_parser("history", help="历史核准摘要")
    history_cmd.add_argument("--digest")

    args = parser.parse_args(argv)
    directories = (args.records or [default_records]) + args.evidence
    try:
        sources, _ = load_material(directories)
        if args.command == "audit":
            result = audit_bundle(sources, args.bundle_id, args.group)
            exit_code = 0 if result["verdict"] == "trusted" else 1
        elif args.command == "field":
            result = evaluate_field(sources)
            if args.unit:
                result = [row for row in result if row["unit"] == args.unit]
            exit_code = 0
        elif args.command == "trusted":
            result = trusted_combinations(sources, args.group)
            exit_code = 0
        else:
            result = approval_history(sources)
            if args.digest:
                result = next((row for row in result
                               if row["digest"] == args.digest), None)
                if result is None:
                    raise ValueError(f"组合摘要不存在: {args.digest}")
            exit_code = 0
    except (ValueError, OSError) as error:
        parser.error(str(error))

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
