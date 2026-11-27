"""按记录字段审计升级包完整性、组合授权与回退边界（只读）。

判断依据只有摘要、组件标识、签署范围、发布方审批（发布方、范围、设备组、时间）
和现场观察。文件名、版本号、介质标签一律不参与判断。工具不制作、传输或执行升级包。

组合承诺的约定：
- ``must_pair`` 中的角色必须一起核准；一个角色的签署或审批缺失，整组不可用。
- 未出现在 ``must_pair`` 中的角色可独立应用。
"""
from collections import defaultdict

from audit_data import normalize

USABLE_APPROVAL_STATES = {"valid", "active"}
SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def _finding(code, severity, target, message, **evidence):
    return {
        "code": code, "severity": severity, "target": target,
        "message": message, "evidence": evidence,
    }


def _at_day(day, at):
    """未指定评估日、或记录未给日期时，视为对所有时间有效。"""
    return at is None or day is None or day <= at


def _usable(record, at):
    return record["state"] in USABLE_APPROVAL_STATES and _at_day(record["day"], at)


def _effective_withdrawals(digest, withdrawals, at):
    return [item for item in withdrawals
            if item["digest"] == digest and _at_day(item["day"], at)]


def _add(findings, code, target, message, severity="error", **evidence):
    findings.append(_finding(code, severity, target, message, **evidence))


def resolve_group(observation, known_groups):
    """确定设备组。

    只认记录字段。记录没有 ``group`` 时，按登记约定用 ``unit`` 的首个
    ``-`` 分隔词与已知审批设备组精确匹配；这不是用文件名或介质标签判断。
    返回 (组, 来源)，无法确定时为 (None, None)。
    """
    if observation["group"]:
        return observation["group"], "field"
    unit = observation["unit"]
    for group in sorted(known_groups, key=lambda value: (-len(value), value)):
        if unit == group or unit.startswith(group + "-"):
            return group, "unit"
    return None, None


def _role_approvals(bundle, approvals, at):
    """按角色找有效审批；摘要绑定必须一致，未标注摘要视为通用审批。"""
    by_role, foreign = {}, {}
    for role in bundle["roles"]:
        matched, bound_elsewhere = [], []
        for approval in approvals:
            if role not in approval["scopes"] or not _usable(approval, at):
                continue
            if approval["digest"] in (None, bundle["digest"]):
                matched.append(approval)
            else:
                bound_elsewhere.append(approval)
        by_role[role] = matched
        foreign[role] = bound_elsewhere
    return by_role, foreign


def _analyse_proofs(bundle, proofs, approvals, at, findings):
    """单件证明只能覆盖它自己的组件，不能顶替组合承诺。"""
    target = f"packages/{bundle['id']}"
    absent_roles, invalid, covered_roles = set(), [], set()
    for proof in proofs:
        if proof["bound_bundle"] != bundle["digest"]:
            continue
        if not _usable(proof, at):
            invalid.append(proof)
            _add(findings, "proof_invalid", target, "单件证明状态无效",
                 proof=proof["id"], state=proof["state"])
            continue
        matched = [role for role, component in bundle["items"].items()
                   if component == proof["item"]]
        if matched:
            covered_roles.update(matched)
            continue
        intended = [role for role in bundle["roles"]
                    if any(role in approval["scopes"] and approval["issuer"] == proof["issuer"]
                           for approval in approvals)]
        if len(intended) == 1:
            absent_roles.add(intended[0])
            _add(findings, "proof_item_absent", target,
                 "单件证明的组件不在包内，不能覆盖该角色",
                 proof=proof["id"], item=proof["item"], role=intended[0],
                 bundle_item=bundle["items"].get(intended[0]))
        else:
            _add(findings, "proof_item_absent", target,
                 "单件证明的组件不在包内", proof=proof["id"], item=proof["item"])
    return absent_roles, invalid, covered_roles


def _analyse_bundle(bundle, data, at, component_uses, findings):
    target = f"packages/{bundle['id']}"
    global_blockers = set()
    role_blockers = defaultdict(set)
    role_notes = defaultdict(list)
    approvals, withdrawals, proofs = (
        data["approvals"], data["withdrawals"], data["proofs"])

    if len(data["digests"][bundle["digest"]]) > 1:
        global_blockers.add("digest_conflict")
        _add(findings, "digest_conflict", target, "摘要对应多个包清单",
             digest=bundle["digest"], bundles=sorted(data["digests"][bundle["digest"]]))

    if bundle["signed_digest"] and bundle["signed_digest"] != bundle["digest"]:
        global_blockers.add("signed_digest_mismatch")
        _add(findings, "signed_digest_mismatch", target, "签署摘要与包清单摘要不一致",
             signed=bundle["signed_digest"], actual=bundle["digest"])

    revocations = _effective_withdrawals(bundle["digest"], withdrawals, at)
    if revocations:
        global_blockers.add("bundle_revoked")
        _add(findings, "bundle_revoked", target,
             "撤销报告使该摘要失效，原审批不可复用",
             digest=bundle["digest"], withdrawals=[w["id"] for w in revocations])

    if not bundle["signed_scope"]:
        global_blockers.add("signed_scope_empty")
        _add(findings, "signed_scope_empty", target, "包没有任何签署范围")

    component_values = list(bundle["items"].values())
    duplicated = sorted({value for value in component_values
                         if component_values.count(value) > 1})
    if duplicated:
        global_blockers.add("component_duplicate_role")
        _add(findings, "component_duplicate_role", target,
             "同一组件标识被放在多个角色", components=duplicated)

    groups = bundle["must_pair"]
    for group in groups:
        missing = sorted(set(group) - set(bundle["signed_scope"]))
        if missing:
            _add(findings, "combination_unsigned", target,
                 "组合承诺中的角色未被签署范围覆盖",
                 roles=group, unsigned=missing)
            for role in group:
                role_blockers[role].add("combination_unsigned")

    for role in bundle["roles"]:
        if role not in bundle["signed_scope"]:
            role_blockers[role].add("role_unsigned")
            if not any(role in group for group in groups):
                _add(findings, "role_unsigned", target,
                     "角色不在签署范围内", role=role)

    approvals_by_role, foreign = _role_approvals(bundle, approvals, at)
    for role in bundle["roles"]:
        signer = bundle["signed_by"].get(role)
        if signer is not None and not any(
                a["issuer"] == signer for a in approvals_by_role[role]):
            role_blockers[role].add("signer_issuer_mismatch")
            _add(findings, "signer_issuer_mismatch", target,
                 "签署方与覆盖该角色的审批发布方不一致",
                 role=role, signer=signer,
                 issuers=sorted({a["issuer"] for a in approvals_by_role[role]}))
        if not approvals_by_role[role]:
            role_blockers[role].add("role_unapproved")
            evidence = {"role": role}
            if foreign[role]:
                evidence["bound_elsewhere"] = [a["id"] for a in foreign[role]]
            _add(findings, "role_unapproved", target,
                 "角色没有有效审批" if not foreign[role]
                 else "角色的审批都绑定到其他摘要", **evidence)
        elif foreign[role]:
            role_notes[role].append(
                "另有审批绑定其他摘要: " + ", ".join(a["id"] for a in foreign[role]))

    absent_roles, invalid_proofs, proof_covered = _analyse_proofs(
        bundle, proofs, approvals, at, findings)
    for role in absent_roles:
        role_blockers[role].add("proof_item_absent")

    # 单件证明只覆盖自己声明的组件；组内只被单件证明覆盖时，组合承诺仍未成立。
    proven_by_proof = proof_covered | set(absent_roles)
    for group in groups:
        proven = [role for role in group if role in proven_by_proof]
        if proven and len(proven) < len(group):
            _add(findings, "combination_not_covered_by_proof", target,
                 "组合只得到单件证明，未覆盖整组", roles=group, proven=proven)

    # 合成更换包混入旧组件编号。
    for role, component in bundle["items"].items():
        others = [use for use in component_uses[component]
                  if use["digest"] != bundle["digest"]]
        if not others:
            continue
        revoked_use = next(
            (use for use in others
             if _effective_withdrawals(use["digest"], withdrawals, at)), None)
        if revoked_use:
            role_blockers[role].add("stale_component")
            _add(findings, "stale_component", target,
                 "更换包仍沿用已撤销包的旧组件标识", role=role,
                 component=component, old_bundle=revoked_use["bundle"],
                 old_digest=revoked_use["digest"])
        else:
            _add(findings, "component_shared", target,
                 "同一组件标识出现在不同摘要的包中", severity="warning",
                 role=role, component=component, other_bundle=others[0]["bundle"],
                 other_digest=others[0]["digest"])
            role_notes[role].append(
                f"组件 {component} 也出现在 {others[0]['bundle']}")

    role_state = {}
    for role in bundle["roles"]:
        blockers = global_blockers | role_blockers[role]
        role_state[role] = {
            "signed": role in bundle["signed_scope"],
            "approved_by": [a["id"] for a in approvals_by_role[role]],
            "approvers": sorted({a["issuer"] for a in approvals_by_role[role]}),
            "applicable": not blockers,
            "blockers": sorted(blockers),
            "notes": sorted(role_notes[role]),
        }

    combinations = []
    for group in groups:
        available = all(role_state[role]["applicable"] for role in group)
        combinations.append({
            "roles": group,
            "available": available,
            "blockers": sorted({code for role in group
                                for code in role_state[role]["blockers"]}),
        })

    independent = [
        {"role": role, "applicable": role_state[role]["applicable"],
         "blockers": role_state[role]["blockers"]}
        for role in bundle["roles"]
        if not any(role in group for group in groups)
    ]

    fully_usable = (not global_blockers
                    and all(entry["applicable"] for entry in role_state.values()))
    return {
        "id": bundle["id"], "digest": bundle["digest"],
        "roles": bundle["roles"],
        "role_state": role_state,
        "groups": combinations,
        "independent": independent,
        "revoked": bool(revocations),
        "fully_usable": fully_usable,
        "usable": bool(independent and any(
            entry["applicable"] for entry in independent))
        or any(entry["available"] for entry in combinations),
    }


def _analyse_units(bundle_by_digest, analyses, data, at, known_groups, findings):
    units = []
    for observation in data["fields"]:
        target = f"field/{observation['id']}"
        digest = observation["registered_bundle"]
        report = {
            "id": observation["id"], "unit": observation["unit"],
            "registered_bundle": digest, "state": observation["state"],
            "group": None, "group_source": None,
            "roles": {}, "completed": [], "awaiting_confirmation": [],
            "held": [], "unexpected": [], "blockers": [],
        }
        bundle = bundle_by_digest.get(digest)
        if bundle is None:
            _add(findings, "registry_digest_unknown", target,
                 "登记的摘要没有对应的包清单", digest=digest)
            report["blockers"].append("registry_digest_unknown")
            units.append(report)
            continue
        if len(data["digests"][digest]) > 1:
            _add(findings, "registry_digest_ambiguous", target,
                 "登记的摘要对应多个包清单，无法确定实际内容",
                 digest=digest, bundles=sorted(data["digests"][digest]))
            report["blockers"].append("registry_digest_ambiguous")
            units.append(report)
            continue
        analysis = analyses[bundle["id"]]

        if analysis["revoked"]:
            _add(findings, "registered_bundle_revoked", target,
                 "现场登记的摘要已被撤销，原审批不可复用", digest=digest)
            report["blockers"].append("registered_bundle_revoked")

        group, source = resolve_group(observation, known_groups)
        report["group"], report["group_source"] = group, source
        if group is None:
            _add(findings, "unit_group_unverified", target,
                 "记录无法确定设备组，不能核对审批覆盖")
            report["blockers"].append("unit_group_unverified")
        else:
            for role in bundle["roles"]:
                covering = [a for a in data["approvals"]
                            if a["id"] in analysis["role_state"][role]["approved_by"]]
                if covering and not any(group in a["groups"] for a in covering):
                    _add(findings, "approval_group_mismatch", target,
                         "审批设备组未覆盖本设备", role=role,
                         unit_group=group,
                         covering_groups=sorted({g for a in covering for g in a["groups"]}))
                    report["blockers"].append(f"approval_group_mismatch:{role}")

        actual_roles, unexpected = [], []
        for component in observation["actual_items"] or []:
            matched = [role for role, item in bundle["items"].items()
                       if item == component]
            if matched:
                actual_roles.extend(matched)
            else:
                unexpected.append(component)
        if unexpected:
            _add(findings, "unexpected_actual_item", target,
                 "现场出现包内没有的组件标识", components=unexpected)
            report["unexpected"] = unexpected

        state, has_actual = observation["state"], observation["actual_items"] is not None
        if state in {"installed", "partial"} and not has_actual:
            if state == "installed":
                _add(findings, "installed_content_unverified", target,
                     "记录声称已完成，但没有实际组件清单", severity="warning")
            else:
                _add(findings, "partial_without_actual_items", target,
                     "记录声称部分完成，但没有实际组件清单")
                report["blockers"].append("partial_without_actual_items")

        if state == "unknown":
            applied = {role: False for role in bundle["roles"]}
            report["roles"] = {role: "unknown" for role in bundle["roles"]}
            units.append(report)
            continue
        if not has_actual:
            applied = {role: state == "installed" for role in bundle["roles"]}
        else:
            applied = {role: role in actual_roles for role in bundle["roles"]}

        combo_status = {}
        for group in bundle["must_pair"]:
            applied_members = [role for role in group if applied[role]]
            available = analysis["groups"][
                bundle["must_pair"].index(group)]["available"]
            if applied_members and len(applied_members) < len(group):
                # 组合只能整体上线：已应用一部分时其余不能单独继续。
                _add(findings, "combination_incomplete", target,
                     "组合内只应用了部分组件，其余不能单独上线",
                     roles=group, applied=applied_members)
                for role in group:
                    combo_status[role] = "completed" if applied[role] else "held"
            elif not available and not all(applied[role] for role in group):
                _add(findings, "combination_held", target,
                     "角色属于未满足组合承诺的更新，不能上线",
                     roles=group, blockers=analysis["groups"][
                         bundle["must_pair"].index(group)]["blockers"])
                for role in group:
                    combo_status[role] = "completed" if applied[role] else "held"
            else:
                for role in group:
                    combo_status[role] = "completed" if applied[role] else "awaiting_confirmation"

        for role in bundle["roles"]:
            role_analysis = analysis["role_state"][role]
            if state == "unknown":
                status = "unknown"
            elif role in combo_status:
                status = combo_status[role]
            elif applied[role]:
                status = "completed"
            elif state == "held":
                status = "held"
            else:
                status = "awaiting_confirmation"
            report["roles"][role] = status

            if state == "installed" and has_actual and not applied[role]:
                _add(findings, "install_incomplete", target,
                     "记录声称已完成，但实际组件不足", role=role)
                report["blockers"].append(f"install_incomplete:{role}")

            if applied[role] and not role_analysis["applicable"]:
                _add(findings, "applied_role_not_available", target,
                     "现场已应用的角色在包中不可用", role=role,
                     blockers=role_analysis["blockers"])
                report["blockers"].append(f"applied_role_not_available:{role}")
            elif status in {"awaiting_confirmation", "held"} and not role_analysis["applicable"]:
                report["blockers"].append(f"role_not_available:{role}")

        for status, bucket in (
                ("completed", "completed"),
                ("awaiting_confirmation", "awaiting_confirmation"),
                ("held", "held")):
            report[bucket] = [role for role, value in report["roles"].items()
                              if value == status]
        report["blockers"] = sorted(set(report["blockers"]))
        units.append(report)
    return units


def audit(evidence, origins=None, at=None):
    data = normalize(evidence)
    findings = []

    component_uses = defaultdict(list)
    for bundle in data["bundles"]:
        for role, component in bundle["items"].items():
            component_uses[component].append(
                {"bundle": bundle["id"], "digest": bundle["digest"], "role": role})

    analyses = {
        bundle["id"]: _analyse_bundle(bundle, data, at, component_uses, findings)
        for bundle in data["bundles"]
    }
    bundle_by_digest = {bundle["digest"]: bundle for bundle in data["bundles"]}

    known_groups = sorted({group for approval in data["approvals"]
                           for group in approval["groups"]})
    units = _analyse_units(bundle_by_digest, analyses, data, at, known_groups, findings)
    trusted = [{
        "bundle": bundle["id"], "digest": bundle["digest"],
        "independent_roles": [entry["role"] for entry in analyses[bundle["id"]]["independent"]
                              if entry["applicable"]],
        "combinations": [{"roles": entry["roles"], "available": entry["available"]}
                         for entry in analyses[bundle["id"]]["groups"]],
        "usable": analyses[bundle["id"]]["usable"],
    } for bundle in data["bundles"]]

    rollback = [{
        "bundle": bundle["id"], "digest": bundle["digest"],
        "available": analyses[bundle["id"]]["fully_usable"],
        "reason": _rollback_reason(analyses[bundle["id"]]),
    } for bundle in data["bundles"]]

    history = {
        "approvals": [{
            "id": a["id"], "issuer": a["issuer"], "scopes": a["scopes"],
            "groups": a["groups"], "state": a["state"], "digest": a["digest"],
            "day": a["day"],
        } for a in data["approvals"]],
        "withdrawals": [{
            "id": w["id"], "digest": w["digest"], "state": w["state"], "day": w["day"],
        } for w in data["withdrawals"]],
        "digests": [{
            "digest": digest,
            "bundles": sorted(data["digests"][digest]),
            "revoked_by": sorted(
                w["id"] for w in data["withdrawals"] if w["digest"] == digest),
            "generic_approvals": sorted(
                a["id"] for a in data["approvals"] if a["digest"] is None),
            "bound_approvals": sorted(
                a["id"] for a in data["approvals"] if a["digest"] == digest),
        } for digest in sorted(data["digests"])],
    }

    findings.sort(key=lambda item: (
        SEVERITY_ORDER[item["severity"]], item["code"], item["target"],
        str(sorted(item["evidence"].items()))))
    return {
        "at": at,
        "findings": findings,
        "bundles": [analyses[bundle["id"]] for bundle in data["bundles"]],
        "units": units,
        "trusted": trusted,
        "rollback": rollback,
        "history": history,
        "blocking": any(item["severity"] == "error" for item in findings),
        "origins": origins or {},
    }


def _rollback_reason(analysis):
    if analysis["revoked"]:
        return "撤销报告使该摘要失效，原审批不可复用"
    if analysis["fully_usable"]:
        return None
    return "完整性、签署或审批核对未通过"
