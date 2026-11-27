"""校验并规范化三份独立来源：发布方审批、升级包清单和现场观察。

只使用记录字段（摘要、组件标识、签署范围、设备组、时间）作判断依据，不使用
文件名、版本号或介质标签。记录缺少关键字段时拒绝读取，避免把残缺材料当成有效
证据；语义上"无法核对"的情形留给审计层报告，而不是静默假设。
"""
from collections import defaultdict
from pathlib import Path

from records_view import load_sources

KNOWN_SOURCES = ("authorities", "packages", "field")
APPROVAL_STATES = {"valid", "active", "revoked", "expired", "withdrawn"}
WITHDRAWAL_STATES = {"revoked", "withdrawn"}
FIELD_STATES = {"installed", "partial", "pending", "held", "unknown"}


def _text(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} 需要非空文本")
    return value


def _text_list(value, label, allow_empty=False):
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{label} 需要非空文本数组")
    if not allow_empty and not value:
        raise ValueError(f"{label} 不能为空")
    return list(value)


def _day(record, label):
    value = record.get("day")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} 的 day 需要非负整数")
    return value


def _mapping(value, label):
    if not isinstance(value, dict) or not value:
        raise ValueError(f"{label} 需要非空对象")
    for key, item in value.items():
        _text(key, f"{label} 的键")
        _text(item, f"{label}[{key}]")
    return dict(value)


def _normalize_must_pair(value, roles, label):
    """规范化组合承诺。

    扁平角色数组表示同一组合（数组内所有角色必须一起核准、一起上线）；
    角色数组的数组表示多个彼此独立的组合。未列入 must_pair 的角色可独立应用。
    """
    if value is None:
        return []
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} 的 must_pair 需要非空数组")
    if all(isinstance(entry, str) for entry in value):
        raw_groups = [list(value)]
    elif all(isinstance(entry, list) for entry in value):
        raw_groups = [
            _text_list(entry, f"{label} 的 must_pair[{index}]")
            for index, entry in enumerate(value)
        ]
    else:
        raise ValueError(f"{label} 的 must_pair 只能全为角色或全为角色数组")
    groups, used = [], set()
    for group in raw_groups:
        for role in group:
            if role not in roles:
                raise ValueError(f"{label} 的 must_pair 引用了不存在的角色 {role}")
            if role in used:
                raise ValueError(f"{label} 的角色 {role} 同时属于多个组合")
            used.add(role)
        groups.append(group)
    return groups


def load_evidence(directories):
    """合并多个离线证据目录，返回 (来源记录, 记录来源路径)。

    重新开封后补充的材料放在别的目录里；同一来源内重复标识必须内容一致，
    内容冲突直接拒绝，避免后到的材料悄悄覆盖先到的记录。
    """
    merged = {name: [] for name in KNOWN_SOURCES}
    origins = {name: {} for name in KNOWN_SOURCES}
    seen = {name: {} for name in KNOWN_SOURCES}
    for directory in directories:
        sources = load_sources(Path(directory))
        unknown = set(sources) - set(KNOWN_SOURCES)
        if unknown:
            raise ValueError(f"{directory} 含未知来源: {', '.join(sorted(unknown))}")
        for name, rows in sources.items():
            for row in rows:
                identifier = row["id"]
                previous = seen[name].get(identifier)
                if previous is not None:
                    if previous != row:
                        raise ValueError(
                            f"记录标识跨证据冲突: {name}/{identifier}"
                            f"（{origins[name][identifier]} 与 {directory}）"
                        )
                    continue
                seen[name][identifier] = row
                origins[name][identifier] = str(directory)
                merged[name].append(row)
    missing = [name for name in KNOWN_SOURCES if not merged[name]]
    if missing:
        raise ValueError(f"缺少来源: {', '.join(missing)}")
    return merged, origins


def _authority(row):
    label = f"authorities/{row['id']}"
    if "scopes" in row:
        _text(row.get("issuer"), f"{label} 的 issuer")
        state = row.get("state", "valid")
        if state not in APPROVAL_STATES:
            raise ValueError(f"{label} 的 state 无效")
        digest = row.get("digest")
        if digest is not None:
            _text(digest, f"{label} 的 digest")
        return {
            "kind": "approval", "id": row["id"], "issuer": row["issuer"],
            "scopes": _text_list(row.get("scopes"), f"{label} 的 scopes"),
            "groups": _text_list(row.get("groups"), f"{label} 的 groups"),
            "state": state, "day": _day(row, label), "digest": digest,
        }
    if "digest" in row and row.get("state") in WITHDRAWAL_STATES:
        return {
            "kind": "withdrawal", "id": row["id"],
            "digest": _text(row.get("digest"), f"{label} 的 digest"),
            "state": row["state"], "day": _day(row, label),
        }
    raise ValueError(f"{label} 既不是审批也不是撤销报告")


def _package(row):
    label = f"packages/{row['id']}"
    if "items" in row:
        items = _mapping(row.get("items"), f"{label} 的 items")
        signed_scope = _text_list(
            row.get("signed_scope"), f"{label} 的 signed_scope", allow_empty=True)
        extra = set(signed_scope) - set(items)
        if extra:
            raise ValueError(f"{label} 的 signed_scope 含未知角色: {', '.join(sorted(extra))}")
        signed_digest = row.get("signed_digest")
        if signed_digest is not None:
            _text(signed_digest, f"{label} 的 signed_digest")
        signed_by = row.get("signed_by")
        if signed_by is not None:
            signed_by = _mapping(signed_by, f"{label} 的 signed_by")
            extra = set(signed_by) - set(items)
            if extra:
                raise ValueError(f"{label} 的 signed_by 含未知角色: {', '.join(sorted(extra))}")
        return {
            "kind": "bundle", "id": row["id"],
            "digest": _text(row.get("digest"), f"{label} 的 digest"),
            "items": items, "roles": list(items),
            "must_pair": _normalize_must_pair(row.get("must_pair"), items, label),
            "signed_scope": signed_scope, "signed_digest": signed_digest,
            "signed_by": signed_by or {}, "day": _day(row, label),
        }
    if "item" in row:
        state = row.get("state", "valid")
        if state not in APPROVAL_STATES:
            raise ValueError(f"{label} 的 state 无效")
        return {
            "kind": "proof", "id": row["id"],
            "item": _text(row.get("item"), f"{label} 的 item"),
            "issuer": _text(row.get("issuer"), f"{label} 的 issuer"),
            "state": state,
            "bound_bundle": _text(row.get("bound_bundle"), f"{label} 的 bound_bundle"),
            "day": _day(row, label),
        }
    raise ValueError(f"{label} 既不是包清单也不是单件证明")


def _field(row):
    label = f"field/{row['id']}"
    state = row.get("state")
    if state not in FIELD_STATES:
        raise ValueError(f"{label} 的 state 无效")
    group = row.get("group")
    if group is not None:
        # 设备组只认显式字段，不从 unit 名称或介质标签推断。
        group = _text(group, f"{label} 的 group")
    actual = row.get("actual_items")
    if actual is not None:
        # 空数组有效：表示现场尚未应用任何组件，与"没有清单"不同。
        actual = _text_list(actual, f"{label} 的 actual_items", allow_empty=True)
    return {
        "kind": "field", "id": row["id"],
        "unit": _text(row.get("unit"), f"{label} 的 unit"), "group": group,
        "registered_bundle": _text(
            row.get("registered_bundle"), f"{label} 的 registered_bundle"),
        "actual_items": actual, "state": state, "day": _day(row, label),
    }


def normalize(evidence):
    approvals, withdrawals, bundles, proofs, fields = [], [], [], [], []
    for row in evidence["authorities"]:
        entry = _authority(row)
        (approvals if entry["kind"] == "approval" else withdrawals).append(entry)
    for row in evidence["packages"]:
        entry = _package(row)
        (bundles if entry["kind"] == "bundle" else proofs).append(entry)
    for row in evidence["field"]:
        fields.append(_field(row))

    digests = defaultdict(list)
    for bundle in bundles:
        digests[bundle["digest"]].append(bundle["id"])
    return {
        "approvals": approvals, "withdrawals": withdrawals, "bundles": bundles,
        "proofs": proofs, "fields": fields, "digests": dict(digests),
    }
