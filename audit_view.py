"""离线审计升级包与现场记录（只读入口）。

只读取本地合成 JSON 记录；不制作、传输或执行升级包。默认读取 ``records/``，
用 ``--records`` 可追加重新开封后的证据目录（可重复）。用 ``--at DAY`` 按某个
原始记录日评估，用 ``--section`` 只看其中一块结果。
"""
import argparse
import json
from pathlib import Path

from audit_data import load_evidence
from audit_engine import audit

SECTIONS = ("findings", "bundles", "units", "trusted", "rollback", "history")


def build(directories, at=None, section=None):
    evidence, origins = load_evidence(directories)
    result = audit(evidence, origins=origins, at=at)
    if section is None:
        return result
    if section not in SECTIONS:
        raise ValueError(f"未知结果区块: {section}")
    return {section: result[section]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path, action="append",
                        help="证据目录，可重复；默认为项目内 records/")
    parser.add_argument("--at", type=int, default=None,
                        help="按某个原始记录日评估撤销与审批的生效")
    parser.add_argument("--section", choices=SECTIONS)
    parser.add_argument("--summary", action="store_true",
                        help="只输出结论与阻断项计数")
    args = parser.parse_args(argv)
    directories = args.records or [Path(__file__).with_name("records")]
    try:
        result = build(directories, at=args.at, section=args.section)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    if args.summary:
        findings = result.get("findings", [])
        result = {
            "at": result.get("at"),
            "blocking": result.get("blocking", any(
                item["severity"] == "error" for item in findings)),
            "errors": sum(1 for item in findings if item["severity"] == "error"),
            "warnings": sum(1 for item in findings if item["severity"] == "warning"),
            "sources": {name: len(rows) for name, rows in
                        (result.get("origins") or {}).items()},
        }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
