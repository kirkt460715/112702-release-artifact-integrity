# 场区离线升级包的完整性与组合上线审核

签名结果和摘要都是外部合成事实。项目没有签名材料、固件或实际设备控制。 资料均为本地合成记录。

以 Python 3.11.2 运行，无第三方依赖。`records/` 中的 `authorities`、`packages`、`field` 对应独立来源。每份材料是 JSON 对象数组，`id` 在同一来源内唯一。报告和观察的时间以各原始记录给出的字段为准。

```sh
python3 -m unittest -v
python3 records_view.py
```

资料入口列出来源、记录标识及条数。通过 `--source` 指定来源，`--offset` 和 `--limit` 限定读取的位置与数量。`--records` 可指定同样结构的其他资料目录。

## 离线审核（offline_audit.py）

只读取证，不制作、不传输、不执行升级包；不采信文件名、版本号或介质标签，只按摘要绑定、组件标识对应、发布方资格与撤销记录判断。

来源语义：

- `authorities`：发布方资格（`issuer`/`scopes`/`groups`）与撤销报告（`digest`/`state`/`day`）。
- `packages`：维护端目录清单。带 `items` 的是组合包（`digest`、逐段组件、`must_pair` 组合承诺、`signed_scope` 组合级签署范围）；带 `bound_bundle` 的是单件证明（`item` 必须与包内真实组件标识一致）。
- `field`：现场观察（设备编号、登记组合、实际在场组件、状态）。

```sh
# 审核单个组合对某设备组的完整性与回退边界；有阻断级发现时退出码为 1
python3 -I offline_audit.py audit bundle-2 --group second
# 现场汇总：completed / pending_confirmation / pending_install / blocked 与结论
python3 -I offline_audit.py field
# 值班员查询当前可用的受信组合
python3 -I offline_audit.py trusted --group second
# 历史核准摘要（组件、签署范围、单件证明、撤销事件及生效日）
python3 -I offline_audit.py history
```

阻断级发现包括：`revoked_bundle`（撤销命中，旧审批不得复用）、`revoked_lineage_component`（混入来自已撤销组合的旧组件编号）、`proof_component_mismatch`（证明签署的组件与包内实物不符）、`unsigned_scope`（某一段无有效覆盖）、`combination_uncovered`/`missing_pair_component`（must_pair 组合承诺未整体核准）、`wrong_group`/`unqualified_issuer`/`invalid_proof`（资格、设备组或证明状态问题）、`unknown_bundle`/`unknown_group`。旧组件编号若不涉撤销血脉则为 `stale_component` 告警，不单独阻断。

重新开封后的新证据放在独立目录，只允许出现 `authorities.json`/`packages.json`/`field.json` 三个同名来源；通过 `--evidence 目录`（可重复）并入，同标识记录由新证据覆盖，原始资料不会被改写。

```sh
python3 -I offline_audit.py --evidence /path/to/resealed audit bundle-2 --group second
```

设备编号到设备组按前缀解析（如 `second-a`、`second-b` 属于 `second`）。审核现场部分更新时，组合承诺缺失会把已在场的配对组件记入 `blocked`（受组合限制未上线），独立更新的未装部分记入 `pending_install`。

```sh
python3 -I -m unittest -v
```
