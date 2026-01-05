# 项目问题清单（仅检测，不修改）

> 依据当前代码静态检查结果整理，后续可按优先级修复。

## 修改建议（概要）

1) 修正日志历史分页顺序：翻页返回更旧数据时，插入到列表末尾或按时间/ID 重新排序，确保“新→旧”一致性。
2) 补齐 SSH 成功日志解析，并接入规则引擎；同时在序列逻辑里用上 `success_within_sec`。
3) 规则引擎事件保留内部主机名（internal_host），仅在展示层映射为公网域名。
4) 前端告警去重统一使用 string 化 ID；时间解析改为手动解析或后端输出 ISO 格式。
5) 删除或合并重复规则文件，确保规则 ID 唯一。
6) 将 `alert_builder` 的 host 来源统一到主流程映射（或传入 public_host），避免硬编码。
7) 支持 `*_regex`：在 loader 中保留该字段，或显式映射到 Rule 结构。
8) HTTP 事件端口字段统一为 `port`（或在 builder 中同时兼容 `dst_port`）。
9) HTTP 分支的 debug 输出与非 HTTP 一致；严重度梯度按需求调整。

## 高优先级

1) 历史日志分页追加方向错误
- 现象：翻页请求到更旧数据后，用 `push` 追加到末尾，顺序变成“新→旧→更旧”，并影响回放顺序。
- 位置：`frontend/src/pages/Logs.vue:259`
 - 修改建议：
   - 将翻页返回数据插入到末尾后，重新按 `id` 或 `created_at` 排序；
   - 或者改为“末尾追加 + 不在 UI 中混排”，即维持“旧→新”。

2) SSH_FAIL_TO_SUCCESS 规则永远无法触发
- 现象：规则依赖 success 事件，但当前只解析失败日志；且序列逻辑未使用 `success_within_sec`。
- 位置：`backend/app/services/detection/engine.py:253`，`backend/app/services/detection/engine.py:266`，`backend/app/services/detection/rules/ssh_fail_to_success.yml:1`，`backend/app/services/parser/ssh.py:8`
 - 修改建议：
   - 新增 SSH success 日志解析器（匹配 “Accepted password” / “Accepted publickey” 等）；
   - 在 `/ingest` 中将 success 事件送入 rule engine；
   - 在 `_eval_sequence` 中使用 `success_within_sec` 限制 success 的时间窗。

3) 规则引擎事件 host 被设置为公网域名，导致内部资产名丢失
- 现象：`alert_builder` 的 `asset.internal_host` 被写成公网域名，SSH 告警主机显示容易退化/混乱。
- 位置：`backend/app/main.py:162`，`backend/app/services/detection/alert_builder.py:286`
 - 修改建议：
   - 规则引擎事件中 `host` 保留内部资产名；
   - 在 `alert_builder` 里增加 `public_host` 字段，或从主流程传入；
   - UI 层按场景显示 internal/public（SSH 显示 internal，HTTP 显示 public）。

## 中优先级

4) 告警去重使用 id 直接比较，number/string 混用导致重复或无法合并
- 现象：`pushAlert` 使用 `x.id === a.id`，但 id 类型可能不一致；已有 `_idOfAlert` 未使用。
- 位置：`frontend/src/store/ids.ts:42`，`frontend/src/store/ids.ts:82`
 - 修改建议：
   - 统一将 `id` 转成 string；去重与更新都使用 `_idOfAlert()` 的结果；
   - `AlertRow.id` 类型改为 `number | string` 以匹配实际数据。

5) created_at 非 ISO 格式导致 Date.parse 跨浏览器不稳定
- 现象：排序和时间展示可能出现偏差或 NaN。
- 位置：`frontend/src/store/ids.ts:48`
 - 修改建议：
   - 后端统一输出 ISO 8601；或
   - 前端使用手动解析（例如 `YYYY-MM-DD HH:mm:ss` 拆分）。

6) HTTP 规则重复加载（同 ID）
- 现象：两个 YAML 均为 `id: HTTP_PATH_BRUTEFORCE`，可能重复评估/重复告警。
- 位置：`backend/app/services/detection/rules/http_scan.yml:1`，`backend/app/services/detection/rules/http_path_bruteforce.yml:1`
 - 修改建议：
   - 删除重复文件，或改成不同 ID 与规则语义；
   - 加载阶段检测重复 ID 并警告/跳过。

7) 规则引擎 host 统一为固定 PUBLIC_HOST，忽略运行时映射配置
- 现象：与主流程 `ASSET_HOST_MAP/DEFAULT_PUBLIC_HOST` 不一致。
- 位置：`backend/app/services/detection/alert_builder.py:8`
 - 修改建议：
   - 删除硬编码 `PUBLIC_HOST`；
   - 将映射逻辑下沉到主流程，构建 event 时明确传入 public_host。

8) 规则引擎宣称支持 *_regex，但 rules_loader 丢弃未知字段
- 现象：YAML 内 `*_regex` 实际不会生效。
- 位置：`backend/app/services/detection/engine.py:30`，`backend/app/services/detection/rules_loader.py:27`
 - 修改建议：
   - `Rule` 中增加 `extra` 字段保留未知字段；
   - 或显式将 `*_regex` 键保存在 Rule，并在 `_match` 中读取。

9) HTTP 事件使用 dst_port，但 alert_builder 只看 port
- 现象：无 scheme 但有 dst_port 时端口推断可能失效。
- 位置：`backend/app/services/detection/alert_builder.py:53`
 - 修改建议：
   - 在 `_guess_scheme_and_port` 中同时读取 `dst_port`；
   - 或在事件构建时统一填充 `port` 字段。

## 低优先级

10) /ingest?debug=true 在 HTTP 分支直接 return，不返回 debug 信息
- 现象：debug 模式对 HTTP 解析/规则输出不可见，与接口描述不一致。
- 位置：`backend/app/main.py:377`，`backend/app/main.py:496`
 - 修改建议：
   - 在 HTTP 分支添加 debug 输出结构，与 SSH 分支对齐；
   - 或在 debug 模式下不提前 return，统一走返回体。

11) severity_for_count 阈值刚达标就返回 HIGH
- 现象：MEDIUM 只有在 threshold+5 才出现，可能不是预期梯度。
- 位置：`backend/app/services/detector/ssh_bruteforce.py:73`
 - 修改建议：
   - 明确等级映射规则（如 `threshold~threshold+4` 为 MEDIUM，以上为 HIGH）；
   - 或将等级阈值配置化，避免硬编码。

---

需要我按优先级给出修复建议时，直接告诉我编号即可。
