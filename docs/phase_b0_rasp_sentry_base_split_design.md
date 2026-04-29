# Phase B0: RaspSentryBase 职责拆分准备设计

## 1. 目标

Phase B0 的目标是为后续 `scanner-core / rule-runtime / EDR adapter / compatibility-layer` 抽离建立清晰 seam。本批不做大规模重构，不改变 `RaspSentryBase` 主路径运行行为，不抽 pipe / event / reload / log 链路。

B0 拆成两个子阶段：

- B0-1：新增设计文档、接口草案、静态边界检查脚本，运行行为不变。
- B0-2：在单独 review 后，可选只抽 `RuleJsonParser`，并用单测证明解析行为一致。

本文件描述 B0-1 的硬边界和 B0-2 的进入条件。

## 2. 本批允许 / 禁止范围

允许：

- 新增本设计文档。
- 新增五个 seam 接口草案头文件。
- 新增 `scripts/check_rasp_sentry_base_boundaries.ps1`。
- 跑构建、静态检查、Phase 2 / Phase 3 回归。

禁止：

- 修改 `rasp_sentry_base.cpp` 主路径逻辑。
- 一次性拆掉 pipe / event / reload / log 主链路。
- 修改 JSON 字段语义。
- 修改 RuleSnapshot 发布流程。
- 修改 reload / unload 行为。
- 修改事件 schema / DB。
- 修改 AMSI Provider `Scan()` 返回语义。
- 提前接入 EDR SDK。

## 3. RaspSentryBase 函数级职责表

| 函数 / 成员 | 当前职责 | 未来归属 | 本批是否改 | 风险 |
|---|---|---|---|---|
| `Initialize()` | 初始化 sentry 连接、初次规则加载、启动 retry/config/log 线程、启动 async event sink | provider adapter / runtime hooks / RuleControlClient / DiagLogger / EventSubmitClient | 不改 | 高 |
| `Shutdown()` | 停止运行态、停止 event sink、唤醒日志线程、关闭线程和句柄、释放 log CS | provider adapter / runtime hooks / DiagLogger / EventSubmitClient | 不改 | 高 |
| `Log()` | 格式化诊断日志，写 `OutputDebugStringA`，入 ring buffer | `DiagLogger` | 不改 | 中 |
| `EnsureLogCsInit()` | 初始化日志 critical section 和 event handle | `DiagLogger` | 不改 | 中 |
| `EnqueueLog()` | 写入日志 ring buffer，满时覆盖最老日志，唤醒 log thread | `DiagLogger` | 不改 | 中 |
| `LogForwardThreadProc()` | 后台 drain 诊断日志，构造成 diag event，经 `SendDetectionEventSyncWorkerOnly()` 发出 | `DiagLogger + EventSubmitClient + LegacyPipeTransport` | 不改 | 中高 |
| `Base64Decode()` | Base64 解码工具，供规则 lib / script 解码使用 | utility / rule-runtime helper | 不改 | 低 |
| `ConnectSentry()` | 连接 `rasp_sentry_rules` pipe，发送 `GET_ALL_RULES`，读取规则 JSON，并预解析 lib | `RuleControlClient + LegacyPipeTransport` | 不改 | 高 |
| `Parser` nested struct | 递归下降 JSON token 读取，暴露给派生类 `ParseRuleExtension()` 使用 | `RuleJsonParser` 内部实现或兼容 parser context | 不改 | 中 |
| `Parser::read_string()` | 读取 JSON 字符串 | `RuleJsonParser` | 不改 | 中 |
| `Parser::read_bool()` | 读取 JSON bool | `RuleJsonParser` | 不改 | 中 |
| `Parser::read_int()` | 读取 JSON int | `RuleJsonParser` | 不改 | 中 |
| `Parser::read_string_array()` | 读取字符串数组 | `RuleJsonParser` | 不改 | 中 |
| `Parser::read_regex_check_array()` | 读取 `RegexCheck` 数组 | `RuleJsonParser` | 不改 | 中 |
| `Parser::skip_value()` | 跳过任意 JSON value | `RuleJsonParser` | 不改 | 中 |
| `Parser::skip_array()` | 跳过 JSON array | `RuleJsonParser` | 不改 | 中 |
| `Parser::skip_object()` | 跳过 JSON object | `RuleJsonParser` | 不改 | 中 |
| `ParseRuleExtension()` | 默认跳过派生模块扩展字段；派生类可重写 | rule parser extension seam | 不改 | 中 |
| `ParseRulesJson()` | 解析 `GET_ALL_RULES` response，填充 base rule 字段、libSource 和派生 rule 扩展字段 | `RuleJsonParser / rule-runtime` | B0-1 不改；B0-2 可单独抽 | 中低 |
| `SendDetectionEvent()` | 对外 detection event fire-and-forget 入口，调用 `TrySubmitDetectionEvent()` | `EventSubmitClient` | 不改 | 高 |
| `TrySubmitDetectionEvent()` | 将 `RaspEvalResult` 构造成 `AsyncEvent`，做字段截断和队列提交 | `EventSubmitClient` | 不改 | 高 |
| `SendDetectionEventSyncWorkerOnly()` | worker-only 同步 pipe 发送，写 `rasp_sentry_events` | `EventSubmitClient + LegacyPipeTransport` | 不改 | 高 |
| `ConfigPipeThreadProc()` | 创建 `rasp_sentry_config` pipe server，接收 0x01 reload / 0x02 unload，调用 hook | `RuleControlClient + LegacyPipeTransport + runtime hook` | 不改 | 高 |
| `SentryRetryThreadProc()` | 初始规则加载失败时轮询 `ConnectSentry()+ParseAndSwap()` | `RuleControlClient + provider runtime hook` | 不改 | 高 |
| `ParseAndSwap()` | 派生类实现 snapshot 构建和发布 | provider adapter / scanner-core boundary | 不改 | 高 |
| `OnReloadSignal()` | 派生类实现 reload 策略 | provider runtime hook | 不改 | 高 |
| `OnUnloadSignal()` | 派生类实现 unload / inert 策略 | provider runtime hook | 不改 | 高 |
| `AllocRule()` | 创建模块规则对象 | rule-runtime parser factory seam | 不改 | 中 |
| `Evaluate()` | 派生类检测入口 | scanner-core/provider adapter boundary | 不改 | 高 |
| `m_luaEngine` | 历史 Lua engine 成员，AMSI 当前已改用 snapshot-local Lua engine | rule-runtime / legacy compatibility | 不改 | 中 |
| `m_eventSink` | async event sink 实例 | `EventSubmitClient` | 不改 | 中高 |
| `m_logQueue` / `m_logEvent` / `m_logThread` | 诊断日志队列和转发线程状态 | `DiagLogger` | 不改 | 中 |
| `m_configThread` / `m_retryThread` | control-plane 兼容线程 | `RuleControlClient + LegacyPipeTransport` | 不改 | 高 |
| pipe 创建 / ACL / `CreateFileW` / `WaitNamedPipeW` / `CreateNamedPipeW` | 旧 sentry named pipe transport | `LegacyPipeTransport` | 不改 | 中高 |

## 4. 接口草案与依赖方向

本批新增接口头文件只定义 seam，不接入主路径。

| 接口 | 文件 | 允许依赖 | 禁止依赖 |
|---|---|---|---|
| `RuleJsonParser` | `rule_json_parser.h` | STL、`rasp_rule_base.h` | pipe / event / logger / AMSI / EDR / DB |
| `RuleControlClient` | `rule_control_client.h` | STL、control DTO | Lua / PCRE2 / event sink |
| `EventSubmitClient` | `event_submit_client.h` | STL、event DTO | `RuleSnapshot` / Lua state / PCRE2 |
| `DiagLogger` | `diag_logger.h` | STL、log level | 检测决策 / AMSI_RESULT |
| `LegacyPipeTransport` | `legacy_pipe_transport.h` | Windows pipe transport DTO | 新 control-plane 业务语义 |

硬规则：

- `rule-runtime` 不依赖 pipe / event / logger / provider runtime。
- `LegacyPipeTransport` 不依赖规则语义。
- `EventSubmitClient` 不依赖 Lua / PCRE2。
- `DiagLogger` 不参与检测决策。
- 新接口头文件不 include AMSI / COM / EDR SDK / DB。

## 5. B0-1 运行行为约束

B0-1 只新增文档、接口草案和静态检查脚本。除必要 build 引用外，不修改 `RaspSentryBase` 主路径逻辑。

Review checklist：

- `rasp_sentry_base.cpp` 无行为逻辑修改。
- reload 行为不变。
- snapshot publish 行为不变。
- event/log/pipe 行为不变。
- sentry pipe 仍兼容。
- AMSI `Scan()` 返回语义不变。

## 6. B0-2 RuleJsonParser 抽离进入条件

B0-2 不自动开始，必须满足：

1. B0-1 文档、接口、静态检查全部通过。
2. 现有构建和回归测试通过。
3. `RuleJsonParser` 抽离方案单独 review。
4. 明确 parser 单测如何验证旧 `ParseRulesJson()` 行为一致。
5. 明确不改 reload / snapshot publish / event / log / pipe。

B0-2 抽 parser 时必须遵守：

- 只抽解析逻辑。
- 不改规则 JSON 字段语义。
- 不改 reload 流程。
- 不改 snapshot 发布流程。
- 不改事件 schema。
- 不改 pipe 协议。
- `RuleJsonParser` 内部不调用 `Log` / pipe / event。

## 7. 静态边界检查

新增脚本：

- `scripts/check_rasp_sentry_base_boundaries.ps1`

检查内容：

- 新接口头文件不得 include AMSI / COM / EDR SDK / DB。
- `RuleJsonParser` 不得依赖 pipe / event / logger。
- `EventSubmitClient` 不得依赖 `RuleSnapshot` / Lua state / PCRE2。
- `DiagLogger` 不得出现 `AMSI_RESULT` 或检测 action/status。
- `LegacyPipeTransport` 不得承载新 control-plane 业务语义。
- B0-1 不应修改 `rasp_sentry_base.cpp` 主路径逻辑。

## 8. 验收标准

文档验收：

- `docs/phase_b0_rasp_sentry_base_split_design.md` 存在。
- 函数级职责表完整，且以当前代码为准补齐实际函数。
- 每个函数都有当前职责、未来归属、本批是否改、风险等级。
- 接口依赖方向明确。
- B0-2 进入条件明确。

接口验收：

- 五个接口草案头文件存在。
- 接口头文件只定义 seam，不接入主路径。
- `RuleJsonParser` 不依赖 pipe / event / logger / AMSI / EDR / DB。
- `RuleControlClient` 不依赖 Lua / PCRE2。
- `EventSubmitClient` 不依赖 `RuleSnapshot` / Lua state / PCRE2。
- `DiagLogger` 不参与检测决策。
- `LegacyPipeTransport` 不承载新业务语义。

行为验收：

- B0-1 运行行为不变。
- `rasp_mod_amsi.dll` 构建通过。
- Phase 2 runtime 测试通过。
- scan budget 测试通过。
- async event queue 测试通过。
- normalizer 测试通过。
- session-context 测试通过。
- sentry 兼容流程不变。

## 9. 本批拒绝的做法

以下做法本批应拒绝：

1. 一次性拆掉 `RaspSentryBase` 的 pipe / event / reload / log 主链路。
2. 抽 parser 时顺手改 JSON 字段语义。
3. 抽 parser 时顺手改 `RuleSnapshot` 发布流程。
4. `RuleJsonParser` 内部继续调用 `Log` / pipe / event。
5. 新接口头文件 include EDR SDK 或 AMSI COM。
6. `LegacyPipeTransport` 承载新 control-plane 业务语义。
7. `EventSubmitClient` 直接读取 `RuleSnapshot` / Lua state。
8. 本批提前接入 EDR SDK。
