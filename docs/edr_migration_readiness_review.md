# DetectPsByAmsiCodex EDR 迁移 Readiness Review

## 1. 当前架构状态结论

当前工程已经具备进入 **EDR 迁移准备阶段** 的条件，但不建议立即迁入 EDR 主进程，也不建议继续在 B0 阶段深改日志线程生命周期。

判断依据：

- `RaspSentryBase` 中最容易与 EDR 迁移发生强耦合的三类职责已经形成 seam：规则 JSON 解析、detection event JSON/transport、diag log JSON/legacy pipe forward。
- detection event path 已经从内联 JSON 和直接 pipe 写入，收敛为 `EventJsonBuilder` + `IEventTransport` / `LegacyPipeEventTransport` + worker-only 薄包装。
- diag log path 已经从 `LogForwardThreadProc()` 中拆出 JSON 构造和 legacy bytes forwarder，生产路径仍保持旧线程、旧 drain、旧 pipe 语义。
- `PushLogEntryLocked()` / `PopLogEntryLocked()` 已经把 ring buffer 写入和读取片段变成可审查的锁内 helper，为后续 `DiagRingBuffer` 或 `DiagLoggerRuntime` 接入留下边界。
- B0-3-3-4a / 4b 已经把日志线程生命周期风险固化为文档和静态门禁，当前决定暂缓 `DiagLoggerRuntime` 是合理的：继续改 `Shutdown()`、`m_logThreadAlive`、`m_logEvent`、`LogForwardThreadProc()` 退出条件，会进入高风险生命周期改造，不再属于 EDR 迁移 readiness 的必要前置。

结论：

- 可以从 B0 拆分阶段转向 EDR 迁移准备文档、接口冻结和目录边界规划。
- `DiagLoggerRuntime` 暂缓，不阻塞 EDR 迁移准备；它属于后续日志生命周期治理，不是当前迁移边界建立的关键路径。
- 下一步应优先冻结 scanner-core / rule-runtime / adapter 接口契约，而不是继续拆 `RaspSentryBase` 的线程生命周期。

## 2. B0 拆分成果清单

| 模块 / seam | 当前状态 | 当前文件 | 价值 | 后续迁移方向 |
|---|---|---|---|---|
| `RuleJsonParser` | 已抽离 | `src/rasp_rule_engine/include/rule_json_parser.h`, `src/rasp_rule_engine/src/rule_json_parser.cpp` | 将规则 JSON 解析从 `RaspSentryBase` 中剥离，避免 parser 依赖 pipe / log / event | 迁入 `rule-runtime` |
| `EventJsonBuilder` | 已抽离并接入 detection event path | `event_submit_client.h/.cpp` | detection event JSON 构造不再散落在 `TrySubmitDetectionEvent()` 中 | 迁入 EDR telemetry DTO adapter 或 scanner-core telemetry boundary |
| `IEventTransport` | 已抽象 | `event_transport.h`, `event_worker_sender.h` | worker-only 发送路径可替换 transport，不绑定 named pipe API | 由 EDR event sink 或 legacy pipe adapter 实现 |
| `LegacyPipeEventTransport` | 已抽离 | `legacy_pipe_event_transport.h/.cpp` | detection event legacy pipe 写入封装为 bytes transport | 归入 `legacy-pipe-compat-layer`，后续可删除 |
| `SendDetectionEventSyncWorkerOnly()` | 已改为 transport 薄包装 | `rasp_sentry_base.cpp` | 保留旧入口，移除直接 pipe 写入职责 | 后续替换为 EDR event sink worker-only 实现 |
| `TrySubmitDetectionEvent()` | 已使用 `EventJsonBuilder` | `rasp_sentry_base.cpp` | 事件入队 DTO 填充保持原地，JSON 构造已独立 | 后续可由 `IEventSink` / EDR sink 接管 |
| `DiagLogger` / `DiagLogSink` seam | 已建立接口草案 | `diag_logger.h`, `diag_log_sink.h` | 明确 diag log 不参与检测决策，不进入 detection event pipeline | 后续接 `edr-diag-log-sink` |
| `DiagRingBuffer` seam | 已建立 | `diag_ring_buffer.h` | ring buffer 数据结构边界形成，但尚未接生产路径 | 后续可迁入 lifecycle/runtime 或 diag logger 内部 |
| `PushLogEntryLocked()` | 已抽出 | `rasp_sentry_base.h/.cpp` | 锁内写 ring buffer 逻辑可审查，保持旧语义 | 后续可替换为 `DiagRingBuffer::Push()` |
| `PopLogEntryLocked()` | 已抽出 | `rasp_sentry_base.h/.cpp` | 锁内 drain 逻辑可审查，保持旧语义 | 后续可替换为 `DiagRingBuffer::Pop()` |
| `LegacyDiagJsonBuilder` | 已抽离并接入 `LogForwardThreadProc()` | `legacy_diag_json_builder.h/.cpp` | diag JSON 构造独立，保留旧 wire format | 归入 legacy diag compatibility |
| `LegacyDiagLogForwarder` | 已抽离并接入 `LogForwardThreadProc()` | `legacy_diag_log_forwarder.h/.cpp` | bytes-only diag forwarder，不理解 detection event | 归入 `legacy-pipe-compat-layer` |
| `LegacyDiagPipeWriter` | 已抽离并接入 `LogForwardThreadProc()` | `legacy_diag_pipe_writer.h/.cpp` | diag legacy pipe 写入封装到独立 writer | 归入 `legacy-pipe-compat-layer` |
| B0-3-3-4a / 4b | 已完成设计和静态门禁 | `phase_b0_3_3_4_diag_logger_lifecycle_design.md`, `check_rasp_sentry_base_boundaries.ps1` | 固化日志生命周期风险，防止职责回退 | 暂缓实现 `DiagLoggerRuntime` |

## 3. RaspSentryBase 剩余职责表

| 当前职责 | 当前位置 | 是否已有 seam | 未来归属 | 迁移优先级 | 是否阻塞 EDR 迁移 | 备注 |
|---|---|---|---|---|---|---|
| `ConnectSentry()` | `src/rasp_rule_engine/src/rasp_sentry_base.cpp` | 部分，已有 `rule_control_client.h` / `legacy_pipe_transport.h` 草案 | `legacy-pipe-compat-layer`，长期由 `edr-rule-provider` 替代 | High | 否 | 需要后续拆成 control client + transport，不应进入 scanner-core |
| `ConfigPipeThreadProc()` | `rasp_sentry_base.cpp` | 有 `rule_control_client.h` / `legacy_pipe_transport.h` seam，但未接入 | `legacy-pipe-compat-layer`，长期由 EDR control-plane 替代 | High | 否 | 当前仍承载 reload/unload 旧 pipe 语义，迁移期可兼容保留 |
| `SentryRetryThreadProc()` | `rasp_sentry_base.cpp` | 暂无完整实现 seam | `lifecycle-runtime` + `edr-rule-provider` backoff | Medium | 否 | 不应在 Scan 热路径拉规则；后续要变成 bounded retry/backoff |
| `Initialize()` | `rasp_sentry_base.cpp` | 暂无完整生命周期 seam | `lifecycle-runtime` / provider adapter lifecycle | Medium | 否 | 继续保留现状，暂不接 `DiagLoggerRuntime` |
| `Shutdown()` | `rasp_sentry_base.cpp` | 有 B0-3-3-4 生命周期设计和静态门禁 | `lifecycle-runtime` | Medium | 否 | 当前不继续改，避免引入 unload / thread UAF 风险 |
| `Log()` | `rasp_sentry_base.cpp` | 有 `DiagLogger` seam | `edr-diag-log-sink` facade 或 provider diag facade | Medium | 否 | 暂不接 EDR logger，不改变 OutputDebugStringA 行为 |
| `EnqueueLog()` | `rasp_sentry_base.cpp` | 有 `DiagRingBuffer` seam 和 `PushLogEntryLocked()` | `DiagLoggerRuntime` / `DiagRingBuffer` | Medium | 否 | 暂不替换底层存储，后续单独评审 |
| `LogForwardThreadProc()` | `rasp_sentry_base.cpp` | 已接 `LegacyDiagJsonBuilder` + `LegacyDiagLogForwarder` + `LegacyDiagPipeWriter` | `legacy-pipe-compat-layer`，长期由 `edr-diag-log-sink` 替代 | Low-Medium | 否 | 已完成关键职责拆分，生命周期暂缓 |
| `SendDetectionEvent()` | `rasp_sentry_base.cpp` | 有 `EventJsonBuilder` / `IEventSink` 方向 seam | `edr-event-sink` | Medium | 否 | 仍保留旧 facade，后续可路由到 EDR event sink |
| `TrySubmitDetectionEvent()` | `rasp_sentry_base.cpp` | 已接 `EventJsonBuilder`，仍使用 `AsyncEventQueue` | `edr-event-sink` / provider telemetry adapter | Medium | 否 | DTO 填充仍在原地，Scan 热路径保持非阻塞入队 |
| `SendDetectionEventSyncWorkerOnly()` | `rasp_sentry_base.cpp` | 已接 `event_worker_sender` + `LegacyPipeEventTransport` | `edr-event-sink` worker-only adapter | Low | 否 | 当前 legacy transport 薄包装已足够支撑迁移准备 |
| `ParseRulesJson()` | `rasp_sentry_base.cpp` | 已接 `RuleJsonParser` | `rule-runtime` | Low | 否 | 可在 M1/M2 物理迁移 |
| `Base64Decode()` | `rasp_sentry_base.cpp` | 暂无独立 seam | `rule-runtime` utility 或 compatibility helper | Low | 否 | 如果只服务旧 rule/config path，可随 parser/control client 拆迁 |
| pipe ACL / SDDL | `ConfigPipeThreadProc()` 等 pipe 创建位置 | 有 `LegacyPipeTransport` 方向 seam | `legacy-pipe-compat-layer` / EDR IPC security adapter | High | 否 | EDR 迁移时必须重新审查 PID/SID/IL/签名校验 |
| reload hooks | `OnReloadSignal()` / config pipe signal | 部分已有 runtime reload 仲裁 | provider adapter lifecycle + EDR control-plane | High | 否 | reload 语义必须保持 Build -> TryEnterReload -> Publish |
| unload hooks | `OnUnloadSignal()` / config pipe signal | 部分已有 inert/unload 设计 | provider adapter lifecycle | High | 否 | 不应由 EDR adapter 直接操作 `EngineRuntime` 内部锁 |

## 4. EDR 目标模块划分

| 目标模块 | 职责 | 输入 | 输出 | 禁止依赖 |
|---|---|---|---|---|
| `scanner-core` | 编排输入归一化、session 聚合、预算控制、规则快照扫描、决策生成 | `ScriptScanInput`, `ScriptScanContext` | `ScriptScanResult`, `DetectionEventLite` | `windows.h`, `amsi.h`, EDR SDK, pipe API, DB |
| `rule-runtime` | 规则 JSON 解析、规则快照构建、Lua / PCRE2 执行 | 规则 bundle / JSON / libSource | immutable rule snapshot / rule eval result | AMSI COM, EDR event bus, pipe, DB |
| `amsi-provider-adapter` | COM/AMSI Provider 注册、`IAmsiStream` 提取、AMSI_RESULT 映射 | AMSI stream / session | `ScriptScanInput`, AMSI result | DB, EDR global lifecycle, remote config fetch in Scan |
| `edr-module-adapter` | 在 EDR 检测进程中承载模块生命周期、线程池、权限模型 | EDR SDK lifecycle | rule/event/config adapter 实例 | AMSI COM, provider runtime internal locks |
| `edr-rule-provider` | 从 EDR 规则中心获取规则版本，构建并发布规则快照 | EDR rule bundle | `IRuleProvider` implementation | Scan 热路径阻塞、直接访问 AMSI |
| `edr-event-sink` | detection event 进入 EDR event bus | `DetectionEventLite` / async event DTO | EDR event | rule-runtime 内部对象、Lua state、PCRE2 |
| `edr-diag-log-sink` | diag log 进入 EDR logger | `DiagLogRecord` | EDR log | detection decision、event pipeline 递归依赖 |
| `legacy-pipe-compat-layer` | 兼容旧 `rasp_sentry_rules/events/config` pipe | legacy bytes/protocol | adapter DTO | 新 EDR control-plane 语义、长期保留 |
| `lifecycle-runtime` | Provider/diag/event worker 生命周期协调、有界 shutdown/drain | runtime config / stop signal | lifecycle status | JSON/pipe/EDR SDK/rule execution |
| `migration-test-harness` | 对比 legacy 与 EDR adapter 行为一致性 | fixtures / fake sinks / fake transports | golden tests / regression report | 生产路径副作用 |

## 5. 接口契约表

| 接口 / 类型 | 所属模块 | 当前来源 | 未来实现方 | 调用方 | 是否允许阻塞 | 是否可在 Scan 热路径调用 | 迁移备注 |
|---|---|---|---|---|---|---|---|
| `ScriptScanInput` | `scanner-core` | Phase 3 / migration design | `amsi-provider-adapter` 构造 | `scanner-core` | N/A | 是，纯 DTO | 必须不持有 `IAmsiStream*` |
| `ScriptSessionKey` | `scanner-core/session-context` | Phase 3 Batch 2 设计 | provider adapter 构造 | session cache / scanner-core | N/A | 是，纯 DTO | 包含 `SessionKeyConfidence` |
| `ScriptScanContext` | `scanner-core` | migration design | config adapter / provider adapter | scanner-core | 不允许远程阻塞 | 是，仅读本地配置 | 包含 budget/fail policy |
| `ScriptScanResult` | `scanner-core` | migration design | scanner-core 生成 | provider adapter | N/A | 是，返回值 | `action` 与 `status` 必须分离 |
| `DetectionEventLite` | telemetry boundary | `event_submit_client.h` 方向 DTO | scanner-core / provider adapter | `IEventSink` | N/A | 是，但只入队 | 不携带完整 payload / DB schema |
| `IRuleProvider` | scanner-core boundary | `rule_control_client.h` 方向规划 | EDR rule provider / legacy adapter | scanner-core | Scan 热路径不允许阻塞 | 是，仅本地 snapshot 读取 | 返回状态需区分 disconnected / stale / faulted |
| `IConfigProvider` | config boundary | migration design | EDR config adapter | scanner-core | Scan 中不远程拉取 | 是，仅本地缓存读取 | 后续冻结接口 |
| `IEventSink` | telemetry boundary | `AsyncEventQueue` / design | EDR event sink / legacy queue sink | scanner-core/provider | `TrySubmit` 不允许阻塞 | 是，仅 TrySubmit | 队列满必须快速返回 |
| `IDiagLogSink` | diag logging boundary | `diag_log_sink.h` | OutputDebugString sink / EDR diag sink / ring buffer sink | diag logger facade | Scan 热路径不允许阻塞 | 谨慎，仅非阻塞实现 | 不参与 detection decision |
| `IEventTransport` | event transport boundary | `event_transport.h` | `LegacyPipeEventTransport` / future EDR transport | worker-only sender | worker 内允许有界失败 | 否 | 只发送 bytes，不理解业务 |
| `ILegacyDiagBytesWriter` | legacy diag transport boundary | `legacy_diag_log_forwarder.h` | `LegacyDiagPipeWriter` | `LegacyDiagLogForwarder` | worker 内允许有界失败 | 否 | 只发送 bytes，不理解 diag schema |
| `RuleJsonParser` | `rule-runtime` | `rule_json_parser.h/.cpp` | rule-runtime | rule provider / legacy parser wrapper | 非 Scan 热路径可阻塞解析 | 否 | 不依赖 log/pipe/event |
| `EventJsonBuilder` | telemetry DTO builder | `event_submit_client.h/.cpp` | EDR telemetry adapter 或 provider telemetry | `TrySubmitDetectionEvent()` / tests | N/A | 可调用，但不得分配超大内存 | 已接 detection event path |
| `LegacyDiagJsonBuilder` | legacy diag compatibility | `legacy_diag_json_builder.h/.cpp` | legacy compat layer | `LogForwardThreadProc()` | N/A | 否 | 保持旧 wire format，无末尾换行 |

## 6. EDR 迁移分阶段路线

### M0：迁移 readiness review

- 目标：复盘 B0 拆分状态，确认是否可进入迁移准备阶段。
- 允许改动：新增 `docs/edr_migration_readiness_review.md`。
- 禁止改动：不改代码、不移动目录、不接 EDR SDK、不改 `RaspSentryBase` 生产逻辑。
- 验收标准：职责表完整、接口契约完整、路线和红线明确。
- 回滚策略：删除本 review 文档。

### M1：scanner-core 目录与接口冻结

- 目标：创建 scanner-core 目录边界和接口定义，冻结 `ScriptScanInput` / `ScriptScanResult` / `IRuleProvider` / `IEventSink` 等契约。
- 允许改动：新增接口头文件、边界检查脚本、迁移测试 harness 草案。
- 禁止改动：不移动生产扫描逻辑、不接 EDR SDK、不改 AMSI Scan 返回语义。
- 验收标准：scanner-core 不 include AMSI/Windows IPC/EDR/DB；接口可被 AMSI adapter 和测试 harness 编译引用。
- 回滚策略：删除新增接口目录，保留现有 `rasp_rule_engine` 路径。

### M2：rule provider 适配

- 目标：把规则获取、规则解析、snapshot 构建从 `RaspSentryBase` 主路径拆成 rule provider adapter。
- 允许改动：新增 `IRuleProvider` legacy implementation，复用 `RuleJsonParser`。
- 禁止改动：不改变 reload 发布语义，不改变 JSON 字段语义，不在 Scan 热路径远程拉规则。
- 验收标准：legacy rule fixture 输出一致；reload 失败保留旧 snapshot；scan + reload 并发回归通过。
- 回滚策略：保留旧 `ConnectSentry()` / `ParseRulesJson()` 调用路径，通过开关回退。

### M3：event sink 适配

- 目标：将 detection event 从 legacy event pipe 迁移到抽象 `IEventSink`，并提供 EDR event sink 实现。
- 允许改动：新增 EDR event sink adapter、legacy sink adapter、事件一致性测试。
- 禁止改动：不改变 `AsyncEventQueue` drop policy，不同步写 EDR event bus，不扩大事件 schema。
- 验收标准：legacy JSON golden fixture 与新 sink DTO 映射一致；EDR 不可用时 Scan 热路径不阻塞。
- 回滚策略：切回 `LegacyPipeEventTransport`。

### M4：diag log sink 适配

- 目标：将 diag log sink 抽象为 `IDiagLogSink`，为 EDR logger 接入做准备。
- 允许改动：新增 EDR diag log sink adapter、OutputDebugString sink、必要的非阻塞队列或采样策略。
- 禁止改动：diag log 不进入 detection event pipeline；不改检测决策；不递归调用 EventSubmitClient。
- 验收标准：日志不可用不影响 Scan；shutdown/unload 不阻塞；日志长度和脱敏策略明确。
- 回滚策略：保留 legacy diag pipe forwarder 和 OutputDebugStringA。

### M5：provider adapter / AMSI adapter 收口

- 目标：将 AMSI COM 提取和 scanner-core 调用边界收口，明确 DLL 只做 provider adapter。
- 允许改动：整理 `amsi_provider.cpp` / `amsi_rule_engine.cpp` 调用边界，增加 adapter tests。
- 禁止改动：不改 `DllMain` 极简策略，不改 `EngineRuntime` 内部锁，不改 fail policy 语义。
- 验收标准：Scan 热路径只读本地 snapshot / 本地 config；AMSI_RESULT 映射有测试。
- 回滚策略：保留当前 `AmsiRuleEngine::Evaluate()` 路径。

### M6：legacy pipe compatibility layer 灰度

- 目标：将旧 `rasp_sentry_rules/events/config` pipe 限定为兼容层，并与 EDR adapter 并行灰度。
- 允许改动：新增兼容层开关、fallback telemetry、灰度统计。
- 禁止改动：legacy pipe 不承载新的 EDR control-plane 语义；不新增旧协议字段作为长期能力。
- 验收标准：EDR path 稳定时不依赖 legacy pipe；fallback 次数可观测。
- 回滚策略：开关切回 legacy pipe 全量。

### M7：删除 legacy pipe 的退出门禁

- 目标：满足删除条件后移除 legacy sentry pipe 和 `rasp_sentry_native.exe` 兼容路径。
- 允许改动：删除 legacy pipe adapter、安装脚本移除旧 exe、清理文档。
- 禁止改动：未满足灰度门禁前不得删除；不得影响 scanner-core/rule-runtime。
- 验收标准：EDR control-plane、event bus、diag logger 连续稳定；测试环境不再部署旧 sentry；灰度 N 天无 fallback。
- 回滚策略：在 `latest_allowed_release` 前保留可恢复分支或安装包。

## 7. 迁移红线

1. `scanner-core` 不得 include `windows.h` / `amsi.h` / EDR SDK / pipe API / DB 头文件。
2. `rule-runtime` 不得直接发送事件，不得依赖 `IEventSink`。
3. Scan 热路径不得远程拉规则。
4. Scan 热路径不得同步写 EDR event bus。
5. diag log 不得进入 detection event pipeline。
6. EDR adapter 不得反向控制 `EngineRuntime` 内部锁。
7. legacy pipe 不得承载新的 EDR control-plane 语义。
8. 不得把 `RaspSentryBase` 整体搬进 EDR。
9. `EventSubmitClient` 不得依赖 `RuleSnapshot` / Lua state / PCRE2 / `RaspLuaEngine`。
10. `LegacyDiagLogForwarder` / `LegacyDiagPipeWriter` 不得理解 detection event 或 EDR event schema。
11. `DiagLoggerRuntime` 后续如实现，不得构造 JSON、写 pipe、调用 EDR SDK、调用 EventSubmitClient。
12. 兼容层新增功能必须标注删除条件、目标移除版本和最后允许发布版本。

## 8. 最小下一步任务

当前最小下一步只做：

- 新增 `docs/edr_migration_readiness_review.md`。
- 不改代码。
- 不移动目录。
- 不接 EDR SDK。
- 不改 `RaspSentryBase` 生产逻辑。
- 不改 `LogForwardThreadProc()`。
- 不改 `Shutdown()`。
- 不改 Scan 相关逻辑。
- 不删除 legacy pipe。

建议后续评审通过后，再进入 M1：scanner-core 目录与接口冻结。

## 9. 验收标准

- `docs/edr_migration_readiness_review.md` 存在。
- B0 拆分成果清单完整。
- `RaspSentryBase` 剩余职责表覆盖指定函数和职责。
- EDR 目标模块划分明确。
- 接口契约表完整，覆盖指定接口和类型。
- M0-M7 迁移路线清晰，每阶段包含目标、允许改动、禁止改动、验收标准、回滚策略。
- 迁移红线明确。
- 当前代码无生产逻辑变更。
- 未删除 legacy pipe。
- 未接 EDR SDK。
- 未修改 `LogForwardThreadProc()` / `Shutdown()` / Scan 相关逻辑。
# Session aggregation status

Status: Dormant / Experimental

Production state: Not wired into current AMSI scan path

Release commitment: Not supported in current version

Session-context is retained as a dormant asset and is not part of the current production readiness claim.
