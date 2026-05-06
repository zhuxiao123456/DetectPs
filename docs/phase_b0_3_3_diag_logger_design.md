# Phase B0-3-3 DiagLogger 拆分设计

## 1. 背景与目标

`RaspSentryBase` 当前仍然承载诊断日志的完整链路：格式化日志、写 `OutputDebugStringA`、写 ring buffer、唤醒日志线程、drain ring buffer、构造 legacy diag JSON、写 `rasp_sentry_events` pipe，并在 `Shutdown()` 中停止日志线程。

B0-3-3 的目标是先固化日志模块边界，为后续从 `RaspSentryBase` 拆出 `DiagLogger`、`IDiagLogSink`、`LegacyDiagLogForwarder` 做准备。

当前阶段为 **B0-3-3-0 design-only**：

- 只新增本设计文档。
- 不修改 `RaspSentryBase` 生产逻辑。
- 不修改 `LogForwardThreadProc()`。
- 不修改日志线程、ring buffer、diag JSON、pipe 写入或 shutdown drain 行为。

## 2. 非目标

B0-3-3-0 不做：

- 不改 `Log()`。
- 不改 `EnqueueLog()`。
- 不改 `LogForwardThreadProc()`。
- 不改 `Shutdown()` 中日志线程停止逻辑。
- 不改 diag JSON schema / wire format。
- 不把 diag log 接入 `EventSubmitClient`。
- 不把 diag log 接入 `AsyncEventQueue`。
- 不接入 EDR SDK。
- 不新增 dropped / timeout / diag event schema。
- 不修改 detection event JSON、transport、queue、pipe 协议。
- 不修改 Phase 2 / Phase 3 runtime、budget、normalizer、session cache。

## 3. 当前日志链路基线

当前生产路径：

```text
RaspSentryBase::Log(fmt, ...)
  -> vsnprintf_s 格式化
  -> OutputDebugStringA
  -> EnqueueLog(text)
      -> EnsureLogCsInit()
      -> m_logCs 保护 ring buffer
      -> 写 m_logQueue[m_logHead]
      -> 更新 m_logHead / m_logTail / m_logCount
      -> SetEvent(m_logEvent)
  -> LogForwardThreadProc()
      -> WaitForSingleObject(m_logEvent, 500)
      -> m_logCs 下 drain ring buffer
      -> 构造 legacy diag JSON
      -> CreateFileW("\\\\.\\pipe\\rasp_sentry_events")
      -> WriteFile(diagJson)
      -> CloseHandle(pipe)
  -> Shutdown()
      -> m_logThreadAlive = false
      -> SetEvent(m_logEvent)
      -> WaitForSingleObject(m_logThread, 3000)
      -> CloseHandle(m_logThread)
```

该链路目前与 `RaspSentryBase` 的规则加载、config pipe、retry thread 和 detection event 代码混在同一类中，是后续迁移到 EDR 日志系统前必须拆出的边界。

## 4. 函数级与成员变量职责表

| 函数 / 成员 | 当前职责 | 未来归属 | 本批是否改 | 风险等级 |
| --- | --- | --- | --- | --- |
| `RaspSentryBase::Log()` | 格式化日志，写 `OutputDebugStringA`，调用 `EnqueueLog()` | `DiagLogger` facade | 否 | Medium |
| `OutputDebugStringA` 调用 | 本地调试输出，当前由 `Log()` 同步调用 | `OutputDebugStringSink` / `DiagLogger` 默认 sink | 否 | Low |
| `RaspSentryBase::EnqueueLog()` | 写入 ring buffer，满时覆盖最老日志，唤醒 `m_logEvent` | `DiagRingBuffer` / `DiagLoggerRuntime` | 否 | Medium |
| `RaspSentryBase::LogForwardThreadProc()` | drain ring buffer，构造 legacy diag JSON，写 `rasp_sentry_events` pipe | `LegacyDiagLogForwarder` | 否 | High |
| `RaspSentryBase::EnsureLogCsInit()` | 初始化日志锁和日志唤醒 event | `DiagLoggerRuntime` | 否 | Medium |
| `RaspSentryBase::Shutdown()` 日志部分 | 停止日志线程，唤醒 event，有界等待并关闭 thread handle | runtime lifecycle / `DiagLoggerRuntime` | 否 | High |
| `m_logQueue` | 固定容量日志 ring buffer 存储 | `DiagRingBuffer` | 否 | Medium |
| `m_logHead` | ring buffer 写游标 | `DiagRingBuffer` | 否 | Medium |
| `m_logTail` | ring buffer 读游标 | `DiagRingBuffer` | 否 | Medium |
| `m_logCount` | ring buffer 当前计数 | `DiagRingBuffer` | 否 | Medium |
| `m_logCs` | ring buffer 临界区锁 | `DiagLoggerRuntime` | 否 | Medium |
| `m_logEvent` | 日志线程唤醒 event | `DiagLoggerRuntime` | 否 | Medium |
| `m_logCsReady` | 日志锁/event 初始化状态 | `DiagLoggerRuntime` | 否 | Low |
| `m_logThread` | legacy log forward worker thread handle | `LegacyDiagLogForwarder` | 否 | High |
| `m_logThreadAlive` | legacy log forward worker 生命周期标志 | `LegacyDiagLogForwarder` | 否 | Medium |

## 5. DiagLogger 边界

`DiagLogger` 是诊断日志 facade，未来负责：

- 接收模块内轻量诊断日志。
- 处理日志等级。
- 格式化日志记录。
- 提交给抽象 sink。
- 保留 `OutputDebugStringA` 或 ring buffer 作为可选 sink。

`DiagLogger` 禁止：

- 修改 `DetectionAction`。
- 修改 `ScanStatus`。
- 修改 `AMSI_RESULT`。
- 修改 block / audit / allow 决策。
- 读取或影响 rule match 结果。
- 调用 Lua / PCRE2。
- 读取 `RuleSnapshot`。
- 访问 `EngineRuntime` 内部锁。
- 访问 `IAmsiStream` / AMSI COM 对象。
- 同步写 EDR event bus、数据库或远程配置。

日志模块只能记录状态，不得反向影响检测结果。

## 6. IDiagLogSink 边界

当前代码中已存在 `src/rasp_rule_engine/include/diag_logger.h`，其中定义了 `DiagLogLevel` 和 `IDiagLogger` seam。B0-3-3-0 不修改该头文件，只在后续 B0-3-3-1 中评审是否保留、扩展或改名为 `IDiagLogSink`。

建议的后续窄接口语义：

```cpp
enum class DiagLogLevel {
    Debug,
    Info,
    Warning,
    Error
};

struct DiagLogRecord {
    DiagLogLevel level;
    std::string module;
    std::string message;
};

class IDiagLogSink {
public:
    virtual ~IDiagLogSink() = default;
    virtual bool TrySubmit(const DiagLogRecord& record) = 0;
};
```

接口边界：

- `IDiagLogSink` 只接收日志记录。
- `IDiagLogSink` 不理解 detection event、rule id、severity、decision、AMSI_RESULT。
- `TrySubmit()` 必须非阻塞或近似非阻塞。
- sink 不得在 Scan 热路径等待 pipe、EDR、磁盘或远程配置。

## 7. LegacyDiagLogForwarder 边界

`LegacyDiagLogForwarder` 只作为 compatibility layer，未来承接当前 `LogForwardThreadProc()` 的 legacy 转发职责。

允许：

- drain diag log。
- 构造当前 legacy diag JSON。
- 写 legacy `rasp_sentry_events` pipe。
- 保持旧字段和旧 wire format。
- 保持旧 shutdown drain 语义，直到单独评审生命周期治理。

禁止：

- 新增事件 schema。
- 新增 EDR telemetry 语义。
- 读取 `RuleSnapshot`。
- 读取 `RaspEvalResult` / `AsyncEvent`。
- 读取 `DetectionAction` / `ScanStatus`。
- 读取 Lua / PCRE2 runtime 对象。
- 影响 block / audit 决策。
- 承载 reload / unload / rule / drain-ack / config update 业务语义。
- 依赖 `EventSubmitClient` / `DetectionEventLite` / `AsyncEventQueue`。

`LegacyDiagLogForwarder` 是兼容层，不是新的日志平台。

如果 `LegacyDiagLogForwarder` 需要写 pipe，应依赖 bytes-only transport 或内部 legacy pipe adapter。该 transport 只能接收 bytes / string payload，不能理解 detection event、diag event、rule id、decision 等业务字段。

## 8. DiagLogger 与 EventSubmitClient 依赖方向

必须避免形成递归日志链：

```text
DiagLogger -> EventSubmitClient -> transport failed -> DiagLogger
```

允许依赖方向：

- `DiagLogger -> IDiagLogSink`
- `LegacyDiagLogForwarder -> Legacy pipe transport`
- 后续可选：`DiagLogger -> low-priority diag sink`

禁止依赖方向：

- `EventSubmitClient -> DiagLogger`
- `IEventTransport -> DiagLogger`
- `LegacyPipeEventTransport -> DiagLogger`
- transport 失败时在发送栈内同步递归打日志

发送失败只能返回状态或聚合计数，不能在同一发送栈内同步调用 `DiagLogger`。

## 9. EDR 日志适配待确认项

本节是后续 `EDRDiagLogSink` 的设计输入，不代表 B0-3-3-0 要接入 EDR SDK。

迁移到 EDR 日志系统前必须确认：

- EDR logger 是否线程安全。
- EDR logger 是否可能阻塞。
- EDR logger 是否允许在 AMSI Provider DLL 中调用。
- EDR logger 是否允许在 Scan 热路径调用。
- shutdown / unload / inert 期间 EDR logger 是否仍可用。
- EDR logger 队列满时的丢弃策略。
- 单条日志最大长度。
- 是否支持结构化字段。
- 是否存在递归日志风险。
- 是否需要脱敏。
- 是否禁止 payload / decoded payload / 原始脚本落日志。
- 是否需要按日志等级采样或限频。
- EDR 进程重启或日志服务不可用时的降级行为。

## 10. Shutdown / Drain / 日志线程生命周期边界

当前日志生命周期属于 `RaspSentryBase`：

- `Initialize()` 中创建 `m_logThread`。
- `LogForwardThreadProc()` 使用 `m_logThreadAlive` 控制退出。
- `Shutdown()` 设置 `m_logThreadAlive = false`。
- `Shutdown()` 通过 `SetEvent(m_logEvent)` 唤醒日志线程。
- `Shutdown()` 最多等待 `m_logThread` 约 3000ms。

B0-3-3-0 不改变上述行为。

后续拆分时必须满足：

- shutdown drain 必须有界等待。
- unload / inert 路径不得长时间等待日志 flush。
- 日志线程停止后不得访问已释放的 engine 资源。
- 日志组件不得持有 `EngineRuntime` 内部锁。
- 日志组件不得阻塞 Scan 热路径。

## 11. 静态检查计划

B0-3-3-0 只写检查计划。B0-3-3-1 再落地脚本。

`diag_logger.*` 禁止出现：

- `DetectionAction`
- `ScanStatus`
- `AMSI_RESULT`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EngineRuntime`
- `IAntimalwareStream`
- `IAmsiStream`
- `CreateFileW`
- `WriteFile`
- `WaitNamedPipeW`
- `CreateNamedPipeW`
- EDR SDK
- `SQL`
- `database`

`legacy_diag_log_forwarder.*` 禁止出现：

- `RaspEvalResult`
- `AsyncEvent`
- `DetectionEventLite`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `DetectionAction`
- `ScanStatus`
- `AMSI_RESULT`
- EDR SDK
- `SQL`
- `database`
- `Reload`
- `Unload`
- `RuleSnapshot`
- `DetectionEvent`
- `DrainAck`
- `ConfigUpdate`

`legacy_diag_log_forwarder.*` 可以使用 legacy pipe API，但只能服务 diag log forward，不得承载 reload、rule、detection 业务。

## 12. 测试计划

B0-3-3-0 不新增测试。

后续 B0-3-3-1 / B0-3-3-2 / B0-3-3-3 应逐步增加：

- `diag_logger_boundary_tests`：验证 `DiagLogger` 不依赖 detection / rule / Lua / PCRE2 对象。
- `diag_logger_tests`：验证日志等级、格式化和 sink 调用。
- `diag_ring_buffer_tests`：验证覆盖最老日志、游标更新、容量边界。
- `legacy_diag_log_forwarder_tests`：验证 legacy diag JSON 与旧行为一致。
- shutdown 测试：验证日志线程可有界退出。
- 并发测试：多线程 `Log()` 不崩、不越界。

回归验证必须继续覆盖：

- `scripts/check_rasp_sentry_base_boundaries.ps1`
- B0-2 parser 回归
- B0-3 event builder / transport 回归
- Phase 2 runtime / async queue / budget 回归
- Phase 3 normalizer / session cache 回归

## 13. 分批路线

| 批次 | 目标 | 是否改生产路径 |
| --- | --- | --- |
| B0-3-3-0 | design-only，新增本设计文档 | 否 |
| B0-3-3-1 | 新增接口头文件 + 静态检查，不改运行行为 | 否 |
| B0-3-3-2 | `Log()` / `EnqueueLog()` 薄包装设计评审 | 待评审 |
| B0-3-3-3 | `LogForwardThreadProc()` 迁移设计评审 | 待评审 |
| B0-3-3-4 | shutdown drain / log thread 生命周期治理评审 | 待评审 |

不要把 `Log()` 和 `LogForwardThreadProc()` 放在同一个实现批次里。

B0-3-3-1 只允许新增或调整接口头文件与静态检查脚本：

- 不新增 `diag_logger.cpp` 生产实现。
- 不新增 `legacy_diag_log_forwarder.cpp` 生产实现。
- 如需 fake / stub，只能用于测试 seam，不接入生产路径。
- 不修改 `Log()` / `EnqueueLog()` / `LogForwardThreadProc()` / `Shutdown()`。

## 14. 验收标准

B0-3-3-0 验收：

- `docs/phase_b0_3_3_diag_logger_design.md` 存在。
- 文档包含背景、目标、非目标。
- 文档包含当前日志链路基线。
- 文档包含函数级 + 成员变量职责表。
- 文档明确 `DiagLogger` 不参与检测决策。
- 文档明确 `EventSubmitClient` 不得反向依赖 `DiagLogger`。
- 文档明确 `LegacyDiagLogForwarder` 是 compatibility layer。
- 文档包含 EDR 日志适配待确认项。
- 文档明确 `OutputDebugStringA` 未来归属。
- 文档明确 B0-3-3-1 不包含生产实现。
- 文档明确 B0-3-3 子批次。
- 文档明确静态检查计划。
- 不修改生产代码。

## 15. 回滚策略

B0-3-3-0 只新增文档，回滚方式为删除该文档。

后续实现批次必须保持：

- `RaspSentryBase::Log()` 旧入口可回退。
- `LogForwardThreadProc()` 旧实现可回退。
- legacy diag JSON schema 可回退。
- shutdown drain 行为可回退。

## 16. 明确拒绝的做法

B0-3-3 拒绝：

1. 本批直接修改 `LogForwardThreadProc()`。
2. 本批把 diag log 接入 `EventSubmitClient`。
3. 本批把 diag log 接入 `AsyncEventQueue`。
4. 本批改变 diag JSON schema。
5. 本批改变日志线程 shutdown 行为。
6. 本批让 `DiagLogger` 读取 `RuleSnapshot` / Lua / PCRE2。
7. 本批新增 EDR SDK adapter。
8. 本批把 `LegacyDiagLogForwarder` 做成新的 event/log 上帝类。
9. 在 transport 失败路径同步递归调用 `DiagLogger`。
10. 让日志模块影响 AMSI 返回结果或检测决策。
11. 让 `LegacyDiagLogForwarder` 依赖 `EventSubmitClient` / `AsyncEventQueue` / `DetectionEventLite`。

## 17. 下一步

下一步建议进入 **B0-3-3-1** 方案评审：

- 是否复用现有 `diag_logger.h`。
- 是否新增 `diag_log_sink.h` / `legacy_diag_log_forwarder.h` 接口草案。
- 如何扩展 `check_rasp_sentry_base_boundaries.ps1`。
- 是否保持不改运行行为。

B0-3-3-1 未评审通过前，不应修改 `Log()`、`EnqueueLog()` 或 `LogForwardThreadProc()`。
