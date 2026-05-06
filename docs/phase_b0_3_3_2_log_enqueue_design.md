# Phase B0-3-3-2 Log / EnqueueLog 薄包装设计

## 1. 背景与目标

B0-3-3-1 已经新增日志接口 seam 和静态边界检查，但 `RaspSentryBase::Log()` / `RaspSentryBase::EnqueueLog()` 仍然直接承载日志格式化、本地调试输出、ring buffer 写入和日志线程唤醒逻辑。

B0-3-3-2 的目标是先设计 `Log()` / `EnqueueLog()` 的未来薄包装方案，并把 `DiagRingBuffer`、`DiagLoggerRuntime` 的职责边界拆清楚。

当前阶段为 **B0-3-3-2a design-only**：

- 只新增本设计文档。
- 不修改 `Log()`。
- 不修改 `EnqueueLog()`。
- 不修改 `LogForwardThreadProc()`。
- 不修改 `Shutdown()`。
- 不新增生产代码。

## 2. 非目标

B0-3-3-2a 不做：

- 不新增 `diag_ring_buffer.h`。
- 不新增 `diag_logger_runtime.h`。
- 不新增 `diag_ring_buffer.cpp`。
- 不新增 `diag_logger_runtime.cpp`。
- 不改 `RaspSentryBase` 生产路径。
- 不改 `OutputDebugStringA` 调用时机。
- 不改 ring buffer 容量、字段长度、覆盖策略。
- 不改 `m_logEvent` 唤醒方式。
- 不改日志线程 shutdown drain。
- 不改 legacy diag JSON。
- 不改 legacy pipe 写入。
- 不接 `EventSubmitClient`。
- 不接 `AsyncEventQueue`。
- 不接 EDR SDK。

## 3. 子批次规划

| 批次 | 目标 | 是否改生产路径 |
| --- | --- | --- |
| B0-3-3-2a | design-only，设计 `Log()` / `EnqueueLog()` 薄包装和 ring buffer/runtime 边界 | 否 |
| B0-3-3-2b | 接口 / 测试 seam，可新增 `diag_ring_buffer.h`、`diag_logger_runtime.h`、纯 ring buffer 单测 | 否 |
| B0-3-3-2c | `Log()` / `EnqueueLog()` 薄包装接入 | 待单独评审 |

禁止把“新增 ring buffer 类型”和“接入 `RaspSentryBase::Log()`”放在同一批。

## 4. Log() 当前行为基线

当前 `RaspSentryBase::Log()` 的旧行为：

```text
RaspSentryBase::Log(fmt, ...)
  -> char buf[1024]
  -> vsnprintf_s(buf, fmt, args)
  -> 如果格式化结果超过缓冲区，尾部写入 "...<truncated>"
  -> 如果 buf 末尾没有 '\n' 且空间足够，则追加 '\n'
  -> OutputDebugStringA(buf)
  -> EnqueueLog(buf)
```

未来薄包装必须保持：

- `Log()` 使用 1024 字节本地缓冲。
- `vsnprintf` 超出缓冲区时，尾部写入 `"...<truncated>"`。
- 如果末尾无换行且仍有空间，追加 `'\n'`。
- 格式化语义不变。
- `OutputDebugStringA(buf)` 仍在同步路径调用。
- 不新增第二次 `OutputDebugStringA("\n")` 调用。
- `OutputDebugStringA` 仍先于 ring buffer 入队，避免调试输出时序变化。
- `EnqueueLog(buf)` 语义不变。

第一版不把 `OutputDebugStringA` 改成异步 sink。

## 5. EnqueueLog() 当前行为基线

当前 `RaspSentryBase::EnqueueLog()` 的旧行为：

```text
EnqueueLog(text)
  -> EnsureLogCsInit()
  -> EnterCriticalSection(&m_logCs)
  -> if m_logCount >= kLogQueueCap:
         m_logTail = (m_logTail + 1) % kLogQueueCap
     else:
         InterlockedIncrement(&m_logCount)
  -> slot = m_logHead % kLogQueueCap
  -> strncpy_s(m_logQueue[slot].text, sizeof(...), text, _TRUNCATE)
  -> m_logHead = (m_logHead + 1) % kLogQueueCap
  -> LeaveCriticalSection(&m_logCs)
  -> if m_logEvent: SetEvent(m_logEvent)
```

未来薄包装必须保持：

- `EnsureLogCsInit()` 调用语义不变。
- `m_logCs` 保护范围不扩大到 pipe、EDR、磁盘或远程调用。
- 满队列时覆盖最老日志。
- 未满队列时递增 `m_logCount`。
- 单条日志使用 `_TRUNCATE` 截断。
- 写入后更新 `m_logHead`。
- 离开锁后触发 `m_logEvent`。
- `SetEvent()` 不移动到锁内。

## 6. DiagRingBuffer 边界

`DiagRingBuffer` 未来只负责日志 ring buffer 数据结构。

允许：

- 固定容量队列。
- 写入日志文本。
- 满时覆盖最老日志。
- `Pop()` / `Drain()`。
- `head` / `tail` / `count`。
- 单条日志截断。
- 第一版容量必须与现有 `kLogQueueCap` 保持一致。
- 第一版单条 slot 长度必须与现有 `m_logQueue[slot].text` 保持一致。

禁止：

- `CreateEventW`
- `SetEvent`
- `WaitForSingleObject`
- `CRITICAL_SECTION` 生命周期
- `OutputDebugStringA`
- `LogForwardThreadProc`
- pipe 写入
- shutdown drain
- EDR / SQL / database
- `DetectionAction`
- `ScanStatus`
- `AMSI_RESULT`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EventSubmitClient`
- `AsyncEventQueue`

`DiagRingBuffer` 是数据结构，不是 runtime。

## 7. DiagLoggerRuntime 边界

`DiagLoggerRuntime` 未来只负责日志 runtime 的最小协调。

允许：

- 初始化日志锁。
- 初始化日志唤醒 event。
- 提供线程安全 enqueue 包装。
- 写入 `DiagRingBuffer`。
- 触发 wake event。
- 暴露 shutdown drain 所需的最小状态。

禁止：

- 构造 diag JSON。
- 写 pipe。
- 接 EDR SDK。
- 读取 detection event。
- 读取 rule snapshot。
- 调用 Lua / PCRE2。
- 访问 AMSI stream。
- 修改 `AMSI_RESULT`。
- 依赖 `EventSubmitClient`。
- 依赖 `AsyncEventQueue`。
- 管理 `LogForwardThreadProc()` 业务逻辑。

`DiagLoggerRuntime` 不应变成新的 mini-`RaspSentryBase`。

## 8. OutputDebugStringA 行为保持

B0-3-3-2 后续实现时建议保持旧顺序：

```text
format
  -> 如果需要，向 buf 追加 '\n'
  -> OutputDebugStringA(buf)
  -> EnqueueLog(buf)
```

原因：

- 避免本地调试输出时序变化。
- 避免把调试输出隐藏到异步队列中。
- 避免在第一版引入 OutputDebugString sink 调度语义。
- 避免把旧的单次 `OutputDebugStringA(buf)` 改成两次输出调用。

后续如果需要 `OutputDebugStringSink`，应作为独立评审项。

## 9. 线程唤醒与 Shutdown 不改声明

B0-3-3-2 不修改：

- `m_logEvent` 类型和创建方式。
- `SetEvent(m_logEvent)` 触发时机。
- `LogForwardThreadProc()` 的 `WaitForSingleObject(m_logEvent, 500)` 行为。
- `m_logThreadAlive` 控制逻辑。
- `Shutdown()` 中 `m_logThreadAlive = false`。
- `Shutdown()` 中 `SetEvent(m_logEvent)`。
- `Shutdown()` 中 `WaitForSingleObject(m_logThread, 3000)`。

日志线程生命周期治理属于 B0-3-3-4，不属于 B0-3-3-2。

## 10. 测试计划

B0-3-3-2a 不新增测试。

B0-3-3-2b 建议新增纯 `DiagRingBuffer` 单测：

- 写入未满时 `count` 增加。
- 写满后继续写，覆盖最老日志。
- `head` / `tail` 正确移动。
- 单条日志超过 slot 长度时截断。
- 第一版容量与 slot 长度保持现有 `kLogQueueCap = 256`、`LogEntry::text[1024]` 语义。
- `Pop()` 顺序正确。
- `Drain()` 顺序正确。
- 空 buffer `Pop()` 返回 false。
- 多次覆盖后 `count` 不超过容量。

B0-3-3-2c 接入 `RaspSentryBase` 时至少验证：

- `Log()` 调用后 ring buffer 有记录。
- 满队列覆盖最老。
- `SetEvent` 被触发。
- `OutputDebugStringA` 调用顺序不变。
- `LogForwardThreadProc()` 行为不变。

## 11. 静态检查计划

B0-3-3-2a 只写检查计划。

`diag_ring_buffer.*` 禁止：

- `CreateFileW`
- `WriteFile`
- `WaitNamedPipeW`
- `CreateNamedPipeW`
- `ConnectNamedPipe`
- `OutputDebugStringA`
- EDR
- SQL
- database
- `DetectionAction`
- `ScanStatus`
- `AMSI_RESULT`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EventSubmitClient`
- `AsyncEventQueue`

`diag_logger_runtime.*` 禁止：

- pipe API
- EDR SDK
- SQL
- database
- `DetectionAction`
- `ScanStatus`
- `AMSI_RESULT`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `RaspLuaEngine`
- `EventSubmitClient`
- `AsyncEventQueue`
- diag JSON

`legacy_diag_log_forwarder.*` 仍保持接口阶段禁止 pipe API。真实 pipe API 只能在后续 forwarder 实现批次单独评审。

## 12. 回滚策略

B0-3-3-2a 只新增文档，回滚方式为删除该文档。

B0-3-3-2b 如只新增接口和纯测试，可直接删除新增文件回退。

B0-3-3-2c 接入时必须保留：

- `RaspSentryBase::Log()` 旧入口。
- `RaspSentryBase::EnqueueLog()` 旧入口。
- 旧 ring buffer 成员可回退。
- `LogForwardThreadProc()` 旧行为不变。

## 13. 明确拒绝的做法

B0-3-3-2 拒绝：

1. B0-3-3-2a 修改任何生产代码。
2. B0-3-3-2b 接入 `RaspSentryBase` 生产路径。
3. 把 `Log()` 和 `LogForwardThreadProc()` 放在同一个实现批次。
4. 在 `DiagRingBuffer` 中创建或等待 event。
5. 在 `DiagRingBuffer` 中写 pipe。
6. 在 `DiagLoggerRuntime` 中构造 diag JSON。
7. 在 `DiagLoggerRuntime` 中依赖 `EventSubmitClient` / `AsyncEventQueue`。
8. 改变 `OutputDebugStringA` 同步调用顺序。
9. 改变 `m_logEvent` 唤醒语义。
10. 改变 shutdown drain 行为。

## 14. 下一步

下一步建议进入 **B0-3-3-2b 方案评审**：

- 是否新增 `diag_ring_buffer.h`。
- 是否新增 `diag_logger_runtime.h`。
- 是否新增纯 `DiagRingBuffer` 单测。
- 是否继续保持不接 `RaspSentryBase` 生产路径。

B0-3-3-2b 未评审通过前，不应修改 `Log()`、`EnqueueLog()` 或 `LogForwardThreadProc()`。
