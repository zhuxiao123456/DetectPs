# Phase B0-3-3-3 LogForwardThreadProc 拆分设计

## 1. 当前阶段

当前阶段为 **B0-3-3-3b：drain helper 最小实现批次**。

本批只允许做一件事：

- 将 `LogForwardThreadProc()` 中“持有 `m_logCs` 后从 ring buffer 取一条日志”的锁内片段抽成 `PopLogEntryLocked()`。

本批不做：

- 不迁移完整 `LogForwardThreadProc()`。
- 不修改外层 `WaitForSingleObject(self->m_logEvent, 500)`。
- 不修改 `if (!hasItem) break;`。
- 不修改 legacy diag JSON 构造。
- 不修改 `line[2048]` / `snprintf` 截断语义。
- 不修改 `CreateFileW` / `WriteFile` / `CloseHandle` pipe 写入。
- 不修改 `Shutdown()` 日志线程 drain。
- 不接 `EventSubmitClient` / `AsyncEventQueue` / EDR SDK。

## 2. 现有行为基线

当前日志转发主链路：

```text
LogForwardThreadProc(param)
  -> self = static_cast<RaspSentryBase*>(param)
  -> self->m_logThreadAlive = true
  -> for (;;)
       -> WaitForSingleObject(self->m_logEvent, 500)
       -> for (;;)
            -> char entryText[1024] = {}
            -> EnterCriticalSection(&self->m_logCs)
            -> hasItem = (self->m_logCount > 0)
            -> if hasItem:
                 slot = self->m_logTail % kLogQueueCap
                 strncpy_s(entryText, sizeof(entryText),
                           self->m_logQueue[slot].text, _TRUNCATE)
                 self->m_logTail = (self->m_logTail + 1) % kLogQueueCap
                 InterlockedDecrement(&self->m_logCount)
            -> LeaveCriticalSection(&self->m_logCs)
            -> if !hasItem: break
            -> escape entryText into desc
            -> id = SentryGenerateEventId()
            -> ts = SentryUtcTimestamp()
            -> snprintf line[2048] legacy diag JSON
            -> CreateFileW("\\\\.\\pipe\\rasp_sentry_events", GENERIC_WRITE, ...)
            -> if opened:
                 WriteFile(hPipe, line, strlen(line), ...)
                 CloseHandle(hPipe)
       -> if !self->m_logThreadAlive && self->m_logCount == 0:
            break
  -> return 0
```

必须保持的旧语义：

- 每轮最多等待 `m_logEvent` 500ms。
- 每次只在锁内取一条日志。
- JSON 构造和 pipe 写入在锁外执行。
- pipe 不可用时静默丢弃。
- `WriteFile` 结果不影响日志线程继续 drain。
- 退出条件仍为 `!m_logThreadAlive && m_logCount == 0`。

## 3. 本批实现：PopLogEntryLocked

新增 helper：

```cpp
// Requires m_logCs to be held by caller.
// out must point to a writable buffer with outSize > 0.
bool RaspSentryBase::PopLogEntryLocked(char* out, size_t outSize);
```

职责：

- 只搬迁当前锁内取一条日志的逻辑。
- 保持 `m_logTail` 更新语义不变。
- 保持 `InterlockedDecrement(&m_logCount)` 不变。
- 保持 `strncpy_s(..., _TRUNCATE)` 不变。
- 空队列返回 `false`。
- 有日志返回 `true`，并把文本写入调用方缓冲区。

调用约束：

- 调用方必须已持有 `m_logCs`。
- 当前唯一调用点继续使用 `char entryText[1024]` 和 `sizeof(entryText)`。
- `out` 必须指向可写缓冲区，且 `outSize > 0`。
- 本批不新增 `nullptr` / `outSize == 0` 外部容错语义，避免行为漂移。

禁止项：

- 不调用 `SetEvent`。
- 不调用 `OutputDebugStringA`。
- 不构造 JSON。
- 不调用 `snprintf`。
- 不生成 event id / timestamp。
- 不访问 pipe。
- 不访问 `EventSubmitClient` / `AsyncEventQueue`。
- 不访问 `LegacyPipeEventTransport` / `IEventTransport`。
- 不访问 EDR / SQL / database。

## 4. LogForwardThreadProc 修改边界

第一版只允许把：

```cpp
EnterCriticalSection(&self->m_logCs);
bool hasItem = (self->m_logCount > 0);
if (hasItem) {
    ...
}
LeaveCriticalSection(&self->m_logCs);
```

替换为：

```cpp
EnterCriticalSection(&self->m_logCs);
bool hasItem = self->PopLogEntryLocked(entryText, sizeof(entryText));
LeaveCriticalSection(&self->m_logCs);
```

不得修改：

- 外层 loop。
- 内层 drain loop。
- `WaitForSingleObject(self->m_logEvent, 500)`。
- `if (!hasItem) break;`。
- legacy diag escape。
- `SentryGenerateEventId()`。
- `SentryUtcTimestamp()`。
- `char line[2048]`。
- `snprintf(line, sizeof(line), ...)`。
- `CreateFileW` / `WriteFile` / `CloseHandle`。
- shutdown 退出条件。

## 5. legacy diag JSON 基线

当前 JSON 仍由 `char line[2048]` 和 `snprintf` 生成：

```json
{
  "id": "...",
  "ts": "...",
  "sev": "info",
  "act": "audit",
  "cat": "diag",
  "mod": "ModuleName()",
  "sensor": "RaspLog",
  "rule": "",
  "desc": "escaped log text",
  "method": "",
  "url": "",
  "ip": "",
  "ua": "",
  "pattern": "LogEventPattern()",
  "payload": ""
}
```

B0-3-3-3b 不允许修改上述 wire format。

后续如果新增 `LegacyDiagJsonBuilder`，第一版也必须保持：

- 字段顺序不变。
- `sev == "info"`。
- `act == "audit"`。
- `cat == "diag"`。
- `sensor == "RaspLog"`。
- `pattern == LogEventPattern()`。
- `desc` escape 行为不变。
- 保持 `line[2048]` / `snprintf` 截断语义，不改成动态无限增长。

## 6. 后续拆分路线

### B0-3-3-3c：LegacyDiagJsonBuilder 设计 / 测试

目标是只抽 diag JSON 构造。

禁止：

- 不写 pipe。
- 不依赖 `LegacyPipeEventTransport`。
- 不依赖 `IEventTransport`。
- 不依赖 `EventSubmitClient`。
- 不依赖 `AsyncEventQueue`。

### B0-3-3-3d：LegacyDiagLogForwarder 设计 / 实现评审

目标是承接 legacy diag forward 兼容逻辑。

允许：

- 写 legacy `rasp_sentry_events` pipe。
- 保持旧字段、旧字段顺序和旧 wire format。
- pipe 不可用时静默失败。

禁止：

- 不读取 `RaspEvalResult`。
- 不读取 `AsyncEvent`。
- 不读取 `DetectionEventLite`。
- 不访问 `RuleSnapshot`。
- 不调用 Lua / PCRE2。
- 不影响 block / audit / allow。
- 不修改 `AMSI_RESULT`。
- 不接 `EventSubmitClient` / `AsyncEventQueue`。
- 不承载 reload / unload / config / drain-ack 语义。

### B0-3-3-3e：LogForwardThreadProc 薄包装接入

最后才允许让 `LogForwardThreadProc()` 委托 helper / builder / forwarder。

该阶段必须单独评审，不能和 B0-3-3-3b 合并。

## 7. 静态检查计划

`PopLogEntryLocked()` 禁止：

- `SetEvent`
- `OutputDebugStringA`
- `CreateFileW`
- `WriteFile`
- `WaitNamedPipe`
- `snprintf`
- `SentryGenerateEventId`
- `SentryUtcTimestamp`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- `IEventTransport`
- `EDR`
- `SQL`
- `database`

`LegacyDiagJsonBuilder.*` 禁止：

- `CreateFileW`
- `WriteFile`
- `WaitNamedPipe`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- `IEventTransport`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `AMSI_RESULT`
- `EDR`
- `SQL`
- `database`

## 8. 测试 / 验证计划

B0-3-3-3b 验证：

- `diag_ring_buffer_tests.exe`
- `scripts/check_rasp_sentry_base_boundaries.ps1`
- `rasp_mod_amsi.dll` Release 构建
- B0-2 parser 回归
- B0-3 event builder / transport 回归
- Phase 2 / Phase 3 回归
- `git diff --check`

后续 B0-3-3-3c 需要额外补充：

- golden diag JSON 字段顺序一致。
- `sev/info`、`act/audit`、`cat/diag`、`sensor/RaspLog` 一致。
- `pattern == LogEventPattern()`。
- `desc` escape 行为一致。
- `line[2048]` 截断语义一致。

## 9. 验收标准

B0-3-3-3b 验收：

- 设计文档存在，且状态与实现一致。
- `PopLogEntryLocked()` 已声明为 private。
- `PopLogEntryLocked()` 注明 caller 必须持有 `m_logCs`。
- `LogForwardThreadProc()` 只替换锁内取日志片段。
- `LogForwardThreadProc()` 外层循环、等待、JSON、pipe、退出条件不变。
- `PushLogEntryLocked()` 不受影响。
- `EnqueueLog()` 不受影响。
- `Shutdown()` 不受影响。
- 静态边界检查通过。

## 10. 回滚策略

如果 B0-3-3-3b 发现行为异常，回滚方式是：

- 删除 `PopLogEntryLocked()` 声明和实现。
- 恢复 `LogForwardThreadProc()` 中原锁内取日志片段。
- 保留或删除本设计文档均不影响运行行为。

回滚不涉及：

- JSON builder。
- pipe transport。
- EventSubmitClient。
- AsyncEventQueue。
- Shutdown。

## 11. 明确拒绝的做法

本批拒绝：

1. 直接重写 `LogForwardThreadProc()`。
2. 一次性同时抽 drain、JSON builder、pipe forwarder。
3. 改变 legacy diag JSON 字段或顺序。
4. 改变 `rasp_sentry_events` pipe name。
5. 改变 `WaitForSingleObject(m_logEvent, 500)`。
6. 改变 `m_logThreadAlive` / `m_logCount` 退出条件。
7. 改变 `Shutdown()` 等待日志线程方式。
8. 把 diag log 接入 detection event pipeline。
9. 接入 `EventSubmitClient` / `AsyncEventQueue`。
10. 接入 EDR SDK。

