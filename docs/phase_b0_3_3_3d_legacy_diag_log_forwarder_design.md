# Phase B0-3-3-3d LegacyDiagLogForwarder / Pipe Forwarder 设计

## 1. 当前阶段

当前阶段为 **B0-3-3-3d design-only**。

本批只设计 legacy diag log pipe forwarder 的拆分边界，不修改生产代码。

目标：

- 将 `LogForwardThreadProc()` 中剩余的 legacy pipe 写入逻辑规划为独立 forwarder。
- 保持现有 `rasp_sentry_events` pipe wire behavior。
- 为后续移除 `LogForwardThreadProc()` 内联 `CreateFileW / WriteFile / CloseHandle` 做准备。

本批不实现、不接入、不修改 `LogForwardThreadProc()`。

## 2. 前置状态

当前已经完成：

- B0-3-3-3b：`PopLogEntryLocked()` 抽出 ring buffer drain 锁内片段。
- B0-3-3-3c-2：`LegacyDiagJsonBuilder` 独立实现和 golden tests。
- B0-3-3-3c-3：`LogForwardThreadProc()` 使用 `LegacyDiagJsonBuilder` 构造 `compactJson`。

当前 `LogForwardThreadProc()` 仍直接负责：

```text
compactJson = LegacyDiagJsonBuilder().Build(input).compactJson
CreateFileW("\\\\.\\pipe\\rasp_sentry_events", GENERIC_WRITE, ...)
WriteFile(hPipe, compactJson.data(), compactJson.size(), ...)
CloseHandle(hPipe)
```

## 3. 非目标

B0-3-3-3d design-only 不做：

- 不新增 `legacy_diag_log_forwarder.cpp`。
- 不修改 `LogForwardThreadProc()`。
- 不替换 `CreateFileW / WriteFile / CloseHandle`。
- 不修改 `rasp_sentry_events` pipe name。
- 不引入 `WaitNamedPipeW`。
- 不引入 retry/backoff。
- 不引入 telemetry。
- 不修改 `LegacyDiagJsonBuilder`。
- 不修改 `Shutdown()`。
- 不修改 `WaitForSingleObject(self->m_logEvent, 500)`。
- 不接 `EventSubmitClient`。
- 不接 `AsyncEventQueue`。
- 不接 `LegacyPipeEventTransport`。
- 不接 EDR SDK。

## 4. 当前 pipe 写入行为基线

当前行为：

```cpp
HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events",
                           GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
if (hPipe != INVALID_HANDLE_VALUE)
{
    DWORD written = 0;
    WriteFile(hPipe,
              compactJson.data(),
              static_cast<DWORD>(compactJson.size()),
              &written,
              nullptr);
    CloseHandle(hPipe);
}
```

必须保持的旧语义：

- 只调用 `CreateFileW`，不先 `WaitNamedPipeW`。
- pipe 不存在、busy、access denied 时静默失败。
- `WriteFile` 返回值不影响日志线程继续 drain。
- 部分写入不重试。
- 不记录 telemetry。
- 不打诊断日志，避免递归日志。
- 不阻塞 Scan 热路径。
- 不改变 `compactJson` 内容。

## 5. 推荐组件边界

建议后续新增两个层次，但必须分批实现：

### 5.1 LegacyDiagPipeWriter

职责：只负责把 bytes 写入 legacy pipe。

建议接口：

```cpp
enum class LegacyDiagForwardStatus {
    Sent,
    EmptyPayload,
    PayloadTooLarge,
    PipeUnavailable,
    AccessDenied,
    WriteFailed
};

class LegacyDiagPipeWriter {
public:
    LegacyDiagForwardStatus Send(std::string_view payload) const;
};
```

允许：

- `CreateFileW`
- `WriteFile`
- `CloseHandle`
- `GetLastError`
- `std::string_view`

禁止：

- 不知道 `DiagLogRecord`。
- 不知道 `LegacyDiagJsonBuildInput`。
- 不知道 `LegacyDiagJsonBuilder`。
- 不知道 `RaspSentryBase`。
- 不知道 `EventSubmitClient` / `AsyncEventQueue`。
- 不知道 detection event DTO。
- 不知道 reload / unload / config / drain-ack。

### 5.2 LegacyDiagLogForwarder

职责：接收已经构造好的 legacy diag JSON，并委托 pipe writer。

建议接口：

```cpp
class LegacyDiagLogForwarder {
public:
    LegacyDiagForwardStatus Forward(std::string_view compactJson) const;
};
```

第一版建议让 `LegacyDiagLogForwarder` 只接受 `std::string_view compactJson`。

原因：

- 当前 `LogForwardThreadProc()` 已经通过 `LegacyDiagJsonBuilder` 得到 JSON。
- forwarder 不应理解日志字段。
- forwarder 不应重新构造 JSON。
- forwarder 不应依赖 `DiagLogRecord`，避免把日志语义和 transport 重新耦合。

现有 `ILegacyDiagLogForwarder` seam 接收 `DiagLogRecord`，可以作为未来更高层 facade seam 保留；本批不强行把它接入生产路径。

## 6. 错误语义

建议状态映射：

| Win32 / 输入情况 | LegacyDiagForwardStatus | 行为 |
|---|---|---|
| `payload.empty()` | `EmptyPayload` | 不调用 pipe |
| `payload.size() > DWORD_MAX` | `PayloadTooLarge` | 不调用 pipe |
| `CreateFileW` 成功且 `WriteFile` 完整写入 | `Sent` | 成功 |
| `CreateFileW` 返回 `ERROR_FILE_NOT_FOUND` | `PipeUnavailable` | 静默失败 |
| `CreateFileW` 返回 `ERROR_PIPE_BUSY` | `PipeUnavailable` | 静默失败 |
| `CreateFileW` 返回 `ERROR_ACCESS_DENIED` | `AccessDenied` | 静默失败 |
| `CreateFileW` 其他失败 | `PipeUnavailable` 或 `WriteFailed` | 第一版可统一失败 |
| `WriteFile` 返回失败 | `WriteFailed` | 不重试 |
| `WriteFile` 部分写入 | `WriteFailed` | 不重试 |

生产接入第一版不使用返回状态改变日志线程行为。

## 7. 与 EventSubmitClient / LegacyPipeEventTransport 的关系

B0-3-3-3d 不复用 `EventSubmitClient`。

原因：

- `EventSubmitClient` 是 detection event 边界。
- diag log 不是 detection event。
- 复用会引入递归日志和事件语义耦合风险。

B0-3-3-3d 第一版也不复用 `LegacyPipeEventTransport`。

原因：

- `LegacyPipeEventTransport` 当前服务 detection event worker-only path。
- 直接复用可能把 diag forwarder 依赖检测事件 transport 语义。
- 如果后续要抽通用 bytes-only pipe transport，必须单独设计，不应在本批顺手做。

## 8. 代码边界

后续实现阶段允许新增：

- `src/rasp_rule_engine/include/legacy_diag_pipe_writer.h`
- `src/rasp_rule_engine/src/legacy_diag_pipe_writer.cpp`
- `src/rasp_rule_engine/include/legacy_diag_log_forwarder.h` 的补充或新接口
- `src/rasp_rule_engine/src/legacy_diag_log_forwarder.cpp`
- `src/rasp_mod_amsi/tests/legacy_diag_log_forwarder_tests.cpp`

生产接入阶段允许修改：

- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - 仅限 `LogForwardThreadProc()` 中 pipe 写入片段。

禁止修改：

- `LegacyDiagJsonBuilder` 行为。
- `EventSubmitClient`。
- `AsyncEventQueue`。
- `LegacyPipeEventTransport`。
- `Shutdown()`。
- `ConfigPipeThreadProc()`。
- rule / Lua / PCRE2 相关代码。
- AMSI Provider 代码。

## 9. 静态检查计划

`legacy_diag_pipe_writer.*` 允许：

- `CreateFileW`
- `WriteFile`
- `CloseHandle`
- `GetLastError`

`legacy_diag_pipe_writer.*` 禁止：

- `RaspEvalResult`
- `AsyncEvent`
- `DetectionEventLite`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `AMSI_RESULT`
- `Reload`
- `Unload`
- `ConfigUpdate`
- `DrainAck`
- EDR SDK
- SQL / database

`legacy_diag_log_forwarder.*` 禁止：

- detection DTO
- rule runtime 类型
- Lua / PCRE2
- AMSI 类型
- EDR / SQL / database
- reload / unload / config 业务语义

生产接入后，`LogForwardThreadProc()` 不应再出现：

- `CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events"`
- `WriteFile(hPipe`
- `CloseHandle(hPipe`

但该检查只能在接入批次打开，不能阻塞 design-only。

## 10. 测试计划

后续实现应新增：

- `legacy_diag_log_forwarder_tests.cpp`

测试覆盖：

- 空 payload 不调用 writer。
- 正常 payload 调用 writer 并返回 `Sent`。
- 不修改 payload 内容。
- 不追加换行。
- `payload.size() <= 2047` 正常发送。
- 超大 payload 返回 `PayloadTooLarge`。
- fake writer 返回失败时 forwarder 不抛异常。
- pipe 不存在时真实 writer 返回非 `Sent`，且不崩溃。
- 部分写入映射为失败。

生产接入回归：

- `legacy_diag_json_builder_tests.exe`
- `diag_ring_buffer_tests.exe`
- `legacy_pipe_event_transport_tests.exe`
- `event_json_builder_tests.exe`
- `event_transport_tests.exe`
- `scripts/check_rasp_sentry_base_boundaries.ps1`
- `rasp_mod_amsi.dll` Release 构建
- B0-2 parser 回归
- Phase2 batch4 回归
- Phase3 input normalization 回归
- Phase3 session context 回归
- `git diff --check`

## 11. 分批路线

### B0-3-3-3d-0：design-only

当前文档。

### B0-3-3-3d-1：fake writer + forwarder 单测

- 新增 forwarder 接口和 fake writer。
- 不使用 Windows pipe API。
- 不接 `LogForwardThreadProc()`。

### B0-3-3-3d-2：LegacyDiagPipeWriter 实现

- 新增真实 Windows pipe writer。
- 保持旧 `CreateFileW` + `WriteFile` 行为。
- 不引入 `WaitNamedPipeW`。
- 不引入 retry/backoff。
- 不接生产路径。

### B0-3-3-3d-3：LogForwardThreadProc 接入 forwarder

- 单独评审。
- 只替换 inline pipe 写入片段。
- 不改变 builder。
- 不改变日志线程生命周期。

## 12. 回滚策略

design-only 回滚：删除本文档。

forwarder 实现回滚：

- 删除 `legacy_diag_pipe_writer.*`。
- 删除 `legacy_diag_log_forwarder.cpp`。
- 删除相关测试。
- `LogForwardThreadProc()` 保持当前 inline pipe 写入。

生产接入回滚：

- 恢复 `LogForwardThreadProc()` 内联 `CreateFileW / WriteFile / CloseHandle`。
- 保留 forwarder 实现和测试不影响生产路径。

## 13. 明确拒绝的做法

本阶段拒绝：

1. 直接实现并接入生产 pipe forwarder。
2. 复用 `EventSubmitClient`。
3. 复用 `AsyncEventQueue`。
4. 复用 detection event transport 语义。
5. 改 pipe name。
6. 加 `WaitNamedPipeW`。
7. 加 retry/backoff。
8. 加 telemetry。
9. 在失败时调用 `Log()`，导致递归日志。
10. 改 shutdown drain。
11. 接 EDR SDK。

## 14. 下一步

下一步建议评审本 design-only 文档。

评审通过后，再进入 **B0-3-3-3d-1：fake writer + forwarder 单测设计 / 实现评审**。

