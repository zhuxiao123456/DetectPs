# Phase B0-3-3-3d-3 LogForwardThreadProc 接入 LegacyDiagLogForwarder 设计

## 1. 当前阶段

当前阶段为 **B0-3-3-3d-3 design-only**。

本批只设计 `LogForwardThreadProc()` 接入 `LegacyDiagLogForwarder + LegacyDiagPipeWriter` 的方式，不修改生产代码。

目标：

- 将 `LogForwardThreadProc()` 中内联 `CreateFileW / WriteFile / CloseHandle` pipe 写入片段替换为 forwarder 调用。
- 保持旧 `rasp_sentry_events` pipe 行为。
- 不改变日志线程生命周期、等待、drain、shutdown 行为。

## 2. 前置状态

已完成：

- B0-3-3-3b：`PopLogEntryLocked()` 抽出 ring buffer drain 锁内片段。
- B0-3-3-3c-2：`LegacyDiagJsonBuilder` 独立实现和 golden tests。
- B0-3-3-3c-3：`LogForwardThreadProc()` 使用 `LegacyDiagJsonBuilder` 构造 `compactJson`。
- B0-3-3-3d-1：`LegacyDiagLogForwarder` bytes-only seam + fake writer tests。
- B0-3-3-3d-2：`LegacyDiagPipeWriter` 真实 Win32 pipe writer + tests。

当前生产路径仍为：

```cpp
LegacyDiagJsonBuildResult built = LegacyDiagJsonBuilder().Build(input);
const std::string& compactJson = built.compactJson;

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

## 3. 非目标

B0-3-3-3d-3 不做：

- 不修改 `LegacyDiagJsonBuilder`。
- 不修改 `LegacyDiagLogForwarder` 行为。
- 不修改 `LegacyDiagPipeWriter` 行为。
- 不修改 `PopLogEntryLocked()`。
- 不修改 `WaitForSingleObject(self->m_logEvent, 500)`。
- 不修改 `m_logThreadAlive`。
- 不修改 `m_logCount` 退出条件。
- 不修改 `Shutdown()`。
- 不修改 pipe name。
- 不新增 `WaitNamedPipeW`。
- 不新增 retry/backoff。
- 不新增 telemetry。
- 不调用 `Log()`。
- 不接 `EventSubmitClient`。
- 不接 `AsyncEventQueue`。
- 不接 EDR SDK。

## 4. 推荐接入方式

后续实现阶段只允许把 pipe 写入片段：

```cpp
HANDLE hPipe = CreateFileW(...);
if (hPipe != INVALID_HANDLE_VALUE)
{
    DWORD written = 0;
    WriteFile(...);
    CloseHandle(hPipe);
}
```

替换为：

```cpp
LegacyDiagPipeWriter writer;
LegacyDiagLogForwarder forwarder(writer);
forwarder.Forward(compactJson);
```

说明：

- 第一版不读取返回状态。
- 第一版不根据返回状态打日志。
- 第一版不根据返回状态 telemetry。
- 第一版不 retry。
- 第一版不 backoff。
- 第一版不改变日志线程继续 drain 的行为。

## 5. 等价性要求

接入后必须保持：

- `compactJson` 内容不变。
- `compactJson` 不追加末尾换行。
- `compactJson.size() <= 2047`。
- pipe name 仍为 `\\.\pipe\rasp_sentry_events`。
- 仍使用 `CreateFileW + WriteFile + CloseHandle`，但通过 writer 间接执行。
- 不调用 `WaitNamedPipeW`。
- pipe 不可用时静默失败。
- `WriteFile` 失败不影响日志线程继续 drain。
- 不改变 `LogForwardThreadProc()` 外层 loop / wait / break / exit condition。
- 不改变 `PopLogEntryLocked()` 调用位置。

## 6. 代码边界

允许修改：

- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - 仅限 `LogForwardThreadProc()` 中 pipe 写入片段。
  - 增加必要 include：
    - `legacy_diag_log_forwarder.h`
    - `legacy_diag_pipe_writer.h`

可选修改：

- `scripts/check_rasp_sentry_base_boundaries.ps1`
  - 增加检查，确保 `LogForwardThreadProc()` 不再直接出现 legacy event pipe 写入 API。

禁止修改：

- `src/rasp_rule_engine/include/rasp_sentry_base.h`
- `src/rasp_rule_engine/src/legacy_diag_json_builder.cpp`
- `src/rasp_rule_engine/src/legacy_diag_log_forwarder.cpp`
- `src/rasp_rule_engine/src/legacy_diag_pipe_writer.cpp`
- `src/rasp_rule_engine/src/event_submit_client.cpp`
- `src/rasp_rule_engine/src/async_event_queue.cpp`
- `Shutdown()` 相关逻辑。

## 7. 静态检查计划

实现后建议新增：

`LogForwardThreadProc()` 不应再出现：

- `CreateFileW`
- `WriteFile`
- `CloseHandle`
- `rasp_sentry_events`
- `HANDLE hPipe`
- `DWORD written`

`LogForwardThreadProc()` 允许出现：

- `LegacyDiagJsonBuilder`
- `LegacyDiagLogForwarder`
- `LegacyDiagPipeWriter`
- `compactJson`

继续保持：

- `LegacyDiagLogForwarder.*` 不出现 Win32 pipe API。
- `LegacyDiagPipeWriter.cpp` 只允许必要 Win32 pipe API，不出现 `WaitNamedPipe` / retry / logging / event submit / EDR。

## 8. 测试计划

实现后必须运行：

- `legacy_diag_pipe_writer_tests.exe`
- `legacy_diag_log_forwarder_tests.exe`
- `legacy_diag_json_builder_tests.exe`
- `diag_ring_buffer_tests.exe`
- `event_json_builder_tests.exe`
- `event_transport_tests.exe`
- `legacy_pipe_event_transport_tests.exe`
- `scripts/check_rasp_sentry_base_boundaries.ps1`
- `rasp_mod_amsi.dll` Release 构建
- B0-2 parser 回归
- Phase2 batch4 回归
- Phase3 input normalization 回归
- Phase3 session context 回归
- `git diff --check`

重点确认：

- `rasp_sentry_base.cpp` 只改 pipe 写入片段。
- `LogForwardThreadProc()` JSON builder 调用不变。
- `LogForwardThreadProc()` drain / wait / shutdown 退出逻辑不变。
- `CreateFileW / WriteFile / CloseHandle` 不再直接出现在 `LogForwardThreadProc()`。
- `LegacyDiagPipeWriter` 仍不使用 `WaitNamedPipeW`。
- `EventSubmitClient` / `AsyncEventQueue` 未接入 diag log。

## 9. 回滚策略

如果接入后发现行为异常，回滚方式：

- 恢复 `LogForwardThreadProc()` 中内联 `CreateFileW / WriteFile / CloseHandle` 旧片段。
- 保留 `LegacyDiagLogForwarder` 和 `LegacyDiagPipeWriter` 不影响生产路径。

回滚不涉及：

- JSON builder。
- ring buffer drain。
- EventSubmitClient。
- AsyncEventQueue。
- Shutdown。

## 10. 明确拒绝的做法

本阶段拒绝：

1. 修改 `LegacyDiagPipeWriter` 行为。
2. 修改 `LegacyDiagLogForwarder` 行为。
3. 改 pipe name。
4. 加 `WaitNamedPipeW`。
5. 加 retry/backoff。
6. 加 telemetry。
7. 调用 `Log()`。
8. 接 `EventSubmitClient`。
9. 接 `AsyncEventQueue`。
10. 接 EDR SDK。
11. 改 shutdown drain。
12. 改 JSON schema。

## 11. 下一步

下一步建议评审本 design-only 文档。

评审通过后，再进入 **B0-3-3-3d-3 实现批次**。

