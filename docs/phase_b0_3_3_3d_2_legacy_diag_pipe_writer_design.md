# Phase B0-3-3-3d-2 LegacyDiagPipeWriter 真实 Pipe Writer 设计

## 1. 当前阶段

当前阶段为 **B0-3-3-3d-2 design-only**。

本批只设计真实 legacy diag pipe writer，不修改生产代码，不接入 `LogForwardThreadProc()`。

目标：

- 为 `LegacyDiagLogForwarder` 提供一个真实 Win32 pipe writer 实现方案。
- 保持当前 `LogForwardThreadProc()` 的 legacy pipe 行为等价。
- 为后续 B0-3-3-3d-3 生产接入做准备。

## 2. 前置状态

B0-3-3-3d-1 已完成：

- `LegacyDiagForwardStatus`
- `ILegacyDiagBytesWriter`
- `LegacyDiagLogForwarder`
- fake writer 单测

当前 forwarder 仍未接生产路径。

当前 `LogForwardThreadProc()` 仍直接执行：

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

## 3. 非目标

B0-3-3-3d-2 不做：

- 不修改 `rasp_sentry_base.cpp`。
- 不修改 `LogForwardThreadProc()`。
- 不接入 `LegacyDiagLogForwarder`。
- 不修改 `LegacyDiagJsonBuilder`。
- 不修改 `EventSubmitClient`。
- 不修改 `AsyncEventQueue`。
- 不修改 `LegacyPipeEventTransport`。
- 不接 EDR SDK。
- 不新增 retry/backoff。
- 不新增 `WaitNamedPipeW`。
- 不新增 telemetry。
- 不调用 `Log()`。
- 不修改 shutdown drain。

## 4. 推荐文件

后续实现阶段建议新增：

- `src/rasp_rule_engine/include/legacy_diag_pipe_writer.h`
- `src/rasp_rule_engine/src/legacy_diag_pipe_writer.cpp`
- `src/rasp_mod_amsi/tests/legacy_diag_pipe_writer_tests.cpp`

可选修改：

- `src/rasp_rule_engine/CMakeLists.txt`
- `src/rasp_mod_amsi/CMakeLists.txt`
- `scripts/check_rasp_sentry_base_boundaries.ps1`

## 5. 推荐接口

```cpp
#pragma once

#include "legacy_diag_log_forwarder.h"

#include <string_view>

class LegacyDiagPipeWriter final : public ILegacyDiagBytesWriter {
public:
    LegacyDiagForwardStatus Send(std::string_view payload) override;
};
```

设计约束：

- `LegacyDiagPipeWriter` 是 bytes-only writer。
- 输入只接收 `std::string_view payload`。
- 不接收 `DiagLogRecord`。
- 不接收 `LegacyDiagJsonBuildInput`。
- 不构造 JSON。
- 不追加换行。
- 不修改 payload。
- 不理解 detection event。

## 6. 行为等价要求

第一版必须保持旧行为：

- 使用 `CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr)`。
- 不调用 `WaitNamedPipeW`。
- 不 retry。
- 不 backoff。
- 不 telemetry。
- 不调用 `Log()`。
- 成功打开 pipe 后调用一次 `WriteFile`。
- `WriteFile` 使用 `payload.data()` 和 `static_cast<DWORD>(payload.size())`。
- 写入完成后 `CloseHandle`。
- 不在 writer 内追加 `\n`。

## 7. 状态映射

建议映射：

| 情况 | LegacyDiagForwardStatus |
|---|---|
| `payload.empty()` | `EmptyPayload` |
| `payload.size() > uint32_t::max()` | `PayloadTooLarge` |
| `CreateFileW` 成功且 `WriteFile` 完整写入 | `Sent` |
| `CreateFileW` 返回 `ERROR_ACCESS_DENIED` | `AccessDenied` |
| `CreateFileW` 返回 `ERROR_FILE_NOT_FOUND` | `PipeUnavailable` |
| `CreateFileW` 返回 `ERROR_PIPE_BUSY` | `PipeUnavailable` |
| `CreateFileW` 其他失败 | `PipeUnavailable` |
| `WriteFile` 返回失败 | `WriteFailed` |
| `WriteFile` 部分写入 | `WriteFailed` |

说明：

- 当前生产路径忽略 `WriteFile` 结果；writer 可以更准确返回状态，但后续接入第一版不得用该状态改变日志线程行为。
- `PayloadTooLarge` 分支可实现，但不要求单测构造 `DWORD_MAX + 1` payload。

## 8. 头文件依赖边界

`legacy_diag_pipe_writer.h` 禁止包含：

- `windows.h`
- `sddl.h`
- `objbase.h`
- `amsi.h`
- `diag_log_sink.h`
- `event_submit_client.h`
- `async_event_queue.h`
- `legacy_pipe_event_transport.h`
- EDR SDK
- DB / SQL 头文件

Win32 API 只能出现在 `.cpp`。

## 9. 实现依赖边界

`legacy_diag_pipe_writer.cpp` 允许：

- `windows.h`
- `CreateFileW`
- `WriteFile`
- `CloseHandle`
- `GetLastError`

禁止：

- `WaitNamedPipeW`
- `CreateNamedPipeW`
- `ConnectNamedPipe`
- `Log(`
- `OutputDebugStringA`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- `LegacyDiagJsonBuilder`
- `DiagLogRecord`
- `RaspEvalResult`
- `AsyncEvent`
- `DetectionEventLite`
- `RuleSnapshot`
- Lua / PCRE2
- AMSI types
- EDR SDK
- DB / SQL
- reload / unload / config / drain-ack 业务语义

## 10. 测试计划

后续实现阶段新增：

- `legacy_diag_pipe_writer_tests.cpp`

建议测试：

1. 空 payload：
   - 返回 `EmptyPayload`。
   - 不尝试打开 pipe。

2. 不存在 pipe：
   - 使用默认 pipe name。
   - 返回非 `Sent`，推荐 `PipeUnavailable`。
   - 不崩溃。

3. payload 不追加换行：
   - 可通过 fake lower-level seam 测试；如果第一版不引入 seam，则由 forwarder/builder 测试覆盖。

4. 状态映射 helper：
   - `ERROR_ACCESS_DENIED -> AccessDenied`
   - `ERROR_FILE_NOT_FOUND -> PipeUnavailable`
   - `ERROR_PIPE_BUSY -> PipeUnavailable`
   - 完整写入 -> Sent
   - 部分写入 -> WriteFailed
   - 写失败 -> WriteFailed

说明：

- 如果为了测试状态映射引入 helper，helper 必须是纯函数，不接生产路径。
- 不要求创建真实 named pipe server。
- 不要求测试 `PayloadTooLarge` 分支构造超大字符串。

## 11. 静态检查计划

后续实现时扩展：

`legacy_diag_pipe_writer.h` 禁止：

- `windows.h`
- `HANDLE`
- `CreateFileW`
- `WriteFile`
- `CloseHandle`
- `GetLastError`
- `WaitNamedPipe`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- EDR / SQL / database

`legacy_diag_pipe_writer.cpp` 禁止：

- `WaitNamedPipe`
- `CreateNamedPipe`
- `ConnectNamedPipe`
- `Log(`
- `OutputDebugStringA`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- `LegacyDiagJsonBuilder`
- `RuleSnapshot`
- `lua_State`
- `pcre2`
- `AMSI_RESULT`
- EDR / SQL / database
- `Reload`
- `Unload`
- `ConfigUpdate`
- `DrainAck`

## 12. 验收标准

B0-3-3-3d-2 实现验收：

- `legacy_diag_pipe_writer.h/.cpp` 存在。
- `legacy_diag_pipe_writer_tests.exe` 通过。
- `legacy_diag_log_forwarder_tests.exe` 继续通过。
- `legacy_diag_json_builder_tests.exe` 继续通过。
- `scripts/check_rasp_sentry_base_boundaries.ps1` 通过。
- `rasp_mod_amsi.dll` Release 构建通过。
- `git diff --check` 通过。
- `rasp_sentry_base.cpp` 无 diff。
- `LogForwardThreadProc()` 无 diff。

## 13. 回滚策略

实现批次回滚：

- 删除 `legacy_diag_pipe_writer.h/.cpp`。
- 删除 `legacy_diag_pipe_writer_tests.cpp`。
- 删除 CMake 注册。
- 删除边界检查新增项。

由于不接生产路径，回滚不影响 `LogForwardThreadProc()`。

## 14. 明确拒绝的做法

本阶段拒绝：

1. 直接接入 `LogForwardThreadProc()`。
2. 抽完整 diag forwarder 生产路径。
3. 增加 `WaitNamedPipeW`。
4. 增加 retry/backoff。
5. 增加 telemetry。
6. 调用 `Log()`。
7. 复用 `EventSubmitClient`。
8. 复用 `AsyncEventQueue`。
9. 复用 `LegacyPipeEventTransport`。
10. 接 EDR SDK。

## 15. 下一步

下一步建议评审本 design-only 文档。

评审通过后，再进入 **B0-3-3-3d-2 LegacyDiagPipeWriter 实现批次**。

