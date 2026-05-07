# Phase B0-3-3-3c-3 LogForwardThreadProc 接入 LegacyDiagJsonBuilder 设计

## 1. 当前阶段

当前阶段为 **B0-3-3-3c-3 design-only**。

本批只设计 `LogForwardThreadProc()` 接入 `LegacyDiagJsonBuilder` 的方式，不修改生产代码。

方向：

- 只替换 `LogForwardThreadProc()` 内联 diag JSON 构造逻辑。
- 不抽 pipe forwarder。
- 不改变日志线程、等待、drain、shutdown、pipe 写入行为。

## 2. 前置状态

B0-3-3-3c-2 已完成：

- 新增 `LegacyDiagJsonBuilder`。
- 新增 `legacy_diag_json_builder_tests.cpp`。
- 固化 legacy diag JSON 字段顺序、固定字段、escape 行为和 `line[2048]` 截断语义。
- 明确 `truncated` 基于 `snprintf` 返回值判断。
- 明确 `compactJson.size() <= 2047`。
- 明确 builder 输出 **不追加末尾换行**。

必须继续保持：

- `LegacyDiagJsonBuilder` 不写 pipe。
- `LegacyDiagJsonBuilder` 不依赖 `EventSubmitClient` / `AsyncEventQueue`。
- `LegacyDiagJsonBuilder` 不依赖 `LegacyPipeEventTransport` / `IEventTransport`。
- `LegacyDiagJsonBuilder` 不依赖 `RuleSnapshot` / Lua / PCRE2 / AMSI / EDR / DB。

## 3. 当前生产路径基线

当前 `LogForwardThreadProc()` 的生产路径仍是：

```text
WaitForSingleObject(self->m_logEvent, 500)
  -> PopLogEntryLocked(entryText, sizeof(entryText))
  -> inline escape entryText to desc
  -> SentryGenerateEventId()
  -> SentryUtcTimestamp()
  -> snprintf(line[2048], legacy diag JSON)
  -> CreateFileW("\\\\.\\pipe\\rasp_sentry_events", ...)
  -> WriteFile(hPipe, line, strlen(line), ...)
  -> CloseHandle(hPipe)
```

旧 JSON format string 末尾为：

```cpp
"\"pattern\":\"%s\",\"payload\":\"\"}"
```

没有末尾 `\n`。

## 4. 本批设计目标

后续实现阶段只允许把以下片段：

```cpp
std::string desc;
for (const char* cp = entryText; *cp; ++cp) {
    ...
}

std::string id = SentryGenerateEventId();
std::string ts = SentryUtcTimestamp();

char line[2048];
snprintf(line, sizeof(line), ...);
```

替换为：

```cpp
LegacyDiagJsonBuildInput input;
input.id = SentryGenerateEventId();
input.timestamp = SentryUtcTimestamp();
input.module = self->ModuleName();
input.pattern = self->LogEventPattern();
input.message = entryText;

LegacyDiagJsonBuildResult built = LegacyDiagJsonBuilder().Build(input);
const std::string& compactJson = built.compactJson;
```

随后保持旧 pipe 写入语义：

```cpp
WriteFile(hPipe,
          compactJson.data(),
          static_cast<DWORD>(compactJson.size()),
          &written,
          nullptr);
```

注意：

- `built.truncated` 第一版不接 telemetry。
- `built.truncated` 不改变日志线程行为。
- `built.truncated` 不影响 pipe 写入。
- 本批实现不得读取或分支判断 `built.truncated`。
- 使用变量名 `compactJson`，避免和旧 `char line[2048]` 混淆。
- `compactJson.size()` 必须不超过 2047。
- `WriteFile` 必须使用 `compactJson.data()` + `static_cast<DWORD>(compactJson.size())`。
- 不得重新使用 `strlen()` 假设 C-string 语义。

## 5. 非目标

B0-3-3-3c-3 不做：

- 不新增 `LegacyDiagLogForwarder` 生产实现。
- 不抽 `CreateFileW`。
- 不抽 `WriteFile`。
- 不抽 `CloseHandle`。
- 不改 `rasp_sentry_events` pipe name。
- 不引入 `WaitNamedPipeW`。
- 不新增 retry/backoff。
- 不新增 telemetry。
- 不改 `WaitForSingleObject(self->m_logEvent, 500)`。
- 不改 `m_logThreadAlive`。
- 不改 `m_logCount` 退出条件。
- 不改 `Shutdown()`。
- 不接 `EventSubmitClient`。
- 不接 `AsyncEventQueue`。
- 不接 EDR SDK。

## 6. 等价性要求

接入后必须保持：

- raw JSON 字段顺序不变。
- raw JSON 固定字段不变。
- raw JSON 不追加末尾换行。
- `desc` escape 行为不变。
- 控制字符 escape 使用小写 hex，例如 `\u001f`。
- UTF-8 字节保留。
- 超长输出有效长度最多 2047。
- pipe 不可用时仍静默失败。
- `WriteFile` 失败仍不影响日志线程继续 drain。

## 7. 代码边界

允许修改：

- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - 仅限 `LogForwardThreadProc()` 中 JSON 构造片段。
  - 增加必要 include：`legacy_diag_json_builder.h`。

可选修改：

- `scripts/check_rasp_sentry_base_boundaries.ps1`
  - 检查 `LogForwardThreadProc()` 不再包含 inline desc escape / `snprintf(line, sizeof(line), ...)`。

禁止修改：

- `src/rasp_rule_engine/include/rasp_sentry_base.h`
- `src/rasp_rule_engine/src/legacy_diag_json_builder.cpp`
- `src/rasp_rule_engine/include/legacy_diag_json_builder.h`
- `src/rasp_rule_engine/src/legacy_pipe_event_transport.cpp`
- `src/rasp_rule_engine/src/event_submit_client.cpp`
- `src/rasp_rule_engine/src/async_event_queue.cpp`
- `Shutdown()` 相关逻辑。

## 8. 静态检查计划

后续实现后建议新增检查：

`LogForwardThreadProc()` 允许继续出现：

- `CreateFileW`
- `WriteFile`
- `CloseHandle`
- `rasp_sentry_events`

因为 pipe forwarder 不在本批范围。

`LogForwardThreadProc()` 不应再出现：

- `std::string desc`
- `for (const char* cp = entryText`
- `char esc[8]`
- `snprintf(esc`
- `char line[2048]`
- `snprintf(line, sizeof(line)`

`LegacyDiagJsonBuilder.*` 继续禁止：

- pipe API
- transport 类型
- event submit 类型
- rule / Lua / PCRE2 / AMSI 类型
- EDR / SQL / database

## 9. 测试计划

实现后必须运行：

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

- `legacy_diag_json_builder_tests.exe` 仍证明 builder 无末尾换行。
- `rasp_sentry_base.cpp` 只改 JSON 构造片段。
- `CreateFileW / WriteFile` 仍在 `LogForwardThreadProc()` 旧位置。
- `EventSubmitClient` / `AsyncEventQueue` 未被接入 diag log。
- `LogForwardThreadProc()` 外层 loop / wait / break / exit condition 不变。
- `PopLogEntryLocked()` 调用不变。
- `WriteFile` 使用 `compactJson.data()` + `compactJson.size()`。
- 不再保留 inline desc escape loop。
- 不再保留 `char line[2048]` 和 `snprintf(line, sizeof(line), ...)`。
- 未修改 `Shutdown()`。

## 10. 回滚策略

若接入后发现行为异常，回滚方式：

- 恢复 `LogForwardThreadProc()` 中 inline escape + `snprintf(line[2048])` 旧逻辑。
- 保留 `LegacyDiagJsonBuilder` 和 tests 不影响生产路径。

回滚不涉及：

- pipe forwarder。
- EventSubmitClient。
- AsyncEventQueue。
- Shutdown。

## 11. 明确拒绝的做法

本阶段拒绝：

1. 同时抽 pipe forwarder。
2. 把 diag log 接入 detection event pipeline。
3. 改 pipe name。
4. 加 `WaitNamedPipeW`。
5. 加 retry/backoff。
6. 加 telemetry。
7. 改 shutdown drain。
8. 改 JSON schema。
9. 让 builder 输出末尾换行。
10. 接 EDR SDK。

## 12. 下一步

下一步建议评审本 design-only 文档。

评审通过后，再进入 B0-3-3-3c-3 实现批次。
