# Phase B0-3-3-3c LegacyDiagJsonBuilder 设计

## 1. 当前阶段

当前阶段为 **B0-3-3-3c-2：LegacyDiagJsonBuilder 独立实现批次**。

本批目标是实现 legacy diag JSON 构造逻辑的独立 builder 和 golden tests，为后续把 `LogForwardThreadProc()` 中的 inline escape / `snprintf(line[2048])` 迁出做准备。

本批已经新增：

- `legacy_diag_json_builder.h`
- `legacy_diag_json_builder.cpp`
- `legacy_diag_json_builder_tests.cpp`

本批仍未接入 `LogForwardThreadProc()` 生产路径。

## 2. 背景

B0-3-3-3b 已经把 `LogForwardThreadProc()` 中的锁内 drain 逻辑抽成 `PopLogEntryLocked()`。当前 `LogForwardThreadProc()` 仍直接负责：

- 从 `entryText` 构造 escaped `desc`。
- 生成 legacy diag event id。
- 生成 UTC timestamp。
- 使用 `char line[2048]` 和 `snprintf` 构造 JSON。
- 写入 legacy `rasp_sentry_events` pipe。

B0-3-3-3c 只规划其中 **legacy diag JSON 构造** 的抽离，不处理 pipe forwarder。

## 3. 非目标

B0-3-3-3c 不做：

- 不修改 `LogForwardThreadProc()`。
- 不修改 `CreateFileW` / `WriteFile` / `CloseHandle`。
- 不修改 `rasp_sentry_events` pipe name。
- 不修改 `WaitForSingleObject(self->m_logEvent, 500)`。
- 不修改 `Shutdown()`。
- 不接 `EventSubmitClient`。
- 不接 `AsyncEventQueue`。
- 不接 `LegacyPipeEventTransport` 或 `IEventTransport`。
- 不接 EDR SDK。
- 不修改 diag JSON schema。
- 不修改字段顺序。
- 不把 `line[2048]` 截断语义改成无限动态字符串。

## 4. 当前 legacy diag JSON 基线

当前 JSON 在 `LogForwardThreadProc()` 内使用 `char line[2048]` 和 `snprintf` 构造。

字段顺序必须保持：

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

固定字段：

- `sev` 固定为 `"info"`。
- `act` 固定为 `"audit"`。
- `cat` 固定为 `"diag"`。
- `sensor` 固定为 `"RaspLog"`。
- `rule` 固定为空字符串。
- `method` 固定为空字符串。
- `url` 固定为空字符串。
- `ip` 固定为空字符串。
- `ua` 固定为空字符串。
- `payload` 固定为空字符串。

动态字段：

- `id` 来自当前 `SentryGenerateEventId()`。
- `ts` 来自当前 `SentryUtcTimestamp()`。
- `mod` 来自 `ModuleName()`。
- `desc` 来自日志文本 escape 后结果。
- `pattern` 来自 `LogEventPattern()`。

## 5. 当前 escape 语义

当前 `desc` escape 行为必须 golden 固化。

已知行为：

- `"` 转义为 `\"`。
- `\` 转义为 `\\`。
- `\n` 转义为 `\n`。
- `\r` 转义为 `\r`。
- `\t` 转义为 `\t`。
- ASCII 控制字符 `< 0x20` 转义为 `\u00xx`。
- 其他字符原样追加。

B0-3-3-3c 后续实现不得顺手替换为新 JSON 库或复用 detection event 的 `EventJsonBuilder`，除非先证明 raw string 与旧行为完全兼容。

## 6. 截断和 snprintf 语义

当前输出使用：

```cpp
char line[2048];
snprintf(line, sizeof(line), ...);
```

后续 `LegacyDiagJsonBuilder` 第一版必须保持此语义：

- 单行输出上限仍由 `line[2048]` 等价控制。
- `snprintf` 截断行为不变。
- 不改成无限增长 JSON 字符串。
- 不新增字段级 payload 落日志。
- 不打印完整检测样本。

`LegacyDiagJsonBuildResult::truncated` 的建议语义：

- `truncated == true`：`snprintf` 返回值 `>= sizeof(line)`。
- `truncated == false`：`snprintf` 返回值 `>= 0` 且 `< sizeof(line)`。
- `snprintf` 返回值 `< 0`：第一版不新增复杂外部失败语义。实现可将其视为构造失败或截断类异常，但不得改变旧生产路径的外部行为；测试重点先覆盖正常构造和正常截断场景。

说明：

- 旧 inline 路径没有显式检查 `snprintf` 返回值。
- B0-3-3-3c-2 不新增复杂失败处理代码。
- 如果后续 builder 需要暴露 `failed` 字段，必须单独 review，不能混入第一版 builder 抽离。

## 7. 推荐接口草案

后续实现可新增：

```cpp
struct LegacyDiagJsonBuildInput {
    std::string id;
    std::string timestamp;
    std::string module;
    std::string pattern;
    std::string message;
};

struct LegacyDiagJsonBuildResult {
    std::string compactJson;
    bool truncated = false;
};

class LegacyDiagJsonBuilder {
public:
    LegacyDiagJsonBuildResult Build(const LegacyDiagJsonBuildInput& input) const;
};
```

接口约束：

- Builder 只负责 JSON 字符串构造。
- Builder 不生成 id。
- Builder 不读取系统时间。
- Builder 不调用 `ModuleName()`。
- Builder 不调用 `LogEventPattern()`。
- Builder 不写 pipe。
- Builder 不访问日志 ring buffer。
- Builder 不访问 `RaspSentryBase` 内部锁。

调用方负责提供 `id / timestamp / module / pattern / message`。

## 8. 禁止依赖

`LegacyDiagJsonBuilder.*` 禁止依赖：

- `CreateFileW`
- `WriteFile`
- `WaitNamedPipe`
- `CloseHandle`
- `EventSubmitClient`
- `AsyncEventQueue`
- `LegacyPipeEventTransport`
- `IEventTransport`
- `RuleSnapshot`
- `RaspEvalResult`
- `AsyncEvent`
- `DetectionEventLite`
- `lua_State`
- `pcre2`
- `AMSI_RESULT`
- EDR SDK
- SQL / database

这条边界的原因是：diag JSON builder 是纯格式化组件，不能知道 transport、检测事件、规则引擎或平台落库语义。

## 9. 与 EventJsonBuilder 的关系

`LegacyDiagJsonBuilder` 不应复用 detection event 的 `EventJsonBuilder` 生产路径。

原因：

- detection event 与 diag event 的字段语义不同。
- detection event 已有 payload / pattern / action / severity 兼容逻辑。
- diag event 当前是 legacy JSONL wire format，必须按旧字段顺序和旧默认值保持兼容。

如未来要统一 JSON escape 工具，只能抽纯字符串 escape helper，且必须单独 review。

## 10. Golden fixture 策略

实现前必须先固化 golden fixture。

所有 golden fixture 必须使用固定输入，避免 flaky test：

- `id = "fixed-id"`
- `timestamp = "2026-01-02T03:04:05.006Z"`
- `module = "fixed-module"`
- `pattern = "fixed-pattern"`

建议用当前旧路径生成或人工锁定以下样例：

1. 普通日志：
   - `message = "hello world"`
   - 验证所有固定字段和字段顺序。

2. 特殊字符：
   - `message` 包含 `"`, `\`, `\n`, `\r`, `\t`
   - 验证 escape 字符串与旧路径一致。

3. 控制字符：
   - `message` 包含 `0x01`, `0x1f`
   - 验证 `\u00xx` 输出一致。

4. Unicode 文本：
   - `message` 包含中文或其他 UTF-8 字符
   - 验证旧路径原样保留 UTF-8 字节，不做额外编码变换。

5. 超长日志：
   - `message` 足够长，使 `line[2048]` 触发截断
   - 验证第一版 builder 保持等价截断语义。
   - 验证 `truncated == true`。

6. 空 message：
   - `desc` 为空字符串
   - 验证 JSON 仍合法。

## 11. Canonical / Raw 比较策略

验收必须分两层：

- 语义一致：解析为 JSON object 后字段值一致。
- 兼容一致：raw JSON string 的字段顺序、固定字段、转义和截断行为一致。

由于 legacy 消费方可能依赖 JSONL 原始格式，本阶段不能只做 canonical object 比较。

## 12. 测试计划

当前实现阶段已新增：

- `legacy_diag_json_builder_tests.cpp`

测试覆盖：

- 固定字段值。
- 字段顺序。
- `desc` escape。
- 控制字符 escape。
- Unicode 字符保留。
- `line[2048]` 等价截断。
- `truncated` 判定。
- 空 message。
- builder 不生成 id / timestamp。

测试门槛：

- 新 builder 输出与 golden raw JSON 一致，或在文档中明确记录 raw 差异并获得单独 review。
- 不新增 event schema。
- 不修改 production `LogForwardThreadProc()`，直到 builder 单测稳定。

## 13. 分阶段实施建议

### B0-3-3-3c-0：design-only

当前文档。

### B0-3-3-3c-1：golden fixture / 测试设计

- 固化当前 diag JSON 字段清单。
- 固化 escape 行为。
- 固化 `line[2048]` 截断行为。
- 固定 `id / timestamp / module / pattern` 测试输入。
- 写测试，但不接生产路径。

### B0-3-3-3c-2：LegacyDiagJsonBuilder 实现

- 新增 builder。
- 不写 pipe。
- 不访问 `RaspSentryBase`。
- 不接 `LogForwardThreadProc()`。

### B0-3-3-3c-3：LogForwardThreadProc 调用 builder

- 单独评审。
- 仅替换 inline JSON escape / snprintf。
- 不迁移 pipe forwarder。

## 14. 静态检查计划

当前边界脚本应检查 `legacy_diag_json_builder.*` 不出现：

- pipe API
- transport 类型
- event submit 类型
- rule / Lua / PCRE2 / AMSI 类型
- EDR / SQL / database

同时不应误伤 `LogForwardThreadProc()` 当前 legacy pipe 写入，因为 pipe forwarder 迁移不属于 B0-3-3-3c。

## 15. 回滚策略

B0-3-3-3c design-only 回滚方式是删除本文档。

当前 builder 实现批次回滚方式：

- 删除 `legacy_diag_json_builder.*`。
- 删除 builder 单测。
- `LogForwardThreadProc()` 继续使用旧 inline JSON 构造。

如果后续已接入生产路径，则回滚为恢复 inline escape / `snprintf(line[2048])` 旧逻辑。

## 16. 明确拒绝的做法

本阶段拒绝：

1. 直接修改 `LogForwardThreadProc()`。
2. 顺手改 pipe forwarder。
3. 复用 detection event JSON builder 改写 diag schema。
4. 用新 JSON 库改变字段顺序或 escape 行为。
5. 改 `line[2048]` 截断语义。
6. 将 diag log 接入 `EventSubmitClient`。
7. 将 diag log 接入 `AsyncEventQueue`。
8. 在 builder 中写 pipe。
9. 在 builder 中生成 id / timestamp。
10. 接入 EDR SDK。

## 17. 下一步

下一步建议评审当前 builder 独立实现批次。

评审通过后，再进入 **B0-3-3-3c-3：LogForwardThreadProc 调用 builder 设计评审**，不要直接抽 pipe forwarder。
