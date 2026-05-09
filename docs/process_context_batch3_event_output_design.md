# ProcessContextProvider Batch 3：事件 JSON 输出设计

## 1. 当前阶段与目标

当前阶段为 **Batch 3 implementation**。

Batch 1 + Batch 2 已完成：
- ProcessContextProvider 独立组件（父进程 PID/名称采集、状态枚举、重试退避、不可变快照）
- ScanContext 前置声明
- AmsiRuleEngine::Evaluate ScanContext overload
- Lua/Regex 上下文注入 parentPid / parentProcessName / processCaptureStatus / processRetryState

Batch 3 目标：
- 将 parentPid / parentProcessName 输出到检测事件 JSON
- 不扩展 RaspEvalResult 为全量上下文容器
- 不输出路径字段
- 不输出采集状态字段

## 2. 设计原则

- RaspEvalResult 是"检测结果摘要"，不是"全量上下文快照"
- 只增加事件层实际需要的字段
- 字段先加但没有消费者 = 技术债
- 路径字段含敏感信息，默认不输出
- 采集状态字段（processCaptureStatus / processRetryState）属于诊断层，不属于事件层
- JSON 字段兼容性承诺是"字段存在且值正确"，而不是 JSON key 顺序

## 3. 修改文件清单

| 文件 | 修改内容 | 影响范围 |
|------|---------|---------|
| `src/rasp_rule_engine/include/rasp_sentry_base.h` | RaspEvalResult 增加 parentPid / parentProcessName | 共享结构体 |
| `src/rasp_rule_engine/include/event_submit_client.h` | EventJsonBuildInput 增加 parentPid / parentProcessName | 事件构造输入 |
| `src/rasp_rule_engine/src/event_submit_client.cpp` | EventJsonBuilder 输出 parent 字段 | JSON 输出格式 |
| `src/rasp_rule_engine/src/rasp_sentry_base.cpp` | TrySubmitDetectionEvent 填充 parent 字段 | 事件提交路径 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | 从 ctx.fields 提取 parent 字段填充 RaspEvalResult | 检测结果构造 |
| `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp` | 新增 parent 字段 golden 测试（CMake 路径：`tests/event_json_builder_tests.cpp`） | 测试覆盖 |

**注：** 测试文件完整路径为 `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp`，在 `src/rasp_mod_amsi/CMakeLists.txt` 中以相对路径 `tests/event_json_builder_tests.cpp` 引用。

## 4. RaspEvalResult 字段扩展

**文件：** `src/rasp_rule_engine/include/rasp_sentry_base.h`

```cpp
struct RaspEvalResult
{
    // === 现有字段（保持不变）===
    bool        matched   = false;
    bool        block     = false;
    std::string ruleId;
    std::string sensor;
    std::string desc;
    std::string payload;
    std::string severity;
    std::string contentName;
    std::string appName;
    std::string ip;
    std::string ua;
    int         confidence;

    // === Batch 3 新增：父进程摘要（只加 2 个字段）===
    uint32_t    parentPid = 0;
    std::string parentProcessName;
};
```

**明确不加的字段：**

| 字段 | 原因 |
|------|------|
| `processCaptureStatus` | 采集状态属于诊断层，不属于事件层 |
| `processRetryState` | 重试状态属于诊断层，不属于事件层 |
| `currentPid` | 事件层可通过其他途径获取，不需要在检测结果摘要中携带 |
| `currentProcessName` | 事件层已有 appName，已能满足大多数当前进程标识需求，因此 Batch 3 不额外增加 |
| `currentProcessPath` | 路径含敏感信息，默认不输出 |
| `parentProcessPath` | 路径含敏感信息，默认不输出 |

## 5. EventJsonBuildInput 字段扩展

**文件：** `src/rasp_rule_engine/include/event_submit_client.h`

```cpp
struct EventJsonBuildInput
{
    // === 现有字段（保持不变）===
    std::string eventId;
    std::string timestamp;
    std::string moduleName;
    std::string ruleId;
    std::string sensor;
    bool        block = false;
    std::string severity;
    std::string description;
    std::string appName;
    std::string contentName;
    int         confidence = 0;
    std::string ip;
    std::string ua;
    std::string payload;

    // === Batch 3 新增：父进程摘要（只加 2 个字段）===
    uint32_t    parentPid = 0;
    std::string parentProcessName;
};
```

**明确不加的字段：**

| 字段 | 原因 |
|------|------|
| `processCaptureStatus` | 事件层不需要采集状态 |
| `processRetryState` | 事件层不需要重试状态 |
| `currentProcessPath` | 路径含敏感信息，默认不输出 |
| `parentProcessPath` | 路径含敏感信息，默认不输出 |
| `emitProcessPathFields` | 不需要调试开关，因为 Batch 3 不输出路径 |

## 6. EventJsonBuilder 输出格式

**文件：** `src/rasp_rule_engine/src/event_submit_event_client.cpp`

修改 `BuildDetection()` 函数，追加 parent 字段：

```cpp
EventJsonBuildResult EventJsonBuilder::BuildDetection(const EventJsonBuildInput& input) const
{
    EventJsonBuildResult result;
    result.decision = input.block ? "block" : "audit";
    result.payload = TruncateUtf8Field(input.payload, kMaxEventPayloadFieldBytes);
    result.eventTruncated = result.payload.size() != input.payload.size();

    const std::string severity = input.severity.empty() ? "High" : input.severity;
    const std::string confidence = input.confidence ? std::to_string(input.confidence) : "70";

    std::ostringstream oss;
    oss << "{\"id\":\"" << JsonEscape(input.eventId) << "\","
        << "\"ts\":\"" << JsonEscape(input.timestamp) << "\","
        << "\"sev\":\"" << JsonEscape(severity) << "\","
        << "\"act\":\"" << JsonEscape(result.decision) << "\","
        << "\"cat\":\"Detection\","
        << "\"mod\":\"" << JsonEscape(input.moduleName) << "\","
        << "\"sensor\":\"" << JsonEscape(input.sensor) << "\","
        << "\"rule\":\"" << JsonEscape(input.ruleId) << "\","
        << "\"desc\":\"" << JsonEscape(input.description) << "\","
        << "\"appName\":\"" << JsonEscape(input.appName) << "\","
        << "\"contentName\":\"" << JsonEscape(input.contentName) << "\","
        << "\"confidence\":\"" << JsonEscape(confidence) << "\","
        << "\"ip\":\"" << JsonEscape(input.ip) << "\","
        << "\"ua\":\"" << JsonEscape(input.ua) << "\","
        << "\"pattern\":\"" << JsonEscape(result.payload) << "\","
        << "\"parentPid\":\"" << input.parentPid << "\","
        << "\"parentProcessName\":\"" << JsonEscape(input.parentProcessName) << "\"}";
    result.compactJson = oss.str();
    return result;
}
```

**实现细节（非强契约）：**

当前版本实现上把 parent 字段追加在 pattern 之后。兼容性承诺是"字段存在且值正确"，而不是 JSON key 顺序。后续调整 Builder 输出顺序不视为兼容性破坏。

**输出 JSON 格式预览：**

```json
{
  "id": "...",
  "ts": "...",
  "sev": "High",
  "act": "block",
  "cat": "Detection",
  "mod": "rasp_mod_amsi",
  "sensor": "AmsiProvider",
  "rule": "...",
  "desc": "...",
  "appName": "powershell.exe",
  "contentName": "...",
  "confidence": "70",
  "ip": "",
  "ua": "",
  "pattern": "...",
  "parentPid": "1234",
  "parentProcessName": "cmd.exe"
}
```

## 7. TrySubmitDetectionEvent 填充字段

**文件：** `src/rasp_rule_engine/src/rasp_sentry_base.cpp`

修改 `TrySubmitDetectionEvent()` 函数，只填充 2 个 parent 字段：

```cpp
EnqueueResult RaspSentryBase::TrySubmitDetectionEvent(const RaspEvalResult& result) const
{
    EventJsonBuildInput input;
    input.eventId = SentryGenerateEventId();
    input.timestamp = SentryUtcTimestamp();
    input.moduleName = ModuleName();
    input.ruleId = result.ruleId;
    input.sensor = result.sensor;
    input.block = result.block;
    input.severity = result.severity;
    input.description = result.desc;
    input.appName = result.appName;
    input.contentName = result.contentName;
    input.confidence = result.confidence;
    input.ip = result.ip;
    input.ua = result.ua;
    input.payload = result.payload;

    // === Batch 3 新增：只填充 2 个 parent 字段 ===
    input.parentPid = result.parentPid;
    input.parentProcessName = result.parentProcessName;

    EventJsonBuildResult built = EventJsonBuilder().BuildDetection(input);

    AsyncEvent event;
    event.priority = EventPriority::Detection;
    event.type = EventType::Detection;
    event.pid = GetCurrentProcessId();
    event.tid = GetCurrentThreadId();
    event.ruleId = result.ruleId;
    event.decision = built.decision;
    event.contentName = result.contentName;
    event.appName = result.appName;
    event.sampleLen = result.payload.size();
    event.reason = result.desc;
    event.eventTruncated = built.eventTruncated;
    event.compactJson = built.compactJson;
    return m_eventSink.TrySubmit(event);
}
```

## 8. AmsiRuleEngine 从 ctx.fields 提取 parent 字段

**文件：** `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

### 8.1 新增 helper：ParseUint32OrZero

为了避免在每个需要解析数字的地方重复 try-catch，新增一个本地 helper：

```cpp
namespace {

uint32_t ParseUint32OrZero(const std::string& value)
{
    try {
        return static_cast<uint32_t>(std::stoul(value));
    } catch (...) {
        return 0;
    }
}

} // namespace
```

### 8.2 Evaluate() 中一次性提取 parent 字段

在 `Evaluate(sensor, ctx)` 函数进入规则循环前，一次性提取 parent 字段：

```cpp
std::vector<RaspEvalResult> AmsiRuleEngine::Evaluate(const std::string &sensor, const RaspLuaContext &ctx)
{
    std::vector<RaspEvalResult> results;
    ScanExecutionContext exec;

    auto snap = std::atomic_load(&m_snapshot);
    if (!snap || !snap->luaEngine)
        return results;
    RaspLuaEngine& luaEngine = *snap->luaEngine;

    // === Batch 3 新增：一次性提取 parent 字段 ===
    uint32_t parentPid = 0;
    std::string parentProcessName;

    for (const auto& f : ctx.fields) {
        if (f.name == "parentPid") {
            parentPid = ParseUint32OrZero(f.value);
        } else if (f.name == "parentProcessName") {
            parentProcessName = f.value;
        }
    }

    // Extract context fields for result population
    std::string contentName;
    std::string appName;
    for (const auto& f : ctx.fields) {
        if (f.name == "contentName")
            contentName = f.value;
        else if (f.name == "appName")
            appName = f.value;
    }

    // 遍历每个规则
    for (const auto& rule : snap->rules) {
        // ... 规则匹配逻辑不变 ...

        // 正则和lua均匹配不到、放行
        if (!matched)
            continue;

        RaspEvalResult r;
        r.matched = true;
        r.block = rule.IsBlock();
        r.ruleId = rule.id;
        r.sensor = sensor;
        r.desc = desc;
        r.payload = payload;
        r.severity = rule.severity.empty() ? "High" : rule.severity;
        r.contentName = contentName;
        r.appName = appName;
        r.confidence = rule.confidence ? rule.confidence : DEFAULT_CONFIDENCE;

        // === Batch 3 新增：填充 parent 字段 ===
        r.parentPid = parentPid;
        r.parentProcessName = parentProcessName;

        TrySubmitDetectionEvent(r);
        exec.matchedBeforeTimeout = true;
        results.push_back(std::move(r));
        if (r.block) {
            break;
        }
    }

    if (exec.timedOut)
        ResolveTimeoutDecision(results, exec);
    EmitScanBudgetTelemetry(exec);
    return results;
}
```

**优化说明：**

- 不在每个命中规则里反复遍历 ctx.fields
- 在规则循环前一次性提取 parent 字段
- 使用 `ParseUint32OrZero` helper 封装异常处理，避免重复 try-catch
- 后续其他地方需要从 ctx.fields 提取数字时可直接复用该 helper

## 9. 测试方案

### 9.1 Builder golden test

**文件：** `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp`（CMake 路径：`tests/event_json_builder_tests.cpp`）

新增测试覆盖：

```cpp
// === Batch 3 新增测试 ===

{
    EventJsonBuilder builder;
    EventJsonBuildInput input = BaseInput();
    input.parentPid = 1234;
    input.parentProcessName = "cmd.exe";
    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "parent JSON parses"))
        return 1;
    if (!Expect(fields["parentPid"] == "1234", "parentPid output as string"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "cmd.exe", "parentProcessName output"))
        return 1;
}

{
    EventJsonBuilder builder;
    EventJsonBuildInput input = BaseInput();
    input.parentPid = 0;
    input.parentProcessName.clear();
    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "empty parent JSON parses"))
        return 1;
    if (!Expect(fields["parentPid"] == "0", "parentPid is 0 when empty"))
        return 1;
    if (!Expect(fields["parentProcessName"].empty(), "parentProcessName empty when not captured"))
        return 1;
}

{
    EventJsonBuilder builder;
    EventJsonBuildInput input = BaseInput();
    input.parentPid = 4;
    input.parentProcessName = "System";
    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "System parent JSON parses"))
        return 1;
    if (!Expect(fields["parentPid"] == "4", "System parentPid is 4"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "System", "System parent name is stable sentinel"))
        return 1;
}

{
    EventJsonBuilder builder;
    EventJsonBuildInput input = BaseInput();
    input.parentProcessName = "process with spaces & special chars \"test\"";
    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "special chars JSON parses"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "process with spaces & special chars \"test\"", 
                "parentProcessName preserves special chars after escape roundtrip"))
        return 1;
}
```

### 9.2 事件提交通路测试（新增）

只测 Builder golden 不够，需要验证整条链路没有把字段掉了。

**测试目标：** RaspEvalResult → TrySubmitDetectionEvent → EventJsonBuildInput → JSON

**方案：** 在 `engine_runtime_tests.cpp` 或新建独立测试文件中增加通路测试

**测试代码示意：**

```cpp
// === Batch 3 新增：事件提交通路测试 ===

bool TestRaspEvalResultToEventJsonPath()
{
    // 构造带 parent 字段的 RaspEvalResult
    RaspEvalResult result;
    result.matched = true;
    result.block = true;
    result.ruleId = "rule-parent-test";
    result.sensor = "AmsiProvider";
    result.desc = "parent path test";
    result.payload = "test payload";
    result.severity = "High";
    result.contentName = "test.ps1";
    result.appName = "powershell.exe";
    result.confidence = 70;
    result.parentPid = 5678;
    result.parentProcessName = "wscript.exe";

    // 直接调用 EventJsonBuilder（绕过 TrySubmitDetectionEvent，但验证字段传递）
    EventJsonBuildInput input;
    input.eventId = "evt-test";
    input.timestamp = "2026-05-09T00:00:00Z";
    input.moduleName = "rasp_mod_amsi";
    input.ruleId = result.ruleId;
    input.sensor = result.sensor;
    input.block = result.block;
    input.severity = result.severity;
    input.description = result.desc;
    input.appName = result.appName;
    input.contentName = result.contentName;
    input.confidence = result.confidence;
    input.payload = result.payload;
    input.parentPid = result.parentPid;
    input.parentProcessName = result.parentProcessName;

    EventJsonBuilder builder;
    EventJsonBuildResult built = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!ParseFlatJsonObject(built.compactJson, fields))
        return false;

    // 验证 parent 字段从 RaspEvalResult 正确传递到 JSON
    if (fields["parentPid"] != "5678")
        return false;
    if (fields["parentProcessName"] != "wscript.exe")
        return false;

    return true;
}

bool TestEventPathWithEmptyParent()
{
    RaspEvalResult result;
    result.matched = true;
    result.ruleId = "rule-empty-parent";
    result.parentPid = 0;
    result.parentProcessName.clear();

    EventJsonBuildInput input;
    input.parentPid = result.parentPid;
    input.parentProcessName = result.parentProcessName;

    EventJsonBuilder builder;
    EventJsonBuildResult built = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!ParseFlatJsonObject(built.compactJson, fields))
        return false;

    // 验证空 parent 字段正确传递
    if (fields["parentPid"] != "0")
        return false;
    if (!fields["parentProcessName"].empty())
        return false;

    return true;
}
```

**测试位置建议：** 扩展 `engine_runtime_tests.cpp` 或新建 `event_submit_path_tests.cpp`

## 10. 边界约束清单

| 禁止项 | 说明 |
|-------|------|
| 不增加 `processCaptureStatus` 到 RaspEvalResult | 采集状态属于诊断层，不属于事件层 |
| 不增加 `processRetryState` 到 RaspEvalResult | 重试状态属于诊断层，不属于事件层 |
| 不增加 `currentPid` 到 RaspEvalResult | 事件层可通过其他途径获取 |
| 不增加 `currentProcessName` 到 RaspEvalResult | 事件层已有 appName，已能满足大多数当前进程标识需求 |
| 不增加 `currentProcessPath` 到 RaspEvalResult | 路径含敏感信息，不输出 |
| 不增加 `parentProcessPath` 到 RaspEvalResult | 路径含敏感信息，不输出 |
| 不增加 `emitProcessPathFields` 开关 | Batch 3 不输出路径，不需要开关 |
| 不接 EDR SDK | Batch 3 只做 JSON 输出 |
| 不改变 AMSI 返回策略 | parent 采集失败不影响检测结果 |
| 不将 JSON key 顺序写为强契约 | 兼容性承诺是"字段存在且值正确" |

## 11. 验收标准

- [ ] RaspEvalResult 只增加 `parentPid` / `parentProcessName` 两个字段
- [ ] EventJsonBuildInput 只增加 `parentPid` / `parentProcessName` 两个字段
- [ ] EventJsonBuilder 输出 parent 字段（追加在末尾）
- [ ] TrySubmitDetectionEvent 只填充 2 个 parent 字段
- [ ] AmsiRuleEngine 在规则循环前一次性提取 parent 字段
- [ ] 新增 `ParseUint32OrZero` helper 封装异常处理
- [ ] Builder golden test 覆盖：parentPid=1234 / 0 / 4(System) / 特殊字符
- [ ] 事件提交通路 test 覆盖：RaspEvalResult → EventJsonBuildInput → JSON
- [ ] 不增加路径字段和状态字段

## 12. 分批实施建议

### Batch 3a：结构体扩展

**只允许：**
- 扩展 RaspEvalResult 增加 parentPid / parentProcessName
- 扩展 EventJsonBuildInput 增加 parentPid / parentProcessName

**禁止：**
- 不增加其他字段
- 不修改 EventJsonBuilder
- 不修改 TrySubmitDetectionEvent
- 不修改 AmsiRuleEngine

**验收：**
- 结构体新增字段编译通过
- 不影响现有代码逻辑

### Batch 3b：输出链路

**只允许：**
- AmsiRuleEngine 新增 `ParseUint32OrZero` helper
- AmsiRuleEngine 一次性提取 parent 字段并填充 RaspEvalResult
- TrySubmitDetectionEvent() 透传两字段
- EventJsonBuilder 输出两字段

**禁止：**
- 不增加其他字段
- 不接 EDR SDK
- 不改变 AMSI 返回策略

**验收：**
- 事件 JSON 包含 parentPid / parentProcessName 字段
- 字段值正确传递

### Batch 3c：测试验证

**只允许：**
- event_json_builder_tests 扩展 parent 字段 golden 测试
- engine_runtime_tests 或新建测试文件增加事件提交通路测试
- 构建并运行测试

**禁止：**
- 不修改生产代码逻辑

**验收：**
- 所有测试通过
- Builder golden test 覆盖 4 种场景
- 通路 test 验证字段传递完整

## 13. 后续 Batch 4 规划

Batch 3 完成后，Batch 4 可选内容：

- 规则验证：parentProcessName 匹配规则测试
- 事件 golden 测试：完整事件 JSON 格式验证
- 并发和失败回退测试：parent 采集失败时事件输出验证

**明确不做：**

- 完整祖先进程链
- ETW 进程缓存
- WMI 查询
- CreateToolhelp32Snapshot 主路径
- Scan 热路径远程查询 EDR
- 默认输出完整进程路径
- 父进程采集失败后 fail-close

## 14. 下一步任务

建议下一步只做：

1. 保存本文档
2. 评审 RaspEvalResult 和 EventJsonBuildInput 的字段边界
3. 确认只增加 parentPid / parentProcessName 两个字段
4. 确认分批节奏：3a（结构体）→ 3b（链路）→ 3c（测试）

评审通过后再进入 Batch 3a，实现结构体扩展。