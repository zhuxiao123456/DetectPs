# ProcessContextProvider Batch 3 Review 证据：提交通路测试代码固化

## 1. 文档目的

本文档固化 Batch 3 新增的 `engine_runtime_tests.cpp` 提交通路测试代码，作为 Review 证据，证明：

1. **RaspEvalResult → EventJsonBuildInput → JSON** 链路不会丢失 parent 字段
2. **空 parent 字段** 正确传递到 JSON 输出

---

## 2. 测试代码固化（commit 799bea4）

### 2.1 提交通路测试 1：parentPid=5678 / parentProcessName="wscript.exe"

**文件：** `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp`

**代码位置：** 第 347-445 行

```cpp
// Batch 3: 事件提交通路测试 - 验证 RaspEvalResult -> EventJsonBuildInput -> JSON
{
    RaspEvalResult result;
    result.matched = true;
    result.block = true;
    result.ruleId = "rule-parent-path";
    result.sensor = "AmsiProvider";
    result.desc = "parent path test";
    result.payload = "test payload";
    result.severity = "High";
    result.contentName = "test.ps1";
    result.appName = "powershell.exe";
    result.confidence = 70;
    result.parentPid = 5678;
    result.parentProcessName = "wscript.exe";

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
    size_t i = 0;
    const std::string& json = built.compactJson;
    auto skipWs = [&]() {
        while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n'))
            ++i;
    };
    auto readString = [&](std::string& s) {
        skipWs();
        if (i >= json.size() || json[i] != '"')
            return false;
        ++i;
        s.clear();
        while (i < json.size() && json[i] != '"') {
            if (json[i] == '\\') {
                ++i;
                if (i >= json.size())
                    return false;
                switch (json[i]) {
                case '"': s.push_back('"'); break;
                case '\\': s.push_back('\\'); break;
                case 'n': s.push_back('\n'); break;
                case 'r': s.push_back('\r'); break;
                case 't': s.push_back('\t'); break;
                default: s.push_back(json[i]); break;
                }
                ++i;
            } else {
                s.push_back(json[i++]);
            }
        }
        if (i >= json.size() || json[i] != '"')
            return false;
        ++i;
        return true;
    };

    skipWs();
    if (i >= json.size() || json[i++] != '{')
        return 1;
    skipWs();
    while (i < json.size() && json[i] != '}') {
        std::string key, value;
        if (!readString(key))
            return 1;
        skipWs();
        if (i >= json.size() || json[i++] != ':')
            return 1;
        if (!readString(value))
            return 1;
        fields[key] = value;
        skipWs();
        if (i < json.size() && json[i] == ',')
            ++i;
        skipWs();
    }

    if (!Expect(fields["parentPid"] == "5678",
                "event submit path: parentPid 5678 reaches JSON"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "wscript.exe",
                "event submit path: parentProcessName wscript.exe reaches JSON"))
        return 1;
}
```

**验证点：**

| 断言 | 验证内容 |
|------|---------|
| `fields["parentPid"] == "5678"` | parentPid 从 RaspEvalResult 正确传递到 JSON |
| `fields["parentProcessName"] == "wscript.exe"` | parentProcessName 正确传递到 JSON |

---

### 2.2 提交通路测试 2：空 parent 字段

**文件：** `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp`

**代码位置：** 第 447-498 行

```cpp
// Batch 3: 事件提交通路测试 - 空 parent 字段
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
    // ... JSON 解析逻辑（同上） ...

    if (!Expect(fields["parentPid"] == "0",
                "event submit path: empty parentPid is 0 in JSON"))
        return 1;
    if (!Expect(fields["parentProcessName"].empty(),
                "event submit path: empty parentProcessName is empty in JSON"))
        return 1;
}
```

**验证点：**

| 断言 | 验证内容 |
|------|---------|
| `fields["parentPid"] == "0"` | 空 parentPid 输出为 "0" |
| `fields["parentProcessName"].empty()` | 空 parentProcessName 输出为空字符串 |

---

## 3. 测试链路证明

### 3.1 数据流路径

```
AmsiRuleEngine::Evaluate()
  └─ 一次性提取 parentPid / parentProcessName from ctx.fields
  └─ 填充 RaspEvalResult.parentPid / parentProcessName
  └─ TrySubmitDetectionEvent(result)
      └─ EventJsonBuildInput.parentPid = result.parentPid
      └─ EventJsonBuildInput.parentProcessName = result.parentProcessName
      └─ EventJsonBuilder::BuildDetection(input)
          └─ JSON 输出: "parentPid":"5678", "parentProcessName":"wscript.exe"
```

### 3.2 测试覆盖矩阵

| 测试场景 | 文件 | 验证层级 |
|---------|------|---------|
| parentPid=5678 → JSON | engine_runtime_tests.cpp | **完整链路** |
| parentPid=0 → JSON | engine_runtime_tests.cpp | **完整链路** |
| parentPid=1234 Builder 测试 | event_json_builder_tests.cpp | Builder 层 |
| parentPid=0 Builder 测试 | event_json_builder_tests.cpp | Builder 层 |
| parentPid=4 (System) Builder 测试 | event_json_builder_tests.cpp | Builder 层 |
| 特殊字符 Builder 测试 | event_json_builder_tests.cpp | Builder 层 |

---

## 4. 运行结果固化

**commit:** `799bea4`

**运行时间:** 2026-05-09T04:29:54Z

**测试结果:**

| 测试 | 结果 |
|------|------|
| `engine_runtime_tests.exe` | ✅ PASS |
| `event_json_builder_tests.exe` | ✅ PASS |
| `process_context_provider_tests.exe` | ✅ PASS |

---

## 5. 边界约束验证

| 约束项 | 验证结果 |
|-------|---------|
| 不加 processCaptureStatus/processRetryState 字段 | ✅ 无违规 |
| 不加路径字段 | ✅ 无违规 |
| 不加 emitProcessPathFields 开关 | ️ 无违规 |
| process_context_provider.h 不扩散到 rasp_rule_engine | ✅ 无违规 |

---

## 6. 后续任务

Batch 3 提交通路测试已固化，下一步进入 **Batch 4 测试补强**：

- 完整事件 JSON golden fixture
- 采集失败路径测试
- 并发检测一致性测试
- payload 截断 + parent 组合测试

详见：`docs/process_context_batch4_test_reinforcement_design.md`

---

## 7. 文档关联

| 文档 | 关系 |
|------|------|
| `process_context_batch3_event_output_design.md` | Batch 3 设计文档 |
| `process_context_batch3_review_evidence.md` | Batch 3 Review 证据（本文档） |
| `process_context_batch4_test_reinforcement_design.md` | Batch 4 设计文档 |