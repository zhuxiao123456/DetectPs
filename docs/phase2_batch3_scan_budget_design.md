# Phase 2 第三批：Scan 执行预算与 Lua / PCRE2 协作式熔断设计

## 1. 批次定位

目标：保护宿主进程，确保 AMSI `Scan()` 热路径不会被 Lua、PCRE2、规则循环或超大上下文拖死。

本批性质：架构安全修复，不是检测能力增强。

允许做：

- `ScanBudget`
- `ScanDeadline`
- `ScanExecutionContext`
- Lua `lua_sethook` 协作式中断
- PCRE2 match / depth / heap limit
- regex 调用次数限制
- regex subject 长度限制
- 规则循环 `maxRules` 限制
- timeout telemetry
- budget / timeout 单测和压力测试

禁止做：

- 事件异步队列
- session cache
- 样本窗口扫描
- 检测规则增强
- worker thread timeout
- `TerminateThread`
- 强杀 Lua / regex 执行线程
- 复杂 telemetry 后端上报

## 2. 核心设计

新增 `ScanBudget`：

```cpp
struct ScanBudget {
    uint32_t totalBudgetMs = 1000;
    uint32_t luaBudgetMs = 300;

    uint32_t maxRules = 128;
    uint32_t maxRegexCalls = 512;
    uint32_t maxRegexSubjectBytes = 64 * 1024;
    uint32_t maxLuaInstructionCount = 100000;

    uint32_t pcre2MatchLimit = 100000;
    uint32_t pcre2DepthLimit = 1000;
    uint32_t pcre2HeapLimitKiB = 1024;
};
```

新增 `ScanDeadline`：

```cpp
class ScanDeadline {
public:
    static ScanDeadline FromNow(std::chrono::milliseconds budget);
    bool Expired() const;
    uint64_t RemainingMs() const;
    uint64_t ElapsedMs() const;

private:
    std::chrono::steady_clock::time_point start_;
    std::chrono::steady_clock::time_point deadline_;
};
```

要求：

- 使用 `std::chrono::steady_clock`。
- 不使用系统时间。
- 不受时间回拨影响。

新增 `ScanExecutionContext`：

```cpp
struct ScanExecutionContext {
    ScanBudget budget;
    ScanDeadline deadline;

    uint32_t rulesEvaluated = 0;
    uint32_t regexCalls = 0;
    uint32_t luaInstructions = 0;

    bool timedOut = false;
    bool regexSubjectTruncated = false;
    bool matchedBeforeTimeout = false;

    std::string timeoutReason;
    std::string regexLimitType;
    std::string decisionAfterTimeout;
};
```

边界要求：

- 不持有 runtime mutex。
- 不修改 `EngineState`。
- 不控制 reload / shutdown。
- 不写 pipe。
- 只描述单次 scan 的预算、计数器、timeout 原因和最终决策。

## 3. Timeout Policy 固化

不要在多个调用点散落 timeout 决策。新增统一函数：

```cpp
Decision ResolveTimeoutDecision(
    const CurrentDecision& current,
    const ScanExecutionContext& exec);
```

第一版策略：

```text
已有 block > timeout_policy > 已有 audit > allow
```

具体行为：

- 如果已有 block，timeout 不覆盖 block，继续返回 block。
- 如果已有非 block 命中，返回当前 audit / 检测结果，并记录 timeout。
- 如果无命中且 timeout，默认 allow，但必须记录 `scan_timeout` 和 `decision_after_timeout=allow`。
- timeout 不能被静默当普通 allow。

建议第一版常量：

```cpp
enum class TimeoutFailPolicy {
    Allow,
    Audit,
    Block
};

constexpr TimeoutFailPolicy kDefaultTimeoutFailPolicy = TimeoutFailPolicy::Allow;
```

## 4. 调用链设计

预算对象贯穿整条链路：

```text
CRaspAmsiProvider::Scan
  -> AmsiRuleEngine::Evaluate(public)
  -> AmsiRuleEngine::Evaluate(sensor, ctx, exec)
  -> rule loop
  -> regex gate / MatchesAnyRegex
  -> Lua Run
```

第一版可以通过 overload 扩展：

```cpp
AmsiEvalResult Evaluate(..., const ScanBudget& budget);

std::vector<RaspEvalResult> Evaluate(
    const std::string& sensor,
    const RaspLuaContext& ctx,
    ScanExecutionContext& exec);
```

如果改动面过大，可以先在 AMSI 模块内部创建 `ScanExecutionContext`，再逐步下传到 `rasp_rule_engine` 的 Lua / regex wrapper。

## 5. 规则循环预算

在 `AmsiRuleEngine::Evaluate()` 规则循环中执行：

- 每条规则前检查 `deadline.Expired()`。
- `rulesEvaluated++`。
- 超过 `maxRules` 后停止后续规则。
- 每次 regex / Lua 返回后检查 `exec.timedOut`。
- 如果已有 block 且后续 timeout，返回 block。
- 如果无 block 且 timeout，调用 `ResolveTimeoutDecision()`。

Telemetry：

- `rule_budget_exceeded`
- `scan_budget_exhausted`
- `scan_timeout`

## 6. Lua 协作式中断

使用 `lua_sethook`：

```cpp
lua_sethook(L, BudgetHook, LUA_MASKCOUNT, 1000);
```

hook 行为：

- 检查 `ScanDeadline::Expired()`。
- 检查 `maxLuaInstructionCount`。
- 设置 timeout 标志。
- 通过 `lua_error` 或受控 error return 退出当前 Lua 执行。

限制：

- hook 内不写日志。
- hook 内不写 pipe。
- hook 内不做复杂内存分配。
- hook 内不访问 runtime mutex。
- `Run()` 结束前必须执行：

```cpp
lua_sethook(L, nullptr, 0, 0);
```

错误路径要求：

- `pcall` 必须捕获 timeout。
- timeout 转换成明确状态，例如 `RaspLuaResult::timedOut = true`。
- timeout 后不产生误报 match。
- timeout 后下一次 scan 正常。

Lua VM 生命周期：

- 如果当前每次 `Run()` 使用独立 Lua state：timeout 后销毁 state。
- 如果复用 Lua state：timeout 后标记 dirty，不直接复用。
- Lua memory quota 本批可不做，但必须在文档中记录为后续技术债。

## 7. PCRE2 Limit 设计

在统一 regex wrapper 中实现，不在每个调用点散落逻辑。

匹配前检查：

- `deadline.Expired()`
- `++regexCalls > maxRegexCalls`
- `subject.size() > maxRegexSubjectBytes`

subject 超长处理：

```text
截断参与 regex 的 subject
记录 regex_subject_truncated
继续匹配截断内容
```

注意：这是预算限制，不是窗口扫描，不属于检测增强。

PCRE2 match context：

```cpp
pcre2_match_context* mctx = pcre2_match_context_create(nullptr);

pcre2_set_match_limit(mctx, budget.pcre2MatchLimit);
pcre2_set_depth_limit(mctx, budget.pcre2DepthLimit);
pcre2_set_heap_limit(mctx, budget.pcre2HeapLimitKiB);
```

返回值处理：

- `PCRE2_ERROR_MATCHLIMIT` -> `regex_limit_hit`, type=`match`
- `PCRE2_ERROR_DEPTHLIMIT` -> `regex_limit_hit`, type=`depth`
- `PCRE2_ERROR_HEAPLIMIT` -> `regex_limit_hit`, type=`heap`

JIT 要求：

- 必须验证 JIT on/off 行为，或在文档明确标记限制。
- 如果无法稳定验证 JIT heap limit，应记录 `JIT heap limit behavior pending verification`。
- 必要时默认高风险路径降级到非 JIT match。

## 8. Telemetry 设计

第一版仍只走 `OutputDebugStringA`。

事件：

```text
scan_budget_begin
scan_timeout
lua_timeout
regex_limit_hit
regex_subject_truncated
rule_budget_exceeded
scan_budget_exhausted
```

字段：

```text
elapsed_ms
total_budget_ms
lua_budget_ms
rules_evaluated
regex_calls
regex_limit_type
subject_len
subject_truncated
matched_before_timeout
decision_after_timeout
```

禁止：

- 写 pipe
- 等 sentry
- 复杂 JSON 上报
- 阻塞 telemetry 后端

## 9. 测试方案

新增 budget / timeout 测试目标，建议独立于 `engine_runtime_tests`，例如：

```text
scan_budget_tests.exe
```

必须测试：

- Lua `while true do end` 被 `lua_sethook` 中断。
- Lua 大量循环触发 instruction limit。
- Lua timeout 后 hook 被清理。
- Lua timeout 后下一次 scan 正常。
- Regex 灾难性回溯触发 match / depth limit。
- Regex subject 超长触发 subject length limit。
- regex 调用次数超过 `maxRegexCalls` 后停止。
- `maxRules` 超限后停止规则循环。
- total budget 到期后停止后续规则。
- 已有 block 不被后续 timeout 覆盖。
- 无命中 timeout 按默认 fail-open 决策，并记录 telemetry。
- timeout 后 `ScanGuard` 析构，`active_scan_count` 归零。
- reload / shutdown 与 timeout 并发不恢复错状态。
- 静态检查无 `TerminateThread`、worker timeout、事件队列、session cache、窗口扫描。

建议测试：

- PCRE2 JIT on/off。
- 多线程同时 Lua timeout。
- 多线程同时 regex limit。
- `totalBudgetMs=1` 极小预算。
- 默认预算下正常规则不误报 timeout。
- Lua timeout 后 VM dirty / destroy 策略。

## 10. 验证脚本

新增：

```text
scripts/test_phase2_batch3.ps1
```

脚本执行：

- 构建 `rasp_mod_amsi.dll`
- 构建 `engine_runtime_tests`
- 构建 `scan_budget_tests`
- 运行所有测试
- 进行 stress loop
- 静态 grep 禁止项

静态禁止项：

```text
TerminateThread
WaitForSingleObject.*1000
std::async
CreateThread.*Scan
event_queue
session_cache
window_scan
```

还要检查：

- `lua_sethook` 存在
- `pcre2_set_match_limit` 存在
- `pcre2_set_depth_limit` 存在
- `pcre2_set_heap_limit` 存在
- `maxRegexSubjectBytes` 存在
- `maxRegexCalls` 存在
- `maxRules` 存在

## 11. 实施顺序

建议严格执行：

1. 写 `docs/phase2_batch3_scan_budget_design.md`。
2. 审查 `RaspLuaEngine::Run / MatchesAnyRegex / PCRE2 wrapper`。
3. 增加 budget / timeout 测试，确认 RED。
4. 实现 `ScanBudget / ScanDeadline / ScanExecutionContext`。
5. 实现 `ResolveTimeoutDecision()`。
6. 将 `ScanExecutionContext` 下传到规则循环、regex、Lua。
7. 实现 PCRE2 match / depth / heap limit。
8. 实现 regex 调用次数和 subject 长度限制。
9. 实现 Lua `lua_sethook` 协作式 timeout。
10. 在规则循环加入 total budget / maxRules 控制。
11. 增加 timeout telemetry。
12. 新增 `test_phase2_batch3.ps1`。
13. 构建、测试、stress loop。
14. 独立 commit / push。

## 12. 最终验收门槛

构建：

- `rasp_mod_amsi.dll` 构建通过。
- `engine_runtime_tests` 继续通过。
- budget / timeout tests 通过。

Lua：

- 死循环被协作式中断。
- 大量循环触发 instruction limit。
- 不使用 `TerminateThread`。
- timeout 后不崩、不挂死。
- timeout 后下一次 scan 正常。

PCRE2：

- 灾难性回溯不拖死 scan。
- match / depth / heap limit 命中有明确返回。
- subject 长度限制生效。
- JIT on/off 行为已验证或文档记录。

Scan 预算：

- total budget 到期后停止后续规则。
- 已有 block 不被 timeout 覆盖。
- 无命中 timeout 按 fail policy 决策。
- `ScanGuard` 正常析构。
- `active_scan_count` 归零。

边界：

- 不引入事件队列。
- 不引入 session cache。
- 不引入窗口扫描。
- 不增强检测规则。
- 不新增 worker thread timeout / 强杀模型。
