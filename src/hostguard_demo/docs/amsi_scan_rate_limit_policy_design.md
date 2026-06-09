# AMSI Scan 频率限制方案

## 背景

AMSI DLL 被 PowerShell、pwsh、wscript、winmgmt、svchost 等宿主进程加载后，每次宿主调用 AMSI Scan 都可能进入 DLL 检测流程。正常情况下 Scan 频率有限，但在以下场景可能出现短时间高频调用：

- PowerShell 执行大型脚本或频繁拼接脚本片段。
- 某些业务脚本框架反复触发 AMSI Scan。
- 攻击者构造大量无效 Scan 输入，试图制造检测开销。
- 规则中存在较重的 C++ 正则或 Lua 逻辑。

如果每次 Scan 都进入完整规则检测，可能导致宿主进程卡顿。因此需要在 DLL 侧增加轻量扫描频率限制，在单位时间内 Scan 次数过多时，对超限部分按比例 fail-open bypass。

该能力是性能保护和稳定性兜底，不改变规则匹配语义。

## 目标

1. 支持通过规则根级配置控制 Scan 限频。
2. 限频在 DLL 单进程内生效，不做跨进程全局计数。
3. 正常频率内不影响检测。
4. 高频超限后，按配置比例 bypass 部分 Scan。
5. bypass 返回 NoMatch / allow-no-detect，不产生 Detection 事件。
6. 内部 telemetry 能区分 bypass_reason=scan_rate_limited。
7. 限频日志按状态变化和窗口摘要输出，避免日志风暴。
8. 配置变化纳入 effective snapshot hash，确保 DLL 可重新加载快照。

## JSON 配置

新增根级字段 `scanRateLimit`，和 `globalMode`、`maxScanContentBytes`、`totalScanTimeoutMs` 同级：

```json
{
  "version": "2026063001",
  "globalMode": "block",
  "maxScanContentBytes": 8192,
  "totalScanTimeoutMs": 1000,
  "scanRateLimit": {
    "enabled": true,
    "windowMs": 1000,
    "maxScans": 200,
    "bypassRatioAfterLimit": 0.8
  },
  "rules": []
}
```

字段含义：

- `enabled`: 是否开启 Scan 限频。
- `windowMs`: 统计窗口长度，单位毫秒。
- `maxScans`: 每个窗口内允许完整检测的 Scan 次数。
- `bypassRatioAfterLimit`: 超过阈值后，超限 Scan 的 bypass 比例。

## 固定语义

`bypassRatioAfterLimit` 语义必须固定：

- `0.0`: observe only，超限后不 bypass，仍全部完整检测，但记录统计和限频日志。
- `1.0`: 超限后全部 bypass。
- `0.8`: 超限后约 80% bypass，约 20% 继续检测。

示例：

```text
windowMs = 1000
maxScans = 200
bypassRatioAfterLimit = 0.8

1 秒内进入 1000 次 Scan：
前 200 次：完整检测
后 800 次：约 640 次 bypass，约 160 次继续检测
```

注意：限频是每个 DLL 实例、每个宿主进程内独立计算。powershell.exe、pwsh.exe、wscript.exe 各自有自己的计数器。

## 默认值和范围

建议默认值：

```json
"scanRateLimit": {
  "enabled": false,
  "windowMs": 1000,
  "maxScans": 200,
  "bypassRatioAfterLimit": 0.8
}
```

建议 clamp：

- `windowMs`: `[100, 60000]`
- `maxScans`: `[1, 100000]`
- `bypassRatioAfterLimit`: `[0.0, 1.0]`

字段缺失或类型非法时使用默认值。

## 代码结构

不要在 `RuleSnapshot` 中平铺限频字段，新增独立结构体：

```cpp
struct ScanRateLimitConfig {
    bool enabled = false;
    uint32_t windowMs = 1000;
    uint32_t maxScans = 200;
    double bypassRatioAfterLimit = 0.8;
};
```

然后挂到快照中：

```cpp
RuleSnapshot::scanRateLimit
```

这样后续增加 `mode`、`logIntervalMs`、`sampleStrategy` 等字段时，不会污染快照结构。

## 运行态计数

AMSI Scan 可能并发进入。Phase 1 建议使用小锁保护运行态，逻辑更稳，成本可接受：

```cpp
std::mutex rateLimitMutex_;
uint64_t windowStartMs_ = 0;
uint64_t windowScanCount_ = 0;
uint64_t overLimitSeq_ = 0;
uint32_t windowBypassed_ = 0;
uint32_t windowEvaluatedAfterLimit_ = 0;
uint64_t lastLogMs_ = 0;
bool windowLimitEntered_ = false;
```

后续如果确认锁开销明显，再优化为 atomic 或分片计数。

## 优先级顺序

限频判断必须放在规则引擎内部，并遵循以下顺序：

1. `offline / paused / inert / snapshot not ready`
2. `trust_process`
3. `scanRateLimit`
4. `content truncate`
5. `totalScanTimeoutMs / regex / lua budget`
6. `rule evaluation`

不要把限频放到最外层 AMSI Provider，否则 paused、host offline、trust_process 等状态也会污染限频统计。

## 限频算法

Phase 1 使用固定窗口，不做复杂滑动窗口。

流程：

1. 读取当前规则快照。
2. 如果 `scanRateLimit.enabled=false`，正常检测。
3. 如果当前时间超过窗口，输出上一窗口摘要并重置窗口。
4. 当前窗口计数加一。
5. 如果 `count <= maxScans`，正常检测。
6. 如果 `count > maxScans`，进入超限逻辑。
7. 根据 `bypassRatioAfterLimit` 做确定性采样。
8. 命中 bypass 时返回 NoMatch，并记录 `bypass_reason=scan_rate_limited`。

确定性采样建议：

```cpp
bypass = ((overLimitSeq * 9973) % 1000) < bypassPermille;
```

要求：

- `overLimitSeq` 从 1 开始递增。
- 使用 `uint64_t`。
- `bypassPermille` 使用四舍五入计算：`static_cast<uint32_t>(ratio * 1000.0 + 0.5)`。

示例：

- `0.0` => `bypassPermille=0`，永不 bypass。
- `0.8` => `bypassPermille=800`，约 80% bypass。
- `1.0` => `bypassPermille=1000`，全部 bypass。

## 返回语义

命中限频 bypass 时：

- 返回 NoMatch / allow-no-detect。
- 不产生 Detection 事件。
- 不表示规则命中 clean。
- 内部 telemetry 标记：

```text
bypass_reason=scan_rate_limited
```

用于排查“为什么没有检出”。

实现上 `ShouldBypassByScanRateLimit()` 不建议只返回 bool。建议返回一个结构体，至少包含：

```cpp
struct ScanRateLimitDecision {
    bool enabled = false;
    bool overLimit = false;
    bool bypass = false;
    const char* reason = "";
    uint64_t windowScanCount = 0;
    uint64_t overLimitSeq = 0;
    uint32_t bypassPermille = 0;
};
```

这样日志和单测都可以直接断言限频原因、窗口计数和采样结果。

## 日志策略

禁止每次 bypass 都打日志。

建议：

1. 首次进入限频状态打一条：

```text
AMSI scan rate limit entered: windowMs=1000 maxScans=200 bypassRatio=0.80
```

2. 窗口切换时打一条摘要：

```text
AMSI scan rate limit summary: scans=420 bypassed=176 evaluatedAfterLimit=44 windowMs=1000 maxScans=200
```

3. 同一窗口内不逐次打印。

4. `bypassRatioAfterLimit=0.0` 时属于 observe only，可用 info/debug 表示“超限但未 bypass”。

## 修改范围

建议修改：

1. `rule_json_parser.h/.cpp`
   - 增加 `ScanRateLimitConfig`。
   - 解析根级 `scanRateLimit`。
   - 做默认值和 clamp。

2. `AmsiRuleEngine::RuleSnapshot`
   - 增加 `scanRateLimit`。

3. `amsi_rule_engine.cpp`
   - 增加线程安全运行态。
   - 增加 `ShouldBypassByScanRateLimit()`。
   - 在 Scan 入口、规则检测前调用。
   - 增加限频 telemetry/log。

4. 测试代码
   - 补 parser 默认值、合法值、非法值和 clamp。
   - 补单线程限频行为。
   - 补并发 Scan 行为。

## 测试要求

1. 默认配置
   - 未配置 `scanRateLimit` 时行为不变。

2. `enabled=false`
   - 即使频率很高，也不 bypass。

3. 阈值内
   - `maxScans=3`，前三次完整检测。

4. 超限全 bypass
   - `bypassRatioAfterLimit=1.0`，超过阈值后全部 NoMatch。

5. observe only
   - `bypassRatioAfterLimit=0.0`，超过阈值后仍全部完整检测，但统计显示进入 over-limit。

6. 窗口恢复
   - 等待超过 `windowMs` 后，新窗口重新允许完整检测。

7. 并发 Scan
   - 多线程同时调用 `Evaluate`，确认：
     - count 不丢失。
     - 不崩溃。
     - 不出现窗口重置竞争。
     - bypassed/evaluated 统计合理。

## 风险

主要风险是漏检。

攻击者可能构造大量无害 Scan 输入，让 DLL 进入限频状态，再把恶意内容放在超限部分，导致被 bypass。

缓解建议：

1. 默认关闭，先灰度开启。
2. 生产环境不要默认 `bypassRatioAfterLimit=1.0`。
3. 保留一定比例继续检测，例如 `0.8` 而不是 `1.0`。
4. 输出限频摘要日志，便于业务侧发现异常高频 Scan。
5. 后续如有需要，再增加进程级策略或高风险内容轻量预筛。

## 结论

Phase 1 建议落地根级 `scanRateLimit`，采用 DLL 进程内固定窗口计数、小锁保护、确定性采样和 fail-open bypass。该方案不新增 IPC，不依赖 Host 全局状态，不改变规则匹配语义，只在高频 Scan 场景下提供性能保护。
