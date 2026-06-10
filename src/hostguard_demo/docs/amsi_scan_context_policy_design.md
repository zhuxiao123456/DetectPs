# AMSI Scan Context 短 TTL 聚合窗口设计

## 1. 背景

当前 AMSI 检测以单次 `ScanBuffer` / `ScanString` 输入为检测边界。PowerShell 等宿主可能将脚本拆成多次 AMSI Scan，例如第一段只包含 `amsi`，第二段才包含 `utils`。如果规则依赖跨片段上下文，单次内容检测会漏报。

本方案在 DLL 进程内增加一个短 TTL 的 Scan 上下文聚合窗口，用“历史上下文尾部 + 当前内容”作为实际检测内容，解决跨多次 AMSI Scan 的片段关联检测问题。

## 2. 目标

1. 不无限拼接 Scan 内容。
2. 在 DLL 进程内维护轻量 ring buffer。
3. 每次 Scan 使用“历史上下文尾部 + 当前内容”作为实际检测内容。
4. 命中任意规则后按配置清空上下文，减少误报、重复告警和后续阻塞。
5. 限频 bypass、全局超时、异常场景不污染上下文。
6. Phase 1 只做滑动窗口上下文，不做 token 提取和规则状态机。

## 3. 非目标

1. 不做 token 级上下文。
2. 不做规则 `matchSequence` 状态机。
3. 不做 Host 全局上下文。
4. 不把上下文原文输出到日志。
5. 不改变规则匹配语义，只改变实际参与检测的 `evalContent`。
6. Phase 1 不按 PID 建 map，只使用当前 DLL 实例级上下文。

## 4. 配置格式

新增根级配置 `scanContext`：

```json
{
  "scanContext": {
    "enabled": false,
    "maxBufferedBytes": 8192,
    "ttlMs": 3000,
    "maxEvalBytes": 16384,
    "clearOnMatch": true
  }
}
```

字段语义：

- `enabled`：是否启用 Scan 上下文聚合，默认 `false`。
- `maxBufferedBytes`：ring buffer 最多保存的历史上下文字节数，默认 `8192`。
- `ttlMs`：距离上次成功 append 到上下文的 Scan 超过该时间后清空上下文，默认 `3000`。
- `maxEvalBytes`：实际参与检测的 `evalContent` 最大长度，默认 `16384`。
- `clearOnMatch`：命中任意规则后是否清空上下文，Phase 1 默认 `true`。

参数 clamp：

- `maxBufferedBytes`: `[0, 65536]`
- `ttlMs`: `[100, 60000]`
- `maxEvalBytes`: `[1024, 131072]`
- `clearOnMatch`: 默认 `true`
- `enabled`: 默认 `false`

补充约束：

- `maxEvalBytes` 最终生效值不得小于 `maxScanContentBytes`。
- 如果用户配置的 `scanContext.maxEvalBytes < maxScanContentBytes`，解析阶段自动将 `maxEvalBytes` 抬高到 `maxScanContentBytes`。
- 这样可以避免当前内容已按 `maxScanContentBytes` 截断后，又被 `maxEvalBytes` 二次过度截尾。

配置缺失或字段非法时使用默认值。`scanContext` 必须纳入 effective snapshot hash，确保配置变化后 DLL 可以感知并清理旧上下文。

## 5. 数据结构

在 `RuleSnapshot` 中新增独立结构体，不平铺字段：

```cpp
struct ScanContextConfig {
    bool enabled = false;
    uint32_t maxBufferedBytes = 8192;
    uint32_t ttlMs = 3000;
    uint32_t maxEvalBytes = 16384;
    bool clearOnMatch = true;
};
```

```cpp
struct RuleSnapshot {
    // existing fields...
    ScanContextConfig scanContext;
};
```

在 `AmsiRuleEngine` 内新增运行态：

```cpp
std::mutex scanContextMutex_;
std::string scanContextBuffer_;
uint64_t lastScanContextAppendMs_ = 0;
std::string lastScanContextSnapshotHash_;
```

说明：

- `scanContextBuffer_` 保存历史上下文尾部，不保存无限历史。
- `lastScanContextAppendMs_` 用于 TTL 过期判断。
- 只有成功 append 到上下文时才更新 `lastScanContextAppendMs_`。
- `lastScanContextSnapshotHash_` 用于发现规则快照或配置变化。
- Phase 1 为 DLL 实例级上下文，不按 PID 建 map。

以下场景不会刷新 TTL：

- scanRateLimit bypass
- trust_process bypass
- global timeout
- exception
- offline / paused / inert
- snapshot not ready

连续发生 bypass 而没有新的 append 时，旧上下文允许自然过期。这是设计行为，不是 Bug。

## 6. 检测流程

整体顺序必须保持如下：

1. 读取规则快照。
2. 处理 offline / paused / inert / snapshot not ready。
3. 处理 `trust_process`。
4. 处理 `scanRateLimit`。
5. 对当前内容做 normalize 和 `maxScanContentBytes` 截断。
6. 调用 `BuildScanEvaluationContent()` 构造 `evalContent`。
7. 使用 `evalContent` 进入 `totalScanTimeoutMs`、regex、Lua budget 和规则遍历。
8. 检测结束后根据结果更新或清空上下文。

关键约束：

- 如果 scanRateLimit bypass，直接返回 NoMatch，不 append 当前内容。
- `BuildScanEvaluationContent()` 必须先读取旧 buffer，再构造 `oldContext + "\n" + currentContent`。
- 不允许先 append 再构造 `evalContent`，避免当前内容被重复检测。
- `evalContent` 超过 `maxEvalBytes` 时只保留尾部。
- TTL 到期时先清空旧 buffer，再构造 `evalContent`。
- 全局超时、异常、限频 bypass 后不 append 当前内容。
- `scanContextMutex_` 只保护 `scanContextBuffer_`、时间戳、snapshot hash 等共享状态。
- `scanContextMutex_` 不应覆盖字符串拼接、`reserve` 和大块内存复制过程。
- 高并发 Scan 场景下必须尽量缩短锁持有时间。

## 7. 核心伪代码

### 7.1 ScanResult

`FinalizeScanContext()` 使用统一的 `ScanResult` 判断是否 append 或 clear：

```cpp
struct ScanResult {
    bool matched = false;

    bool rateLimitedBypass = false;

    bool globalTimeout = false;

    bool exception = false;
};
```

字段语义：

- `matched`：任意规则最终命中。
- `rateLimitedBypass`：scanRateLimit 放行。
- `globalTimeout`：全局预算耗尽。
- `exception`：规则执行异常或不可恢复错误。

`matched` 的定义与规则动作解耦。只要任意规则最终命中，无论规则 `mode` 为 `block`、`monitor`、`audit`、`detect`，均视为 `matched=true`。

因此：

```cpp
if (result.matched && cfg.clearOnMatch) {
    ClearScanContextLocked("rule_match");
}
```

会清空上下文。不要把是否告警、是否阻断与 `clearOnMatch` 绑定。

### 7.2 构造检测内容

```cpp
std::string AmsiRuleEngine::BuildScanEvaluationContent(
    const RuleSnapshot& snapshot,
    const std::string& currentContent,
    uint64_t nowMs,
    ScanContextBuildInfo* info)
{
    const ScanContextConfig& cfg = snapshot.scanContext;

    if (!cfg.enabled || cfg.maxBufferedBytes == 0) {
        info->enabled = false;
        info->currentLen = currentContent.size();
        info->bufferedLen = 0;
        info->evalLen = currentContent.size();
        return TrimTail(currentContent, cfg.maxEvalBytes);
    }

    std::string contextCopy;
    bool expired = false;

    {
        std::lock_guard<std::mutex> lock(scanContextMutex_);

        MaybeClearScanContextForSnapshotChange(snapshot.effectiveHash);

        expired = lastScanContextAppendMs_ != 0 &&
            nowMs - lastScanContextAppendMs_ > cfg.ttlMs;

        if (expired) {
            ClearScanContextLocked("ttl_expired");
        }

        contextCopy = scanContextBuffer_;

        info->enabled = true;
        info->currentLen = currentContent.size();
        info->bufferedLen = contextCopy.size();
        info->expired = expired;
    }

    std::string eval;
    if (!contextCopy.empty()) {
        eval.reserve(contextCopy.size() + 1 + currentContent.size());
        eval.append(contextCopy);
        eval.push_back('\n');
    } else {
        eval.reserve(currentContent.size());
    }
    eval.append(currentContent);

    TrimStringTailInPlace(eval, cfg.maxEvalBytes);

    info->evalLen = eval.size();

    return eval;
}
```

设计说明：

- 锁内只做 TTL 判断、snapshot change 判断和 context buffer 拷贝。
- 锁外完成 `evalContent` 拼接、`TrimTail`、`reserve`。
- 这样可以避免高并发 Scan 时，字符串拼接和大块内存复制长时间占用 `scanContextMutex_`。

### 7.3 检测结束后更新上下文

```cpp
void AmsiRuleEngine::FinalizeScanContext(
    const RuleSnapshot& snapshot,
    const std::string& currentContent,
    uint64_t nowMs,
    const ScanResult& result)
{
    const ScanContextConfig& cfg = snapshot.scanContext;
    if (!cfg.enabled || cfg.maxBufferedBytes == 0) {
        return;
    }

    std::lock_guard<std::mutex> lock(scanContextMutex_);

    auto currentSnapshot = std::atomic_load(&m_snapshot);
    if (!currentSnapshot || currentSnapshot->effectiveHash != snapshot.effectiveHash) {
        return;
    }

    if (result.matched && cfg.clearOnMatch) {
        ClearScanContextLocked("rule_match");
        return;
    }

    if (result.rateLimitedBypass || result.globalTimeout || result.exception) {
        return;
    }

    if (currentContent.empty()) {
        return;
    }

    if (!scanContextBuffer_.empty()) {
        scanContextBuffer_.push_back('\n');
    }
    scanContextBuffer_.append(currentContent);
    TrimStringTailInPlace(scanContextBuffer_, cfg.maxBufferedBytes);
    lastScanContextAppendMs_ = nowMs;
    lastScanContextSnapshotHash_ = snapshot.effectiveHash;
}
```

## 8. 清理时机

以下场景必须清空 `scanContext`：

1. 规则快照 hash 变化。
2. `scanContext` 配置变化。
3. reload / pause / resume / unload。
4. TTL 到期。
5. 命中任意规则且 `clearOnMatch=true`。
6. Shutdown / destructor。

说明：

- reload 后新规则语义可能变化，旧上下文不能继续参与检测。
- pause / unload / inert 场景下旧上下文不应在后续 running 时继续命中。
- resume 时也清理一次，避免暂停期间残留内容影响恢复后的第一轮 Scan。
- TTL 基于 `lastScanContextAppendMs_` 判断，只有成功 append 后才刷新时间。

## 9. 日志和 Telemetry

不允许输出完整上下文内容，只输出长度、状态和必要 hash。

构造检测内容时打印 debug：

```text
scan_context enabled=1 current_len=xx buffered_len=xx eval_len=xx expired=0 appended=0 cleared_on_match=0
```

命中后清空：

```text
scan_context cleared reason=rule_match
```

TTL 到期清空：

```text
scan_context cleared reason=ttl_expired
```

snapshot 变化清空：

```text
scan_context cleared reason=snapshot_changed
```

日志要求：

- 默认 debug，避免刷 warning。
- 清空日志只在状态变化时打印。
- 不打印 `evalContent`、`currentContent` 或历史 buffer 原文。

## 10. 异常和旁路语义

以下场景不 append 当前内容：

1. offline / paused / inert / snapshot not ready。
2. trust_process bypass。
3. scanRateLimit bypass。
4. normalize 失败或异常。
5. totalScanTimeoutMs 全局超时。
6. 规则执行出现不可恢复异常。

PCRE2 单 pattern 的 match/depth/heap/jit stack limit 命中时，当前语义是跳过当前规则继续后续规则。该场景是否 append 取决于最终 Scan 是否发生全局超时或异常：

- 仅单条规则 regex limit，整体 Scan 正常完成：可以 append。
- 触发全局 budget exhausted：不 append。

## 11. 实现文件

计划修改：

1. `rule_json_parser.h`
   - 增加 `ScanContextConfig`。
   - `RuleSnapshot` 新增 `scanContext` 字段。

2. `rule_json_parser.cpp`
   - 解析根级 `scanContext`。
   - 缺失或非法字段使用默认值。
   - 对参数做 clamp。
   - 将 `scanContext` 纳入 effective snapshot hash。

3. `amsi_rule_engine.h`
   - 增加 scan context 运行态字段。
   - 声明 `BuildScanEvaluationContent()`、`FinalizeScanContext()`、`ClearScanContext()` 等内部函数。

4. `amsi_rule_engine.cpp`
   - 在 Evaluate / Scan 入口接入上下文构造。
   - 在检测结束后按结果 append 或 clear。
   - 在 snapshot hash 变化时清理上下文。
   - 日志只输出长度和状态。

5. `rasp_sentry_base.cpp` 或 runtime reload/pause/resume/unload 相关路径
   - 在状态变化时调用规则引擎清理上下文。
   - 如果引擎对象在 reload 时整体替换，则可通过对象替换自然清空，但仍建议保留显式清理接口。

## 12. 测试计划

1. `enabled=false` 时行为不变。
2. `amsi` 和 `utils` 分两次 Scan，TTL 内第二次可以命中。
3. TTL 到期后，先扫 `amsi`，超过 TTL 再扫 `utils` 不命中。
4. `maxBufferedBytes` 只保留尾部。
5. `maxEvalBytes` 限制 `evalContent` 最大长度。
6. 命中规则后 `clearOnMatch=true` 清空上下文，后续 Scan 不再重复命中旧上下文。
7. scanRateLimit bypass 后不 append。
8. totalScanTimeoutMs 超时后不 append。
9. 多线程并发 Evaluate 不崩溃，buffer 不破坏。
10. 规则 reload / snapshot hash 变化后上下文清空。
11. 命中 `audit` / `monitor` / `detect` 规则时，只要 `clearOnMatch=true`，同样清空上下文。
12. 连续 bypass 不刷新 `lastScanContextAppendMs_`，旧上下文按 TTL 自然过期。

## 13. 联调验证建议

规则示例：

```json
{
  "version": 1,
  "globalMode": "block",
  "scanContext": {
    "enabled": true,
    "maxBufferedBytes": 8192,
    "ttlMs": 3000,
    "maxEvalBytes": 16384,
    "clearOnMatch": true
  },
  "rules": [
    {
      "id": "AMSI-CONTEXT-01",
      "sensor": "AmsiProvider",
      "enabled": true,
      "mode": "block",
      "severity": 3,
      "confidence": 90,
      "description": "跨 AMSI Scan 片段检测 amsi utils",
      "config": {
        "regexField": "body",
        "regexPatterns": [
          "(?is)\\bamsi\\b[\\s\\S]{0,64}\\butils\\b"
        ]
      }
    }
  ]
}
```

PowerShell 验证：

```powershell
"amsi"
"utils"
```

预期：

- `scanContext.enabled=false`：不命中。
- `scanContext.enabled=true` 且两次 Scan 在 TTL 内：第二次命中。
- 命中后清空上下文，第三次单独输入 `utils` 不应因为旧 `amsi` 重复命中。

## 14. 风险

1. 误报风险：不同命令在短时间内被拼接后形成命中。
   - 通过 `ttlMs`、`maxBufferedBytes`、`clearOnMatch` 控制。

2. 性能风险：`evalContent` 变长。
   - 通过 `maxEvalBytes`、`totalScanTimeoutMs`、scanRateLimit 控制。

3. 并发风险：AMSI Scan 可能并发进入。
   - Phase 1 使用 mutex 保护 buffer。
   - `BuildScanEvaluationContent()` 中锁只覆盖共享状态读取和拷贝，不覆盖字符串拼接过程。

4. 日志风险：上下文可能包含敏感脚本。
   - 禁止输出原文，只输出长度和状态。

## 15. 已知限制

Phase 1 使用 DLL 实例级上下文：

```text
DLL实例
    ↓
scanContextBuffer_
```

作为唯一上下文。

这意味着同一宿主进程内多个独立 Runspace、Pipeline、ScriptBlock 可能共享同一个 Scan Context。

示例：

Runspace A:

```text
amsi
```

Runspace B:

```text
utils
```

理论上可能形成关联命中。

这是 Phase 1 为降低复杂度而接受的设计权衡。未来演进方向是引入：

```cpp
ScriptSessionContextCache
```

按以下维度做更细粒度隔离：

- SessionId
- ScriptBlockId
- ContentName

本阶段不实现该能力。

## 16. Phase 1 结论

当前方案 Phase 1 可以接受。

已知限制：

- DLL 实例级上下文可能存在跨 Runspace 污染。
- 未来通过 `SessionContextCache` 演进解决。

在当前 AMSI 项目阶段，该风险低于引入复杂 Session 状态机带来的实现成本。

因此建议通过评审并进入开发。
