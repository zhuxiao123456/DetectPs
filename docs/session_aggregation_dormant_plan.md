# Session Aggregation Dormant Plan

## 1. 当前决策

当前版本不做 session 聚合能力。

目标策略：

- 从生产 AMSI 检测链路摘除 session 聚合接入。
- 保留 `ScriptSessionContextCache` 实现和测试，作为 dormant / experimental 资产。
- 明确 session 聚合不属于当前版本能力承诺。
- 不删除 legacy 代码资产，不接真实 AMSI session，不修改 EDR 迁移链路。

统一状态标签：

```text
Status: Dormant / Experimental
Production state: Not wired into current AMSI scan path
Release commitment: Not supported in current version
```

## 2. 当前生产接入点

当前 session 聚合已经接入生产检测链路，不是纯 dormant 代码。

生产调用链：

```text
CRaspAmsiProvider::Scan()
  -> AmsiRuleEngine::Evaluate(contentName, appName, sample, sampleLen)
  -> ScriptInputNormalizer::Normalize()
  -> ScriptSessionKey
  -> ScriptSessionContextCache::UpdateAndBuildView()
  -> ctx.fields["body"] = sessionView.body
  -> AmsiRuleEngine::Evaluate("AmsiProvider", ctx)
  -> Regex / Lua
```

当前生产耦合点：

| 文件 | 接入点 | 处理要求 |
|---|---|---|
| `src/rasp_mod_amsi/include/amsi_rule_engine.h` | `#include "script_session_context_cache.h"` | 移除 |
| `src/rasp_mod_amsi/include/amsi_rule_engine.h` | `ScriptSessionContextCache m_sessionCache` | 移除 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | `MakeSessionContentHash()` | 移除，摘除后为死代码 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | `ScriptSessionKey` 构造 | 移除 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | `m_sessionCache.UpdateAndBuildView()` | 移除 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | `ctx.fields["body"]` 使用 session view | 改为直接使用 normalized body |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | `sessionAggregated/sessionTruncated/sessionBypassed` 日志字段 | 移除 |
| `src/rasp_mod_amsi/CMakeLists.txt` | `script_session_context_cache.cpp` 进入生产 target | 从生产 target 断开 |
| `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp` | split token across chunks 生产聚合测试 | 删除或改为反向断言 |

## 3. 摘除后的生产主链路

目标生产链路：

```text
CRaspAmsiProvider::Scan()
  -> AmsiRuleEngine::Evaluate(contentName, appName, sample, sampleLen)
  -> ScriptInputNormalizer::Normalize()
  -> ctx.fields["body"] = normalized.normalized
  -> AmsiRuleEngine::Evaluate("AmsiProvider", ctx)
  -> Regex / Lua
```

`AmsiRuleEngine::Evaluate()` 应恢复为：

```cpp
NormalizedScriptInput normalized = m_inputNormalizer.Normalize(sample, sampleLen);
if (!normalized.normalized.empty()) {
    ctx.fields.push_back({"body", normalized.normalized, true});

    char msg[256];
    snprintf(msg, sizeof(msg),
             "[RaspAmsi][normalizer] rawLen=%zu normalizedLen=%zu truncated=%d utf16=%d b64=%d nulls=%d\n",
             normalized.rawLen,
             normalized.normalizedLen,
             normalized.truncated ? 1 : 0,
             normalized.decodedUtf16Le ? 1 : 0,
             normalized.decodedBase64 ? 1 : 0,
             normalized.hadNullBytes ? 1 : 0);
    OutputDebugStringA(msg);
}
```

禁止保留：

- `ScriptSessionKey`
- `SessionContextView`
- `SessionKeyConfidence`
- `m_sessionCache`
- `UpdateAndBuildView()`
- `sessionAggregated`
- `sessionTruncated`
- `sessionBypassed`

## 4. 保留的实验资产

以下文件保留，不删除：

| 文件 | 保留原因 | 状态 |
|---|---|---|
| `src/rasp_mod_amsi/include/script_session_context_cache.h` | 后续 session 聚合研究资产 | Dormant / Experimental |
| `src/rasp_mod_amsi/src/script_session_context_cache.cpp` | 后续 session 聚合研究资产 | Dormant / Experimental |
| `src/rasp_mod_amsi/tests/session_context_cache_tests.cpp` | 维护实验组件行为 | Experimental test |
| `scripts/test_phase3_batch2_session_context.ps1` | 可用于手动验证实验组件 | Experimental test script |
| `docs/phase3_batch2_session_context_design.md` | 保留设计背景 | Dormant design |

建议在 `script_session_context_cache.h` 顶部补充：

```cpp
// Dormant / experimental component.
// Not wired into the production AMSI scan path in the current release.
// Keep tests for future research; do not include this header from
// amsi_rule_engine.h unless session aggregation is explicitly re-enabled.
```

建议在 `docs/phase3_batch2_session_context_design.md` 顶部补充：

```markdown
Status: Dormant / Experimental
Production state: Not wired into current AMSI scan path
Release commitment: Not supported in current version
```

## 5. 生产 target 依赖图断开

必须达成：

- `rasp_mod_amsi.dll` 不编译 `src/script_session_context_cache.cpp`。
- `rasp_mod_amsi.dll` 的生产头文件不 include `script_session_context_cache.h`。
- `amsi_rule_engine.h/.cpp` 不出现 session cache 类型或调用。
- `engine_runtime_tests` 不再链接 `script_session_context_cache.cpp`，除非测试目标明确标注为 experimental。
- `session_context_cache_tests` 可以继续单独编译 `src/script_session_context_cache.cpp`。

验证命令：

```powershell
rg -n "script_session_context_cache.cpp" src\rasp_mod_amsi\CMakeLists.txt
```

预期：只允许出现在 `session_context_cache_tests` block。

## 6. 测试分层

生产回归测试：

- `engine_runtime_tests`
- `script_input_normalizer_tests`
- `scan_budget_tests`
- `async_event_queue_tests`
- `rasp_mod_amsi` build

实验测试：

- `session_context_cache_tests`
- `scripts/test_phase3_batch2_session_context.ps1`

生产测试调整要求：

- `engine_runtime_tests.cpp` 不得继续断言 `I` + `EX` 跨 `AmsiRuleEngine::Evaluate()` 聚合命中。
- 如果保留该场景，应改为反向断言：

```text
first chunk "I" does not match
second chunk "EX" does not match
production scan path does not aggregate session chunks
```

实验测试保留要求：

- `session_context_cache_tests` 继续验证 append、4KB、TTL、LRU、CloseSession、并发等实验组件行为。
- 实验测试通过不代表当前版本支持生产 session 聚合。

## 7. 文档状态统一

需要统一标注 session 聚合状态的文档：

| 文档 | 修改要求 |
|---|---|
| `docs/phase3_batch2_session_context_design.md` | 顶部加入 dormant / experimental 状态 |
| `docs/edr_migration_boundary_plan.md` | session-context 描述改为未来候选能力，不是当前生产能力 |
| `docs/edr_migration_readiness_review.md` | 标注 session-context 为 dormant asset |
| 本文档 | 作为摘除方案 review 文档 |

统一表述：

```text
当前版本支持输入归一化和单段脚本检测。
当前版本不支持、不承诺 session 聚合检测。
ScriptSessionContextCache 保留为 dormant / experimental 研究资产。
```

## 8. 静态门禁规则

建议新增：

```text
scripts/check_session_aggregation_dormant.ps1
```

或扩展现有边界检查脚本。

规则 1：`amsi_rule_engine.h` 不得包含：

- `script_session_context_cache.h`
- `ScriptSessionContextCache`
- `m_sessionCache`

规则 2：`amsi_rule_engine.cpp` 不得包含：

- `ScriptSessionKey`
- `SessionContextView`
- `SessionKeyConfidence`
- `UpdateAndBuildView`
- `m_sessionCache`
- `sessionAggregated`
- `sessionTruncated`
- `sessionBypassed`

规则 3：`CMakeLists.txt` 中 `script_session_context_cache.cpp` 只允许出现在 `session_context_cache_tests` block。

规则 4：`engine_runtime_tests.cpp` 不得包含生产聚合断言文案：

- `session context exposes split token across chunks`
- `split token across chunks`
- 其他等价“生产链路跨 chunk 聚合命中”描述

### 8.1 CI 强制门禁

`check_session_aggregation_dormant.ps1` 必须纳入 CI，不允许只作为人工 review 辅助脚本。

CI 阶段建议：

```text
configure/build
  -> check_session_aggregation_dormant.ps1
  -> production regression tests
  -> experimental session_context_cache_tests
```

CI 失败条件：

- `amsi_rule_engine.h/.cpp` 出现 session cache 生产接入符号。
- `script_session_context_cache.cpp` 被生产 target 编译。
- `engine_runtime_tests` 继续断言生产链路跨 chunk 聚合命中。
- 文档中缺少统一 dormant 状态标签。

CI 语义：

- `session_context_cache_tests` 通过仅证明实验资产仍可维护。
- CI 不得把 `session_context_cache_tests` 作为当前版本生产能力验收。
- 如果未来任何 PR 重新接入 `ScriptSessionContextCache` 到 production scan path，必须先通过“重新启用门槛表”的架构评审。

## 9. 文件级修改清单

| 文件 | 修改内容 |
|---|---|
| `src/rasp_mod_amsi/include/amsi_rule_engine.h` | 移除 session cache include 和成员 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | 移除 session key/cache 调用，恢复 normalized body 直接进入检测 |
| `src/rasp_mod_amsi/CMakeLists.txt` | 从生产 target / 生产测试 target 断开 `script_session_context_cache.cpp` |
| `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp` | 删除或反转生产聚合测试 |
| `src/rasp_mod_amsi/include/script_session_context_cache.h` | 增加 dormant / experimental 注释 |
| `docs/phase3_batch2_session_context_design.md` | 增加当前版本不接生产链路说明 |
| `docs/edr_migration_boundary_plan.md` | 标注 session-context 为未来候选能力 |
| `docs/edr_migration_readiness_review.md` | 标注 session-context 为 dormant asset |
| `scripts/check_session_aggregation_dormant.ps1` 或现有脚本 | 增加生产链路禁止 session cache 门禁 |

## 10. 下游影响清单

| 下游对象 | 影响 | 处理方式 |
|---|---|---|
| `rasp_mod_amsi.dll` | 不再执行 session 聚合；检测输入恢复为单次 normalized body | 预期行为，需在 release note 标注 |
| `AmsiRuleEngine::Evaluate()` | 不再跨调用拼接 body | 更新生产测试，避免继续断言跨 chunk 命中 |
| Regex / Lua 规则 | 只看到当前 normalized chunk，不再看到 aggregated body | 规则命中结果可能减少跨 chunk 命中；当前版本接受 |
| `engine_runtime_tests` | 需要删除或反转 split-token 聚合测试 | 生产测试必须反映当前能力边界 |
| `session_context_cache_tests` | 继续保留 | 仅作为 experimental test |
| `scripts/test_phase3_batch2_session_context.ps1` | 不再代表生产能力验收 | 文案标注 experimental/dormant |
| `docs/phase3_batch2_session_context_design.md` | 原设计不能继续表达为当前版本能力 | 增加 dormant / experimental 状态 |
| `docs/edr_migration_boundary_plan.md` | session-context 应描述为未来候选能力 | 补充不是当前生产能力 |
| `docs/edr_migration_readiness_review.md` | session-context 应描述为 dormant asset | 补充当前未接生产链路 |
| CI / release gate | 需要防止 session 聚合回归接入 | 新增强制门禁脚本 |
| 安全能力声明 | 当前版本不支持 session aggregation bypass 收敛 | release note 明确说明 |

## 11. 实验资产 owner

`ScriptSessionContextCache` 作为 dormant / experimental 资产保留时，必须指定 owner，避免长期无人维护或被误接入生产。

建议 owner 规则：

| 资产 | Owner | 职责 |
|---|---|---|
| `script_session_context_cache.h/.cpp` | AMSI/RASP scanner-core owner | 保持可编译、可测试；禁止未评审接入生产 |
| `session_context_cache_tests.cpp` | 测试 owner / scanner-core owner | 保持实验测试通过；测试语义不得伪装成生产能力 |
| `phase3_batch2_session_context_design.md` | 架构 owner | 维护 dormant 状态和重新启用门槛 |
| `check_session_aggregation_dormant.ps1` | CI / build owner | 纳入 CI，确保门禁稳定 |

Owner 必须在正式实施 PR 或后续迁移文档中补实名或团队名。未指定 owner 前，不应继续扩大 session experimental 代码。

## 12. 重新启用门槛表

未来若要重新启用 session 聚合，必须作为独立 phase 重新评审，不允许直接恢复 `m_sessionCache.UpdateAndBuildView()`。

| 门槛 | 必须满足的条件 | 验收方式 |
|---|---|---|
| 真实 AMSI session key | Provider 能获取并传递真实 AMSI session id | fake / integration `IAmsiStream` 测试 |
| `CloseSession()` 清理 | `CRaspAmsiProvider::CloseSession()` 能清理对应 cache | Close 后同 key 不带旧上下文 |
| Key confidence 策略 | Strong / Medium / Weak / None 语义重新确认 | 单元测试 + 架构评审 |
| 跨线程策略 | 明确是否允许跨 tid 聚合 | 多线程测试 |
| 污染隔离 | 不同 pid/app/content/session 不互相污染 | 隔离测试 |
| 有界资源 | per-session 4KB、global cap、LRU、TTL 生效 | 压测 + 单测 |
| Scan 热路径预算 | 聚合不引入长锁、IPC、阻塞日志 | 性能测试 |
| Telemetry | hit/miss/bypass/evict/close 可观测 | telemetry 测试或 debug 断言 |
| 误报/漏报评估 | 通过样本回归证明收益大于风险 | 样本集回归 |
| CI 门禁更新 | dormant 检查切换为 enabled 检查 | CI 规则更新 PR |
| 文档状态更新 | dormant 改为 enabled，并列明版本 | 文档 PR |

未满足以上门槛时，session 聚合必须保持 dormant。

## 13. 验证计划

生产链路静态验证：

```powershell
rg -n "ScriptSessionContextCache|m_sessionCache|UpdateAndBuildView|SessionContextView|SessionKeyConfidence" `
  src\rasp_mod_amsi\include\amsi_rule_engine.h `
  src\rasp_mod_amsi\src\amsi_rule_engine.cpp
```

预期：无结果。

CMake 依赖验证：

```powershell
rg -n "script_session_context_cache.cpp" src\rasp_mod_amsi\CMakeLists.txt
```

预期：只出现在 `session_context_cache_tests`。

构建验证：

```powershell
cmake --build src\rasp_mod_amsi\build-codex --config Release --target `
  rasp_mod_amsi engine_runtime_tests session_context_cache_tests
```

测试验证：

```powershell
.\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
.\src\rasp_mod_amsi\build-codex\Release\session_context_cache_tests.exe
```

文档 / diff 验证：

```powershell
git diff --check
```

## 14. 风险与回滚

风险：

- 生产行为变化：跨 Scan 的 `I` + `EX` 不再命中。这是当前决策要求的预期变化。
- 测试语义冲突：旧生产聚合测试必须删除或反转，否则会与当前能力边界冲突。
- 文档误导：旧文档若不更新，会让 reviewer 误以为当前版本仍支持 session 聚合。

回滚：

- 如未来重新启用 session 聚合，必须作为新 phase 单独评审。
- 重新启用前必须补齐真实 AMSI session、`CloseSession()` 清理、key confidence、端到端测试和 telemetry。
- 不允许仅恢复 `m_sessionCache.UpdateAndBuildView()` 作为快速回滚。

## 15. 建议提交说明

```text
摘除生产链路中的 session 聚合接入

根据当前版本不启用 session 聚合的架构决策，将 ScriptSessionContextCache 从 AMSI 生产检测链路中摘除。

主要修改：
- AmsiRuleEngine 不再持有 ScriptSessionContextCache
- AmsiRuleEngine::Evaluate() 恢复为 normalizer -> body -> Regex/Lua 单段检测链路
- 生产 DLL 不再编译 script_session_context_cache.cpp
- engine_runtime_tests 不再证明生产 session 聚合能力
- 保留 script_session_context_cache.* 和 session_context_cache_tests 作为 dormant/experimental 资产
- 文档和静态门禁明确当前版本不支持 session 聚合

本次不删除实验实现，不接真实 AMSI session，不修改 LogForwardThreadProc / Shutdown / EDR 迁移代码。
```
