# Phase 3 Batch 2: ScriptSessionContextCache 设计方案

## 1. 目标

本批只实现 `ScriptSessionContextCache`，用于改善分段 PowerShell 脚本输入的上下文完整性。组件应按未来 `scanner-core/session-context` 边界设计，当前可以先放在 `src/rasp_mod_amsi` 下，后续物理迁移时不应重写。

核心目标：

- 基于 `ScriptSessionKey` 做有界 session 聚合。
- 每个 session view 严格不超过 4KB。
- 支持 TTL、LRU、全局内存上限。
- 支持 `CloseSession()` / `Clear()`。
- key 不可靠、缓存不可用、内存压力、TTL/LRU 淘汰时降级为当前 chunk 检测。
- 不新增检测能力、不修改事件 schema、不改 Phase 2 runtime。

## 2. 开发边界

允许：

- 基于 `ScriptSessionKey` 的有界 session 聚合。
- 每 session 4KB 上限。
- LRU / TTL / 全局内存上限。
- CloseSession / Clear / shutdown cleanup。
- 拆分脚本、LRU、TTL、并发、内存上限测试。

禁止：

- 依赖 `IAmsiStream*`。
- 依赖 `RuleSnapshot*`。
- 依赖 Lua state / PCRE2 runtime 对象。
- 依赖 sentry pipe / EDR SDK / DB。
- 在 Scan 热路径等待清理线程、IPC、EDR、磁盘日志。
- 引入清理线程。
- 引入 session 以外的新检测能力。
- 修改事件 schema / DB。
- 修改 Phase 2 runtime 状态机。

## 3. 文件规划

新增文档：

- `docs/phase3_batch2_session_context_design.md`

新增代码：

- `src/rasp_mod_amsi/include/script_session_context_cache.h`
- `src/rasp_mod_amsi/src/script_session_context_cache.cpp`
- `src/rasp_mod_amsi/tests/session_context_cache_tests.cpp`
- `scripts/test_phase3_batch2_session_context.ps1`

命名必须保持平台无关。不要命名为 `amsi_session_context_cache.*`。AMSI 侧如需做 key 适配，后续单独使用 `amsi_session_key_adapter.*`。

## 4. 核心接口

```cpp
enum class SessionKeyConfidence {
    Strong,
    Medium,
    Weak,
    None
};

struct ScriptSessionKey {
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t amsiSession = 0;
    std::string contentNameHash;
    SessionKeyConfidence confidence = SessionKeyConfidence::None;
};

struct SessionContextView {
    std::string body;
    bool aggregated = false;
    bool truncated = false;
    bool cacheBypassed = false;
};

struct SessionContextCacheConfig {
    size_t perSessionMaxBytes = 4096;
    size_t globalMaxBytes = 1024 * 1024;
    size_t maxSessions = 1024;
    uint64_t strongTtlMs = 60000;
    uint64_t mediumTtlMs = 30000;
    uint64_t weakTtlMs = 5000;
};

class ScriptSessionContextCache {
public:
    explicit ScriptSessionContextCache(SessionContextCacheConfig config = {});

    SessionContextView UpdateAndBuildView(
        const ScriptSessionKey& key,
        std::string_view normalizedChunk,
        uint64_t nowMs);

    void CloseSession(const ScriptSessionKey& key);
    void Clear();
};
```

`ScriptSessionContextCache` 不接收 raw sample，不调用 `ScriptInputNormalizer`。调用顺序必须是：

```text
raw sample -> ScriptInputNormalizer -> normalized chunk -> ScriptSessionContextCache
```

## 5. Key 置信度策略

| Confidence | 行为 |
|---|---|
| `Strong` | 正常聚合，使用 `strongTtlMs` |
| `Medium` | 短 TTL 聚合，使用 `mediumTtlMs` |
| `Weak` | 第一版降级单 chunk，不入 cache |
| `None` | 降级单 chunk，不入 cache |

第一版不启用 Weak 聚合。原因是弱 key 容易造成跨请求污染，误把不同脚本片段拼接到同一上下文。

## 6. 4KB 截断策略

采用严格总长度上限：`view.body.size() <= 4096`。marker 计入总长度。

```cpp
constexpr size_t kMaxViewBytes = 4096;
constexpr std::string_view kMarker = "\n/*<rasp_truncated>*/\n";
constexpr size_t kSuffixBytes = 1024;
constexpr size_t kPrefixBytes = kMaxViewBytes - kSuffixBytes - kMarker.size();
```

超过上限时：

```text
bounded = prefix(kPrefixBytes) + marker + suffix(kSuffixBytes)
```

验收必须断言：

```cpp
view.body.size() <= 4096
```

如果当前 chunk 自身超过 4KB，也必须返回当前 chunk 的有界视图，不能返回空。

## 7. 聚合拼接策略

Session aggregation 默认按 chunk 到达顺序直接 append normalized body。

禁止在普通 chunk 之间插入空格、换行或 delimiter，避免破坏跨 chunk token。例如：

```text
"I" + "EX" -> "IEX"
```

只有发生截断时才允许插入 `kMarker`。

## 8. Current Chunk Visibility Gate

`ScriptSessionContextCache` 是上下文增强组件，不是输入过滤组件。

任何情况下不得因为缓存不可用、key 不可靠、TTL/LRU/内存限制而返回空 body 或丢弃当前 chunk。除非 `normalizedChunk` 本身为空，否则 `view.body` 必须非空，并且必须包含当前 chunk 的有界表示。

具体要求：

- cache 正常：返回历史上下文 + 当前 chunk 的 4KB bounded view。
- TTL 过期：丢弃历史，但返回当前 chunk。
- LRU 淘汰：当前 session 重新建立，返回当前 chunk。
- `Weak/None`：不入 cache，但返回当前 chunk。
- `globalMaxBytes` 压力：可以淘汰历史 session，但不能丢当前 chunk。
- 内部异常或配置异常：降级返回当前 chunk。
- 当前 chunk 自身超过 4KB：返回当前 chunk 的 4KB bounded view。
- 空 chunk 可以返回空，但不能崩溃。

## 9. Lazy Cleanup 策略

第一版不引入清理线程。

`UpdateAndBuildView()` 内部顺序：

1. 如果 key 不可靠，直接返回当前 chunk bounded view。
2. 淘汰当前时间下过期 session。
3. 查找或创建当前 session。
4. 追加当前 normalized chunk。
5. 对当前 session body 做 4KB bounded view。
6. 更新 LRU。
7. 依据 `maxSessions` 淘汰 LRU。
8. 依据 `globalMaxBytes` 淘汰 LRU。
9. 返回当前 session view。

`CloseSession()` 精确删除指定 key。`Clear()` 清空全部 session。

## 10. 内存统计门禁

`globalMaxBytes` 和 `perSessionMaxBytes` 的统计必须以实际缓存 body 的字节数为准，不能只按 chunk 长度粗略累加。

要求：

- 更新同一个 session 时，global memory 必须先扣除旧 body size，再加上新 body size。
- session 被 LRU 淘汰时，global memory 必须扣除该 session 当前 body size。
- `CloseSession()` 删除 session 后，global memory 必须回落。
- `Clear()` 后，global memory 必须归零。
- 当前 chunk 降级单 chunk 且不入 cache 时，不应增加 global memory。
- `view.body` 的临时返回值不计入缓存内存，只有实际存入 cache 的 session body 计入。

测试必须覆盖这些内存回落场景。

## 11. 锁边界

第一版可以使用 `std::mutex` 保护 map / LRU / 内存计数。

允许锁内：

- 查找 session。
- 更新 session body。
- 更新 LRU。
- 更新 TTL。
- 更新内存计数。
- 执行 bounded string copy。

禁止锁内：

- normalizer。
- Lua。
- PCRE2。
- IPC。
- event sink。
- 磁盘日志。
- EDR SDK 调用。
- DB 写入。

锁内字符串大小被 `perSessionMaxBytes` 限制，避免大字符串扩容拖慢 Scan 热路径。

## 12. AMSI 接入边界

AMSI 侧只做 key 适配：

```text
AMSI session / pid / tid / contentName -> ScriptSessionKey + SessionKeyConfidence
```

`ScriptSessionContextCache` 不知道 AMSI，不 include AMSI / COM 头。

接入点建议放在 `AmsiRuleEngine` 输入链路中：

```text
raw sample
 -> ScriptInputNormalizer
 -> ScriptSessionContextCache::UpdateAndBuildView
 -> RaspLuaContext.body
 -> Evaluate
```

如果 key 不可靠、cache 异常、TTL/LRU/内存淘汰发生，必须降级单 chunk 检测。

## 13. 测试方案

新增 `session_context_cache_tests.cpp`，先写 RED 测试。

必须覆盖：

1. 单 chunk 原样返回。
2. `"I"` + `"EX"` 聚合后包含 `"IEX"`。
3. chunk 间不插入空格。
4. `view.body.size() <= 4096`，包括 marker。
5. 当前 chunk 超过 4KB 时返回 bounded 当前 chunk。
6. `SessionKeyConfidence::Weak` 降级单 chunk。
7. `SessionKeyConfidence::None` 降级单 chunk。
8. 同一个 pid/tid 但不同 `contentNameHash` 不互相污染。
9. 同一个 `contentNameHash` 但不同 pid 不互相污染。
10. TTL 到期后，新 chunk 不带旧上下文。
11. LRU 淘汰后，旧 session 再来时从单 chunk 开始。
12. `CloseSession()` 后同 key 再来不带旧上下文。
13. `Clear()` 后全量清空且 global memory 归零。
14. 大量小 chunk 累积不会突破 per-session 4KB。
15. 大量 session 不会突破 `globalMaxBytes`。
16. 多线程同 key 更新不崩、不越界。
17. 多线程不同 key 更新不崩、不越界。
18. TTL 过期后仍返回当前 chunk。
19. LRU 压力下仍返回当前 chunk。
20. global memory 压力下仍返回当前 chunk。
21. 更新同一个 session 后，global memory 不重复累加旧 body。
22. session 被 LRU / `CloseSession()` / `Clear()` 删除后，global memory 正确回落。
23. 空 chunk 不崩溃。

## 14. 边界检查脚本

新增 `scripts/test_phase3_batch2_session_context.ps1`。

检查内容：

- 构建 `rasp_mod_amsi.dll`。
- 运行 `session_context_cache_tests.exe`。
- 运行 Phase 2 回归：`engine_runtime_tests`、`scan_budget_tests`、`async_event_queue_tests`。
- 运行 Phase 3 Batch 1 回归：`script_input_normalizer_tests`。
- 静态检查 `script_session_context_cache.*` 不包含 forbidden 依赖。

Forbidden patterns：

```text
IAmsiStream
IAntimalwareProvider
RuleSnapshot
lua_State
pcre2
rasp_sentry_rules
rasp_sentry_events
rasp_sentry_config
CreateNamedPipe
ConnectNamedPipe
EDR
SQL
database
```

## 15. 验收标准

- `ScriptSessionContextCache` 不依赖 AMSI / COM / Lua / PCRE2 / sentry / EDR / DB。
- 每 session 和全局内存都有硬上限。
- `view.body.size() <= 4096`。
- TTL / LRU / CloseSession / Clear 生效。
- `Weak/None` key 安全降级单 chunk。
- 任何非空当前 chunk 都不会因 cache 状态被丢弃。
- 内存统计以实际缓存 body 字节数为准。
- Scan 热路径不等待 IPC、EDR、磁盘日志、清理线程。
- Phase 2 和 Phase 3 Batch 1 回归测试继续通过。
- 本批独立 commit，便于单独 review 和回滚。

## 16. 最终开发顺序

1. 写 `docs/phase3_batch2_session_context_design.md`。
2. 写 `session_context_cache_tests.cpp`，先 RED。
3. 实现 `script_session_context_cache.h/.cpp`。
4. 跑 `session_context_cache_tests`。
5. 接入 `AmsiRuleEngine` 输入链路。
6. 跑 Phase 2 / Phase 3 Batch 1 回归。
7. 跑边界检查脚本。
8. 独立 commit / review。
Status: Dormant / Experimental

Production state: Not wired into current AMSI scan path

Release commitment: Not supported in current version
