# v4 增量迁移到当前主线方案

## 文档范围

基线分支：当前主线 `codex`，最近确认提交为 `dccb420 统一命名管道为 amsi_detect`。

对比来源：`D:\Code\rasp\DetectPsV4`，仅作为能力块参考来源，不做整分支 merge，不做整文件覆盖。

路径约定：除特别说明外，本文路径均为当前仓库相对路径，例如 `src/rasp_rule_engine/src/rasp_lua_engine.cpp`。

迁移原则：

- 版本 1 / 当前主线为唯一生产基线。
- v4 只作为增量能力来源。
- 每个能力块必须按“设计、测试、最小实现、回归”单独迁移。
- 不把 HostGuard 完整规则编译/加载体系作为本阶段前置条件。

## 1. 一句话结论

当前最建议迁的 3 项：

1. `scriptEncoding` 字段解析 + `Precompile(..., isBytecode)` 的 source/bytecode 双路径。第一批只做 DLL 兼容能力，不先做 HostGuard/EXE 侧完整 bytecode 编译体系。
2. PCRE2 匹配资源复用能力，但这是“重设计项”，不是 v4 代码搬迁项。必须在保留当前 `ScanBudget`、match/depth/heap/subject limit 语义前提下重新设计 TLS 资源复用。
3. `perf_counters.h` 的零开销观测框架思想，可后置为可选编译能力，先不接入事件主链路。

当前不建议先迁的 3 项：

1. v4 的 `thread_local lua_State + generation` 整体实现。它会改变当前每次 `Run()` 独立 Lua state 的隔离语义，必须等待生命周期与并发测试稳定后再评审。
2. v4 `rule_server.cpp` 中完整 Lua bytecode 编译/下发体系。它依赖 HostGuard 规则打包语义，当前阶段不应先做。
3. build number 自动递增、stress tool、perf JSONL 周期上报整体接入。它们属于辅助观测，不应压在正则/Lua 主链迁移前。

## 2. 基线确认表

| 能力点 | 当前主线证据 | 当前是否存在 | v4 证据 | 迁移判断 |
|---|---|---:|---|---|
| `scriptEncoding` 字段 | `src/rasp_rule_engine/include/rasp_rule_base.h` 的 `RaspRuleBase` 仅有 `scriptBodyBase64` / `scriptEval`，无 `scriptEncoding` | 否 | `DetectPsV4/rasp_rule_engine/include/rasp_rule_base.h` 增加 `scriptEncoding` | P0 迁入 |
| `scriptEncoding` JSON 解析 | `src/rasp_rule_engine/src/rule_json_parser.cpp::ParseRulesArray()` 解析 `scriptBodyBase64`，未解析 `scriptEncoding` | 否 | `DetectPsV4/rasp_rule_engine/src/rasp_sentry_base.cpp::ParseRulesJson()` 解析 `scriptEncoding` | P0 迁入 |
| `Precompile(..., isBytecode)` | `src/rasp_rule_engine/include/rasp_lua_engine.h` 中 `Precompile(ruleId, combinedSrc)` 只有 source 参数 | 否 | `DetectPsV4/rasp_rule_engine/include/rasp_lua_engine.h` 声明 `Precompile(ruleId, payload, bool isBytecode=false)` | P0 迁入 |
| bytecode 加载 | `src/rasp_rule_engine/src/rasp_lua_engine.cpp::Run()` 总是 `luaL_loadbuffer()` 加载 source | 否 | v4 `Run()` 根据 payload magic 使用 `lua_load(..., "b")` | P0 迁入 |
| `PrecompileAll()` bytecode/source 分支 | `src/rasp_mod_amsi/src/amsi_rule_engine.cpp::PrecompileAll()` 总是 `libSource + decoded` 后 source 编译 | 否 | v4 `PrecompileAll()` 根据 `rule.scriptEncoding == "bytecode"` 分支 | P0 迁入 |
| PCRE2 compiled pattern cache | `src/rasp_rule_engine/src/rasp_lua_engine.cpp::GetOrCompilePcre2()` 已缓存 `pcre2_code*` | 是 | v4 同样存在 compiled pattern cache | 已具备 |
| PCRE2 TLS match resource cache | 当前 `MatchesAnyRegex()` 每次创建/释放 `pcre2_match_context` 与 `pcre2_match_data` | 否 | v4 `TlsPcre2Cache` 复用 match context/data | Batch 2 重设计 |
| PCRE2 ScanBudget / limit | 当前 `CreateBudgetedMatchContext()` 设置 `pcre2MatchLimit`、`pcre2DepthLimit`、`pcre2HeapLimitKiB`，并记录 limit | 是 | v4 固定 match limit，预算语义弱于当前主线 | 当前语义必须保留 |
| Lua timeout hook | 当前 `Run()` 已接入 `ScanExecutionContext` / Lua hook / timeout reason | 是 | v4 使用 instruction hook，但不包含当前完整预算上下文 | 当前语义必须保留 |
| TLS Lua state cache | 当前每次 `Run()` 新建独立 `lua_State` | 否 | v4 `thread_local TlsLuaCache` + `m_generation` | P2，需准入门槛 |
| RuleSnapshot 内嵌 Lua engine | `src/rasp_mod_amsi/include/amsi_rule_engine.h::RuleSnapshot` 包含 `std::shared_ptr<RaspLuaEngine>` | 是 | v4 使用成员 `m_luaEngine` | 当前模型不能回退 |
| perf counters | 当前主线未引入 `perf_counters.h` | 否 | v4 有 `perf_counters.h` / `RASP_TICK` / `RASP_ACCUM` | P1/P2 |
| rule server bytecode 编译 | 当前 `src/rasp_sentry_native/src/rule_server.cpp::BuildAssembledJson()` 不编译 Lua bytecode | 否 | v4 `CompileToByteCode()` / `CompileAllRulesToBytecode()` | 暂不先迁 |

## 3. 差异总结

### 正则编译 / 匹配链

v4 多了：

- `TlsPcre2Cache`，thread-local 保存 `pcre2_match_context* mctx` 和 `matchData` map。
- `MatchesAnyRegex()` 使用 `t_pcre2.GetOrCreate(re)` 复用 `pcre2_match_data`。

当前主线多了：

- `ScanExecutionContext* exec`
- `TryEnterRegexCall()`
- `BoundedRegexSubjectLength()`
- `pcre2MatchLimit / pcre2DepthLimit / pcre2HeapLimitKiB`
- `RecordRegexLimit()`

结论：

- v4 的 PCRE2 TLS 缓存是性能优化。
- 当前主线的预算/limit 语义比 v4 更完整。
- PCRE2 不是 code port，而是 design port。迁移目标不是照抄 v4，而是在保留当前 ScanBudget / match/depth/heap/subject limit 语义的前提下引入资源复用。

### Lua 编译 / 加载链

v4 多了：

- `scriptEncoding` 字段。
- `RaspLuaEngine::Precompile(ruleId, payload, isBytecode)`。
- `AmsiRuleEngine::PrecompileAll()` 根据 `rule.scriptEncoding == "bytecode"` 分支。
- `RaspLuaEngine::Run()` 对 bytecode 使用 `lua_load(..., "b")`。
- `thread_local TlsLuaCache` 缓存 `lua_State + funcRef`，通过 `m_generation` 失效。

当前主线状态：

- 未解析 `scriptEncoding`。
- 每次 `Run()` 新建独立 `lua_State`。
- 已接入 `ScanExecutionContext` / Lua hook / timeout reason。
- `RuleSnapshot` 已持有独立 `RaspLuaEngine`，reload 并发安全模型与 v4 不同。

结论：

- `scriptEncoding + Precompile bytecode/source 双路径` 是功能增强，适合优先迁。
- `thread_local lua_State + generation` 是高风险性能优化，不建议第一批迁。

### 观测 / 辅助能力

v4 多了：

- `perf_counters.h`
- `RASP_TICK` / `RASP_ACCUM`
- `PerfCounters`
- `build_version.h`
- `rasp_amsi_stress.cpp`

结论：

- perf counters 属于低侵入观测基础，可后置迁。
- build version / stress tool 不影响检测语义，应放 P2。

### 功能增强 / 性能优化 / 高风险改动

功能增强：

- `scriptEncoding`
- bytecode/source 双路径
- rule server bytecode 编译

性能优化：

- TLS PCRE2 match resource cache
- TLS Lua state cache
- perf counters
- stress tool

高风险改动：

- TLS Lua state：改变 Lua 全局状态隔离、timeout 后 state 复用、snapshot 生命周期语义。
- rule server bytecode 编译：依赖 Lua 版本、bytecode 兼容性、HostGuard 规则包格式。
- 直接迁 v4 PCRE2 TLS cache：会弱化当前主线已有协作式预算和 PCRE2 limit。

## 4. Batch 1 bytecode 契约

Batch 1 只实现 DLL 端兼容 bytecode 的能力，不要求 EXE / HostGuard 立即生成 bytecode。

硬约束：

1. `scriptEncoding` 缺失时，DLL 必须按 source 处理。
2. `scriptEncoding == "source"` 时，DLL 按 source 处理。
3. `scriptEncoding == "bytecode"` 时，DLL 端绝不再拼接 `libSource`。
4. 如果服务端未来下发 bytecode，必须保证 bytecode 已经包含 global library 语义。
5. 如果服务端下发的 bytecode 未包含 global library，DLL 不做补救，规则可能因缺依赖而不命中。
6. bytecode 校验失败时，`Precompile()` 不缓存该规则，`IsLoaded(ruleId)` 返回 false，不得崩溃。
7. bytecode 路径必须和 source 路径一样受 Lua hook / ScanBudget 约束。

解释：

- v4 `rule_server.cpp::PrependLibToRuleScript()` 先把 global lib 与 rule script 合并，再 `lua_dump()`。
- v4 `AmsiRuleEngine::PrecompileAll()` 在 bytecode 路径直接 `Precompile(rule.id, decoded, true)`，不再拼接 `libSource`。
- 当前主线 Batch 1 必须固化这一契约，否则 source/bytecode 混跑时会出现隐藏依赖缺失。

## 5. 迁移优先级

### P0：现在就值得迁

- `scriptEncoding` 字段解析。
- `RaspLuaEngine::Precompile(..., isBytecode)` 的 bytecode 验证与缓存。
- `RaspLuaEngine::Run()` bytecode/source 加载分支。
- `AmsiRuleEngine::PrecompileAll()` source/bytecode 分支。

### P1：第二批再迁

- PCRE2 资源复用重设计。
- `rule_server.cpp` 的 `CompileToByteCode()` / `CompileAllRulesToBytecode()`，前提是先冻结 demo Host / HostGuard 的规则 envelope。
- `perf_counters.h` 基础结构，不先接 pipe/event 周期上报。

### P2：可后置

- `thread_local lua_State + generation`。
- build number 自动递增。
- perf JSONL 周期 emit。
- stress tool。
- HostGuard 侧 prepared bundle / bytecode 全量规则编译体系。

## 6. TLS Lua cache 准入门槛

`thread_local lua_State + generation` 不进入 Batch 1。

只有同时满足以下条件，才允许启动 TLS Lua cache 设计评审：

1. 当前主线 reload / unload / shutdown 生命周期已稳定。
2. 当前 `RuleSnapshot` / `RaspLuaEngine` 持有关系已经冻结，不再回退到全局 `m_luaEngine`。
3. 已有并发测试覆盖 reload 中 scan、timeout 中 scan、unload 中 scan。
4. 已明确 timeout 后 lua_State 是否可复用，以及 dirty state 如何处理。
5. 已明确 TLS cache 在 DLL unload / thread detach / engine snapshot 销毁时的资源释放策略。

未满足这些条件时，TLS Lua cache 只保留为 P2 性能优化，不进入开发。

## 7. 函数级迁移清单

| 建议项 | 文件 | 类 / 函数 | 迁移原因 | 依赖项 | 风险点 |
|---|---|---|---|---|---|
| `scriptEncoding` 字段 | `src/rasp_rule_engine/include/rasp_rule_base.h` | `RaspRuleBase` | 让 DLL 能识别 source vs bytecode | `RuleJsonParser` 同步解析 | 默认值必须兼容旧规则 |
| 解析 `scriptEncoding` | `src/rasp_rule_engine/src/rule_json_parser.cpp` | `ParseRulesArray()` | 当前主线不解析该字段 | `RaspRuleBase::scriptEncoding` | 不能破坏 `ParseRuleExtension()` 旧行为 |
| Precompile 双路径 | `src/rasp_rule_engine/include/rasp_lua_engine.h` | `RaspLuaEngine::Precompile()` | 支持 bytecode 直接缓存 | Lua 5.4 bytecode magic 校验 | 校验失败必须不缓存 |
| Precompile 双路径实现 | `src/rasp_rule_engine/src/rasp_lua_engine.cpp` | `RaspLuaEngine::Precompile()` | source 语法检查，bytecode 头校验 | `m_sources` 需调整为 payload 语义 | source / bytecode 误判会导致规则失效 |
| bytecode 加载 | `src/rasp_rule_engine/src/rasp_lua_engine.cpp` | `RaspLuaEngine::Run()` | `lua_load(..., "b")` 加载 bytecode | 当前 Lua hook / budget 逻辑 | 必须保留 `ScanExecutionContext` timeout |
| PrecompileAll 分支 | `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | `AmsiRuleEngine::PrecompileAll()` | bytecode 不应再拼接 `libSource` | `scriptEncoding` | Host 侧未包含 lib 时 bytecode 规则缺依赖 |
| PCRE2 TLS 资源复用 | `src/rasp_rule_engine/src/rasp_lua_engine.cpp` | `MatchesAnyRegex()` | 减少每次匹配资源创建释放 | 当前 `ScanExecutionContext` | 重设计项，不能照抄 v4 |
| perf counters | `src/rasp_rule_engine/include/perf_counters.h` | `PerfCounters` / `RASP_TICK` / `RASP_ACCUM` | 可选性能观测 | CMake option | 不应先接事件 pipe |
| rule server bytecode 编译 | `src/rasp_sentry_native/src/rule_server.cpp` | `CompileToByteCode()` / `CompileAllRulesToBytecode()` | 将 Lua 编译成本移出 DLL | Lua static build、规则 envelope | 暂不建议第一批迁 |

## 8. 实施批次建议

### Batch 1：低风险高收益

目标：

- 当前主线具备兼容 bytecode 规则的能力。
- 不要求 HostGuard / EXE 立即生成 bytecode。
- 不改变当前 Lua state 隔离模型。

允许改动：

- `RaspRuleBase` 增加 `scriptEncoding`。
- `RuleJsonParser` 解析 `scriptEncoding`。
- `RaspLuaEngine::Precompile()` 增加 `bool isBytecode = false`。
- `RaspLuaEngine::Run()` 支持 source / bytecode 加载分支。
- `AmsiRuleEngine::PrecompileAll()` 根据 `scriptEncoding` 分支。

禁止改动：

- 不迁 `thread_local lua_State`。
- 不改 HostGuard / rule_server 生成 bytecode。
- 不改事件 schema。
- 不改 reload/snapshot 发布模型。
- 不改 Lua timeout hook 语义。

### Batch 2：PCRE2 资源复用重设计

目标：

- 优化正则热路径资源复用。
- 保留当前 ScanBudget / PCRE2 limit 语义。

迁移定位：

- 这是 design port，不是 code port。
- 迁移目标不是照抄 v4 代码。
- 迁移目标是在保留当前 `ScanBudget` / match/depth/heap/subject limit 语义的前提下，引入 `pcre2_match_data` / `pcre2_match_context` 资源复用。

允许改动：

- 设计新的 TLS PCRE2 match resource cache。
- 可复用 `pcre2_match_data`。
- 可复用或池化 `pcre2_match_context`，但每次匹配前必须按 `ScanExecutionContext` 设置 limit。

禁止改动：

- 不绕过 `TryEnterRegexCall()`。
- 不取消 `BoundedRegexSubjectLength()`。
- 不取消 `RecordRegexLimit()`。
- 不固定使用 v4 的 `500000` limit 覆盖当前 budget。
- 不让 Lua 内 `regex_match` / `regex_capture` 与 C++ `MatchesAnyRegex()` 使用不同预算语义。

### Batch 3：观测与辅助能力

目标：

- 提供可选观测。
- 不改变检测语义。

允许改动：

- 引入 `perf_counters.h`。
- CMake 增加 `RASP_PERF_ENABLED` option，默认 OFF。
- `RaspLuaEngine` 可选注入 `PerfCounters*`。
- 独立 stress tool。

禁止改动：

- 不在 Scan 热路径同步写 pipe / 文件。
- 不默认开启 perf event 周期上报。
- 不和生产事件 schema 绑定。

## 9. 当前主线需要同步修改的落点

### 需要改的 `.h`

- `src/rasp_rule_engine/include/rasp_rule_base.h`
  - 增加 `std::string scriptEncoding;`
- `src/rasp_rule_engine/include/rasp_lua_engine.h`
  - `Precompile()` 增加 `bool isBytecode = false`。
  - 注释从 source cache 调整为 payload cache。
- `src/rasp_mod_amsi/include/amsi_rule_engine.h`
  - 如果 `PrecompileAll()` 签名不变，仅实现内部改动；不需要暴露新 API。
- Batch 3 可新增：
  - `src/rasp_rule_engine/include/perf_counters.h`

### 需要改的 `.cpp`

- `src/rasp_rule_engine/src/rule_json_parser.cpp`
  - 解析 `scriptEncoding`。
- `src/rasp_rule_engine/src/rasp_lua_engine.cpp`
  - `Precompile()` bytecode/source 双路径。
  - `Run()` bytecode/source 加载分支。
  - Batch 2 再改 `MatchesAnyRegex()` TLS 资源复用。
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
  - `PrecompileAll()` 根据 `scriptEncoding` 分支。

### 暂不建议第一批改的文件

- `src/rasp_sentry_native/src/rule_server.cpp`
- `src/rasp_sentry_native/CMakeLists.txt`
- `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/include/build_version.h`

### 调用点同步

- 所有 `luaEngine.Precompile(rule.id, combined)` 调用保持兼容，默认 `isBytecode=false`。
- `scan_budget_tests.cpp` 中直接调用 `Precompile()` 的测试应无需改，除非新增 bytecode 测试。
- `AmsiRuleEngine::PrecompileAll()` 必须保证 bytecode 路径不拼接 `libSource`。

## 10. 测试与验收建议

### Batch 1 迁移验收

必须测试：

- 旧 source 规则无 `scriptEncoding` 时仍正常命中。
- `scriptEncoding: "source"` 明确 source 路径正常命中。
- `scriptEncoding: "bytecode"` 且 payload 非 Lua bytecode 时不缓存，`IsLoaded(ruleId) == false`，不崩溃。
- 构造 Lua 5.4 bytecode 后，`Precompile(..., true)` + `Run()` 正常命中。
- `scriptEncoding == "bytecode"` 时 `PrecompileAll()` 不拼接 `libSource`。
- source 规则、bytecode 规则、无 `scriptEncoding` 规则三者在同一 rule set 下混跑。
- reload 前后同时存在 old snapshot / new snapshot 时，source 和 bytecode 两种 payload 都不崩溃。
- Lua timeout 测试仍通过，尤其 `while true do end` 仍被 hook 中断。

最容易出事故：

- bytecode 被当成 source 走 `luaL_loadbuffer()`。
- source 被误判 bytecode。
- bytecode 路径绕过现有 Lua budget hook。
- `scriptEncoding` 缺字段时兼容性破坏。
- bytecode 规则缺 global lib 依赖导致静默不命中。

### Batch 2 迁移验收

必须测试：

- regex call limit 仍生效。
- subject length limit 仍生效。
- catastrophic regex 仍触发 match/depth/heap limit。
- 多线程并发 regex match 不崩溃。
- 同一线程重复 match 不重复创建 match_data，可通过测试 seam 或 perf counter 验证。
- Lua 内 `regex_match` / `regex_capture` 与 C++ `MatchesAnyRegex()` 预算语义保持一致。
- PCRE2 资源复用改造后，Lua 里的 `regex_match` / `regex_capture` 与 C++ `MatchesAnyRegex()` 行为一致。

最容易出事故：

- TLS match context 固定 limit，覆盖当前 per-scan budget。
- TLS match_data keyed by stale `pcre2_code*`，在 snapshot/engine 销毁后存在悬挂语义。
- 复用资源导致 JIT on/off limit 行为不一致。
- Lua regex 内建与 C++ regex path 预算语义漂移。

### Batch 3 迁移验收

必须测试：

- `RASP_PERF_ENABLED` OFF 时构建无额外依赖、无行为变化。
- ON 时 atomic counters 多线程更新正确。
- 不在 Scan 热路径同步写 pipe / 日志 / 文件。
- stress tool 独立构建，不影响 `rasp_mod_amsi.dll`。

## 11. 最小下一步

建议下一步只做 Batch 1 设计与实现评审：

- `scriptEncoding`
- `Precompile(source/bytecode)`
- `Run(source/bytecode 分支)`
- `PrecompileAll()` 分支

暂不进入：

- PCRE2 TLS 资源复用实现。
- TLS Lua state cache。
- rule_server bytecode 编译。
- perf counters / stress tool。

## 最终建议

先做 Batch 1。它能让当前主线向 v4 bytecode/source 双路径靠拢，同时不触碰当前最敏感的 Lua state 生命周期和 HostGuard 规则编译体系。

PCRE2 TLS 复用值得做，但必须按当前 `ScanBudget` 重新设计，不应直接复制 v4。

