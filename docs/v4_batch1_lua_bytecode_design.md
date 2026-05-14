# v4 Batch 1：Lua source / bytecode 双路径兼容设计

## 1. 目标

Batch 1 只做 DLL 端兼容能力：

- 支持规则 JSON 中可选 `scriptEncoding`
- 支持 `source` / `bytecode` 双路径预编译
- 支持 Lua bytecode 在 `Run()` 中加载执行
- 保持旧 source 规则完全兼容
- 不接 HostGuard 侧 bytecode 编译
- 不迁 TLS Lua state
- 不改事件 schema / pipe / reload / snapshot 模型

一句话：让当前 DLL 能正确消费未来 HostGuard 可能下发的 bytecode，但当前 EXE 仍可继续下发 source 规则。

## 2. Bytecode 契约

必须写死以下语义：

- `scriptEncoding` 缺失：按 `source` 处理。
- `scriptEncoding == "source"`：按 `source` 处理。
- `scriptEncoding == "bytecode"`：按 bytecode 处理。
- bytecode 路径绝不拼接 `libSource`。
- bytecode 必须由上游提前包含 global library 语义。
- bytecode 校验失败：不缓存该规则，`IsLoaded(ruleId) == false`，不崩溃。
- source / bytecode 两条路径都必须继续受 Lua hook / ScanBudget 控制。

## 3. 修改范围

### 需要修改

`src/rasp_rule_engine/include/rasp_rule_base.h`

- `RaspRuleBase` 增加：

```cpp
std::string scriptEncoding; // "" / "source" / "bytecode"
```

`src/rasp_rule_engine/src/rule_json_parser.cpp`

- `ParseRulesArray()` 增加：

```cpp
else if (rkey == "scriptEncoding")
    p.read_string(rule.scriptEncoding);
```

`src/rasp_rule_engine/include/rasp_lua_engine.h`

- `Precompile()` 改为：

```cpp
void Precompile(const std::string& ruleId,
                const std::string& payload,
                bool isBytecode = false);
```

- 注释从 `source` cache 调整为 `payload` cache。

`src/rasp_rule_engine/src/rasp_lua_engine.cpp`

- `Precompile()` 增加 bytecode 分支。
- `Run()` 增加 bytecode/source 加载分支。
- 保留当前每次 `Run()` 新建 `lua_State` 的模型。
- 保留当前 `ScanExecutionContext`、Lua hook、timeout 逻辑。

`src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

- `AmsiRuleEngine::PrecompileAll()` 增加分支：
  - bytecode：`Base64Decode` 后直接 `Precompile(rule.id, decoded, true)`
  - source：`libSource + "\n" + decoded` 后 `Precompile(rule.id, combined, false)`

### 不修改

- 不修改 `src/rasp_sentry_native/src/rule_server.cpp`
- 不修改 `AsyncEventQueue`
- 不修改 `EventJsonBuilder`
- 不修改 pipe 名称 / 协议
- 不修改 `RuleSnapshot` 发布模型
- 不引入 `thread_local lua_State`
- 不新增 HostGuard prepared bundle

## 4. 核心实现设计

### 4.1 `RaspRuleBase`

新增字段：

```cpp
std::string scriptEncoding;
```

默认空字符串。语义：

```cpp
""         -> source
"source"  -> source
"bytecode"-> bytecode
其他值      -> source，并可记录日志
```

非法值不建议直接失败。为兼容旧规则和灰度数据，非法值降级 source 更安全。

### 4.2 `RuleJsonParser`

在现有 `scriptBodyBase64` 附近解析 `scriptEncoding`。

原则：

- 只读取字符串
- 不校验语义
- 不影响 unknown field / extension parser 行为

### 4.3 `RaspLuaEngine::Precompile`

建议内部语义从 `combinedSrc` 改为 `payload`。

伪代码：

```cpp
void RaspLuaEngine::Precompile(const std::string& ruleId,
                               const std::string& payload,
                               bool isBytecode)
{
    if (ruleId.empty() || payload.empty())
        return;

    if (isBytecode) {
        if (!IsLua54Bytecode(payload)) {
            Log("[RaspLuaEngine] Precompile: invalid bytecode header...");
            return;
        }

        std::lock_guard<std::mutex> lk(m_mutex);
        m_sources[ruleId] = payload; // 或后续改名 m_payloads
        return;
    }

    lua_State* L = luaL_newstate();
    if (!L)
        return;

    if (luaL_loadbuffer(L, payload.data(), payload.size(), ruleId.c_str()) != LUA_OK) {
        Log(...);
        lua_close(L);
        return;
    }

    lua_close(L);

    std::lock_guard<std::mutex> lk(m_mutex);
    m_sources[ruleId] = payload;
}
```

Bytecode 校验建议：

```cpp
static bool IsLua54Bytecode(const std::string& payload)
{
    static const unsigned char kLua54Magic[] = {0x1b, 'L', 'u', 'a', 0x54};
    return payload.size() >= sizeof(kLua54Magic) &&
           std::memcmp(payload.data(), kLua54Magic, sizeof(kLua54Magic)) == 0;
}
```

注意：Lua bytecode 可能包含 NUL，必须使用 `std::string::data()` + `size()`，不能使用 `c_str()` + strlen 语义。

### 4.4 `RaspLuaEngine::Run`

当前主线每次新建 `lua_State`，保留。

只改加载阶段：

```cpp
const bool isBytecode = IsLuaBytecodePayload(payload);

int loadRc = LUA_ERRSYNTAX;
if (isBytecode) {
    struct Reader {
        const char* data;
        size_t size;
        bool consumed;
    } reader{payload.data(), payload.size(), false};

    loadRc = lua_load(L, ReaderFn, &reader, ruleId.c_str(), "b");
} else {
    loadRc = luaL_loadbuffer(L, payload.data(), payload.size(), ruleId.c_str());
}
```

必须保持：

- `lua_sethook()` 仍在执行前设置
- `ClearLuaBudgetHook(L)` 仍在所有退出路径调用
- timeout 后仍转换为当前 `RaspLuaResult` 的 timeout 字段
- `lua_close(L)` 仍在所有退出路径执行

### 4.5 `AmsiRuleEngine::PrecompileAll`

伪代码：

```cpp
void AmsiRuleEngine::PrecompileAll(..., RaspLuaEngine& luaEngine)
{
    for (const auto& rule : rules) {
        if (rule.scriptBodyBase64.empty())
            continue;

        std::string decoded;
        if (!Base64Decode(rule.scriptBodyBase64, decoded)) {
            Log(...);
            continue;
        }

        const bool isBytecode = (rule.scriptEncoding == "bytecode");

        if (isBytecode) {
            luaEngine.Precompile(rule.id, decoded, true);
            continue;
        }

        std::string combined = libSource.empty()
            ? decoded
            : libSource + "\n" + decoded;

        luaEngine.Precompile(rule.id, combined, false);
    }
}
```

非法 `scriptEncoding`：

```cpp
const bool isBytecode = (rule.scriptEncoding == "bytecode");
// 其他值都按 source
```

可选日志：

```cpp
if (!rule.scriptEncoding.empty() &&
    rule.scriptEncoding != "source" &&
    rule.scriptEncoding != "bytecode") {
    Log("[RaspAmsi] PrecompileAll: unknown scriptEncoding=%s rule=%s; treating as source", ...);
}
```

## 5. 测试方案

### 必须新增 / 修改的测试

优先放在现有 `scan_budget_tests.cpp` 或新增轻量 `lua_bytecode_tests.cpp`。

测试 1：旧规则兼容

- 无 `scriptEncoding`
- source 脚本正常 `Precompile`
- `Run()` 正常 match

测试 2：显式 source

- `scriptEncoding = "source"`
- 结果与缺省一致

测试 3：非法 bytecode

- `scriptEncoding = "bytecode"`
- payload 是普通 Lua source
- `Precompile(..., true)` 后 `IsLoaded(ruleId) == false`
- 不崩溃

测试 4：真实 bytecode

- 测试中用 Lua API 临时生成 bytecode，避免硬编码不稳定二进制。
- `Precompile(ruleId, bytecode, true)`
- `Run()` 正常返回 matched

测试 5：bytecode 不拼接 libSource

- 构造 `libSource = "function helper() return true end"`
- 构造 bytecode payload 本身不依赖 `helper`
- 验证 `PrecompileAll()` 没有拼接 source 前缀
- 更直接的方式：通过 fake / helper 检查传给 `Precompile()` 的 payload 与 decoded bytecode 完全一致

测试 6：混合规则集

同一 rule set 包含：

- 无 `scriptEncoding`
- `source`
- `bytecode`

三者同时加载、执行，不互相影响。

测试 7：timeout 回归

- `while true do end`
- source 路径仍 timeout
- 如果可构造 bytecode 版本，也验证 bytecode 路径仍 timeout

## 6. 验收标准

构建验收：

- `rasp_mod_amsi.dll` Release build 通过
- `rasp_sentry.exe` 不要求修改，但现有 build 不应被破坏
- `engine_runtime_tests` 通过
- `scan_budget_tests` 通过
- 新增 bytecode/source 测试通过

功能验收：

- 旧规则缺 `scriptEncoding` 行为不变
- `scriptEncoding=source` 行为正确
- `scriptEncoding=bytecode` 可加载有效 Lua 5.4 bytecode
- 无效 bytecode 不缓存、不崩溃
- bytecode 路径不拼接 `libSource`
- source 和 bytecode 混跑正常

边界验收：

- 不修改 `rule_server.cpp`
- 不引入 HostGuard 规则编译
- 不引入 TLS Lua state
- 不修改事件 schema
- 不修改 reload / shutdown / snapshot 发布模型
- 不绕过 ScanBudget / Lua hook

## 7. 风险点

主要风险：

- bytecode header 判断过松或过严
- bytecode payload 含 NUL，误用 C 字符串 API
- bytecode 路径绕过 Lua hook
- `PrecompileAll()` 对 bytecode 误拼接 `libSource`
- source / bytecode 混合 rule set 中 reload 后状态不一致

缓解：

- 所有 payload 使用 `data()` + `size()`
- bytecode 只校验 Lua 5.4 magic，不尝试解析完整格式
- 继续每次 `Run()` 新建 `lua_State`
- 测试覆盖 source / bytecode / missing `scriptEncoding` 混跑
- reload 回归测试覆盖 old/new snapshot coexistence

## 8. 推荐实施顺序

1. 更新设计文档：新增 Batch 1 实施细节。
2. 先写测试：
   - source 缺省
   - source 显式
   - invalid bytecode
   - valid bytecode
   - mixed rules
3. 修改 `RaspRuleBase` 和 `RuleJsonParser`。
4. 修改 `RaspLuaEngine::Precompile()`。
5. 修改 `RaspLuaEngine::Run()`。
6. 修改 `AmsiRuleEngine::PrecompileAll()`。
7. 跑单测和构建。
8. 独立 commit / review。

## 9. 当前不做

Batch 1 明确不做：

- `rule_server.cpp::CompileToByteCode()`
- `CompileAllRulesToBytecode()`
- `thread_local lua_State`
- `m_generation`
- PCRE2 TLS resource cache
- perf counters
- build version
- stress tool
- HostGuard prepared bundle

当前最小闭环是：当前 DLL 能消费 `scriptEncoding`，且 source / bytecode 两条 Lua 加载路径都正确、受预算控制、与旧规则兼容。

