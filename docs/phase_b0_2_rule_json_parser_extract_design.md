# Phase B0-2 RuleJsonParser 抽离设计

## 1. 目标

Phase B0-2 的目标是把 `RaspSentryBase::ParseRulesJson()` 以及当前嵌套 `Parser` 中的纯 JSON 规则解析逻辑抽离到独立 `RuleJsonParser`，为后续 `rule-runtime` 拆分提供低风险边界。

本批不是重写解析器，而是迁出已有解析逻辑，并证明新旧解析结果一致。

目标范围：

- 新增 `src/rasp_rule_engine/src/rule_json_parser.cpp`。
- 复用现有 `src/rasp_rule_engine/include/rule_json_parser.h` seam。
- 将 `Parser` nested struct 的纯 JSON reader 逻辑迁出。
- 将 `RaspSentryBase::ParseRulesJson()` 改为薄包装，继续作为旧入口存在。
- 保留 `IRuleObjectFactory` / `IRuleExtensionParser` 扩展机制，用于承接当前 `AllocRule()` 和 `ParseRuleExtension()` 行为。
- 增加 parser 单测，证明新 parser 与旧路径解析结果一致。

## 2. 非目标

本批明确不做以下事项：

- 不改 JSON 字段语义。
- 不改 rule reload 流程。
- 不改 `RuleSnapshot` 构建和发布流程。
- 不改事件发送逻辑。
- 不改日志逻辑。
- 不改 named pipe 协议。
- 不改 `rasp_sentry_native.exe` 兼容行为。
- 不改 AMSI Provider `Scan()` 返回语义。
- 不接入 EDR SDK。
- 不抽离 `SendDetectionEvent()` / `ConnectSentry()` / `ConfigPipeThreadProc()`。
- 不调整 Lua / PCRE2 / runtime / async event queue / session cache。

## 3. 现有行为基线

实现前需要以当前 `src/rasp_rule_engine/src/rasp_sentry_base.cpp` 为准梳理 `ParseRulesJson()` 和 nested `Parser` 的实际行为。

已确认并锁定的当前行为：

| 行为点 | 当前职责 | B0-2 要求 |
|---|---|---|
| JSON 顶层结构 | 解析 sentry 下发的规则 JSON | 新旧行为一致 |
| 规则对象创建 | 通过 `AllocRule()` 创建规则对象 | 迁出后通过 `IRuleObjectFactory` 调用 |
| 扩展字段解析 | 通过 `ParseRuleExtension()` 处理派生规则字段 | 迁出后通过 `IRuleExtensionParser` 调用 |
| 未知字段 | 由 parser 跳过或交给扩展解析 | 不改变处理语义 |
| 可选字段缺失 | 按旧默认值处理 | 不改变默认值 |
| 类型不匹配 | 按旧错误/跳过语义处理 | 不扩大容错，不新增强校验 |
| `libSource` | 从规则包中提取 Lua lib source | `RuleParseResult.libSource` 保持一致 |
| 空规则数组 | 按旧行为返回成功或空结果 | 不改变语义 |
| 异常 JSON | 返回失败语义 | 错误进入 `RuleParseResult.error` |

当前字段清单：

| JSON 字段 | 目标字段 | 当前行为 |
|---|---|---|
| `globalLibrariesBase64` | `libSourceOut` | 支持字符串数组；每项 Base64 解码后追加 `\n` |
| `globalLibraries` | `libSourceOut` | 同 `globalLibrariesBase64`，也接受裸字符串 |
| `rules` | `rulesOut` | 仅解析数组；非数组时跳过并继续 |
| `id` | `RaspRuleBase::id` | 字符串；空 id 的规则不加入输出 |
| `sensor` | `RaspRuleBase::sensor` | 字符串 |
| `enabled` | `RaspRuleBase::enabled` | bool；缺失时保持默认 `true` |
| `description` | `RaspRuleBase::description` | 字符串 |
| `severity` | `RaspRuleBase::severity` | 字符串 |
| `scriptBodyBase64` | `RaspRuleBase::scriptBodyBase64` | 字符串 |
| `scriptEval` | `RaspRuleBase::scriptEval` | 字符串 |
| `confidence` | `RaspRuleBase::confidence` | int；缺失时保持结构体默认值 |
| `mode` | `RaspRuleBase::mode` | `"block"` -> Block，`"off"` -> Off，其他值 -> Audit |
| `scriptTimeoutMs` | `RaspRuleBase::scriptTimeoutInstructions` | `ms * 50000`；结果小于等于 0 时回退 `500000` |
| `config.regexField` | `RaspRuleBase::regexField` | AMSI extension 解析，字符串 |
| `config.regexPatterns` | `RaspRuleBase::regexPatterns` | AMSI extension 解析，字符串数组 |
| `config.regexChecks[].id` | `RegexCheck::id` | 非空且 patterns 非空才加入 check |
| `config.regexChecks[].field` | `RegexCheck::field` | 字符串 |
| `config.regexChecks[].patterns` | `RegexCheck::patterns` | 字符串数组 |
| `config.regexCondition` | `RaspRuleBase::regexCondition` | `"all"` -> All，其他值 -> Any |
| 其他 rule 字段 | extension parser 或 skip | base parser 调用 `ParseRuleExtension(rkey, &parser, rule)` |
| 其他 top-level 字段 | 无 | `skip_value()` |

当前容错/默认行为：

- `json.empty()` 返回 false。
- 顶层不是 `{` 返回 false。
- rule object 不是 `{` 时跳过该元素。
- `read_string` 只处理简单反斜杠转义，不做完整 JSON Unicode unescape。
- 未知复杂对象/数组由 `skip_object()` / `skip_array()` 跳过。
- `ParseRulesJson()` 最终返回 `!rulesOut.empty()`；只有 global library 但没有有效规则时返回 false。
- 解析过程中遇到部分字段类型不匹配时，多数场景保持字段默认值并继续，除非破坏外层结构导致循环结束。

## 4. 新接口映射

目标调用关系：

```cpp
RaspSentryBase::ParseRulesJson(...)
    -> RuleJsonParser::Parse(json, factory, extensionParser)
```

B0-2 实现必须以当前已提交的 `src/rasp_rule_engine/include/rule_json_parser.h` 为准。本批不调整接口签名，避免把 parser 抽离扩大成规则类型重构。

当前接口语义：

```cpp
struct RuleParseResult {
    bool ok = false;
    std::vector<std::unique_ptr<RaspRuleBase>> rules;
    std::string libSource;
    std::string error;
};

class IRuleObjectFactory {
public:
    virtual ~IRuleObjectFactory() = default;
    virtual RaspRuleBase* CreateRule() const = 0;
};

class IRuleExtensionParser {
public:
    virtual ~IRuleExtensionParser() = default;
    virtual void ParseRuleExtension(const std::string& key,
                                    void* parserContext,
                                    RaspRuleBase& rule) = 0;
};

class RuleJsonParser {
public:
    RuleParseResult Parse(std::string_view json,
                          const IRuleObjectFactory& factory,
                          IRuleExtensionParser& extensionParser) const;
};
```

如果实现阶段认为 `CreateRule()` 应改为 `unique_ptr`、`RaspRuleBase` 应改为更窄的规则 DTO、或 `ParseRuleExtension()` 应增加返回值，必须作为独立 review 项处理，不允许混入 B0-2。

`RaspSentryBase` 在 B0-2 后仍然负责：

- 作为旧入口保留 `ParseRulesJson()`。
- 提供 `AllocRule()` 对应的 factory adapter。
- 提供 `ParseRuleExtension()` 对应的 extension parser adapter。
- 在调用方层面决定是否记录日志、是否保留旧规则、是否进入 reload_failed。

`RuleJsonParser` 只负责：

- 读取 JSON。
- 构造规则 DTO。
- 填充 `RuleParseResult`。
- 返回错误原因。

## 5. 错误语义

`RuleJsonParser` 不负责策略决策，只负责表达解析结果。

| 场景 | `ok` | `rules` | `libSource` | `error` | 调用方责任 |
|---|---:|---|---|---|---|
| 完整解析成功 | true | 已填充 | 已填充或空 | 空 | 正常继续 |
| 空规则包且旧行为允许 | true | 空 | 已填充或空 | 空 | 按旧行为继续 |
| 非法 JSON | false | 空或部分丢弃 | 空或已读值 | 错误描述 | 调用方记录日志并保留旧 snapshot |
| 类型不匹配且旧行为失败 | false | 空或部分丢弃 | 空或已读值 | 错误描述 | 调用方处理 reload_failed |
| factory 创建失败 | false | 已创建部分可丢弃 | 已读值 | 错误描述 | 调用方处理 |
| extension parser 失败 | 按旧行为 | 按旧行为 | 已读值 | 按旧行为 | 必须保持旧语义 |

要求：

- `RuleJsonParser` 内部不调用 `Log()`。
- `RuleJsonParser` 内部不发送 event。
- `RuleJsonParser` 内部不访问 pipe。
- `RuleJsonParser` 内部不修改 runtime state。
- 解析失败通过 `RuleParseResult.error` 返回，由调用方决定日志和降级策略。
- B0-2 实现前必须确认当前 `ParseRuleExtension()` 的失败表达方式：是否抛异常、是否内部吞掉、是否默认 skip、是否影响整包解析。
- 当前 `IRuleExtensionParser::ParseRuleExtension()` 返回 `void`，B0-2 不得在未单独 review 的情况下引入 bool 返回语义或改变失败传播方式。

当前失败语义确认：

- `RaspSentryBase::ParseRuleExtension()` 默认实现调用 `Parser::skip_value()`，不返回失败。
- `AmsiRuleEngine::ParseRuleExtension()` 只处理 `config`；`config` 不是对象时直接返回，不标记失败。
- AMSI extension 内部未知字段调用 `skip_value()`，不标记失败。
- AMSI extension 中字段读取失败通常 break/skip，并继续由外层 parser 收敛，不直接导致整包失败。
- 当前实现没有通过返回值表达 extension 失败；B0-2 必须保持该语义。

## 6. 行为一致性测试策略

B0-2 的测试重点不是“新 parser 能解析”，而是证明“新旧路径结果一致”。

B0-2 必须先建立 golden parser fixtures，再迁出实现。原因是 `RaspSentryBase::ParseRulesJson()` 迁出后会变成薄包装，届时已经没有独立旧路径可直接对比。

推荐流程：

1. 在迁出前，用当前旧 `ParseRulesJson()` 解析测试 JSON。
2. 将解析结果序列化为稳定的规则摘要 expected。
3. B0-2 实现后，用新 `RuleJsonParser` 解析同样 JSON。
4. 将新结果摘要与 expected 对比。

规则摘要至少包含：

- rule count。
- id / name / description / sensor / severity / action。
- enabled。
- methods / urlPatterns / tags。
- regex / pattern / check 字段。
- `libSource`。
- extension 字段解析结果。

测试结构：

```cpp
auto expected = LoadGoldenParserFixture(name);
auto newResult = ParseWithNewRuleJsonParser(json);

AssertEqual(expected.success, newResult.ok);
AssertEqual(expected.libSource, newResult.libSource);
AssertEquivalentRuleSummary(expected.rules, newResult.rules);
AssertEquivalentErrorSemantics(expected, newResult);
```

兜底方案：如果 golden fixture 无法覆盖某类旧行为，可以在测试中临时保留 `LegacyParseRulesJsonForTest`，仅用于 B0-2 测试，不进入生产路径，不作为长期兼容层。

如果旧路径不方便直接调用，可在生成 golden fixture 时新增测试专用派生类：

```cpp
class TestRaspSentryBase final : public RaspSentryBase {
public:
    using RaspSentryBase::ParseRulesJson;
    // 复用旧 AllocRule() / ParseRuleExtension() 行为或提供等价测试实现。
};
```

### 6.1 正常路径用例

- 单条规则。
- 多条规则。
- 空规则数组。
- 带 `libSource` 的规则包。
- 带 Lua 脚本字段的规则。
- 带 regex / pattern / check 字段的规则。
- 带 severity / action / sensor / description 的规则。
- enabled / disabled 规则。
- tags / methods / urlPatterns 等基础数组字段。

### 6.2 兼容路径用例

- 缺少可选字段。
- 未知字段。
- 字段顺序变化。
- 数组为空。
- bool / int / string 边界值。
- 未知复杂对象由 skip_value 跳过。
- 未知复杂数组由 skip_value 跳过。
- 扩展字段交给 `IRuleExtensionParser`。

### 6.3 异常路径用例

- 非法 JSON。
- 类型不匹配。
- 字符串未闭合。
- 数组未闭合。
- 对象未闭合。
- factory 创建 rule 失败。
- extension parser 返回失败。
- extension parser 抛出异常时的转换语义。

## 7. 依赖边界

`RuleJsonParser` 必须保持纯解析边界。

允许依赖：

- 标准库。
- 当前 JSON reader / parser 基础设施。
- 规则 DTO / rule config 类型。
- `IRuleObjectFactory`。
- `IRuleExtensionParser`。

禁止依赖：

- AMSI / COM 头文件。
- EDR SDK。
- DB / SQL 相关头文件。
- named pipe / Windows IPC API。
- `EngineRuntime`。
- `AsyncEventQueue`。
- `RaspLuaEngine`。
- PCRE2 runtime 对象。
- `IAmsiStream`。
- `RuleSnapshot` 发布逻辑。

禁止调用：

- `Log()`。
- `SendDetectionEvent()`。
- `SendDetectionEventSyncWorkerOnly()`。
- `ConnectSentry()`。
- `CreateNamedPipe()`。
- `ConnectNamedPipe()`。
- `ConfigPipeThreadProc()`。
- `OnReloadSignal()`。
- `OnUnloadSignal()`。

## 8. 静态检查扩展

B0-2 实现时需要扩展 `scripts/check_rasp_sentry_base_boundaries.ps1`。

新增检查目标：

- `src/rasp_rule_engine/src/rule_json_parser.cpp`
- `src/rasp_rule_engine/include/rule_json_parser.h`

`rule_json_parser.cpp` 不得出现：

- `Log(`
- `SendDetectionEvent`
- `ConnectSentry`
- `CreateNamedPipe`
- `ConnectNamedPipe`
- `rasp_sentry_rules`
- `rasp_sentry_events`
- `rasp_sentry_config`
- `EngineRuntime`
- `IAmsiStream`
- `windows.h`
- `amsi.h`

`rule_json_parser.h` 不得 include：

- AMSI / COM 相关头。
- EDR SDK。
- DB / SQL 相关头。
- pipe / IPC 相关头。

## 9. 回滚策略

B0-2 必须保持低风险可回滚。

回滚方式：

- 如果新 parser 与旧行为存在不可接受差异，停止接入新 parser。
- 保留旧 `RaspSentryBase::ParseRulesJson()` 实现作为回退路径。
- 新 `RuleJsonParser` 可暂时只作为测试路径存在，不切主路径。
- 不修改 reload / snapshot publish / event / log / pipe，因此回滚不涉及生命周期和协议。

不允许的回滚方式：

- 通过修改 JSON 字段语义来适配测试。
- 通过改变 reload 失败策略来掩盖 parser 差异。
- 通过事件或日志路径补偿 parser 行为差异。

## 10. 实施顺序

1. 保存并 review 本设计文档。
2. 补齐当前 `ParseRulesJson()` 字段清单和旧行为基线。
3. 确认当前 `ParseRuleExtension()` 失败语义。
4. 生成 golden parser fixtures。
5. 新增 parser 单测，先基于 golden fixture 构造一致性断言。
6. 新增 `src/rasp_rule_engine/src/rule_json_parser.cpp`。
7. 迁出 nested `Parser` 和纯 JSON 解析逻辑。
8. 将 `RaspSentryBase::ParseRulesJson()` 改为薄包装。
9. 扩展 `scripts/check_rasp_sentry_base_boundaries.ps1`。
10. 运行 parser 单测。
11. 运行 B0 边界检查。
12. 运行 Phase 2 / Phase 3 回归测试。
13. 独立 commit / review。

## 11. 验收标准

文档验收：

- `docs/phase_b0_2_rule_json_parser_extract_design.md` 存在。
- 目标、非目标、错误语义、依赖边界、测试策略、回滚策略明确。
- 明确 B0-2 不修改 reload / snapshot publish / event / log / pipe。
- 明确 B0-2 以当前 `rule_json_parser.h` 接口签名为准，不调整 `RaspRuleBase` / factory / extension parser 签名。
- 字段清单已补齐，否则不得开始迁出 Parser。
- `ParseRuleExtension()` 当前失败语义已确认，否则不得开始迁出 Parser。
- golden parser fixtures 已生成，否则不得切换主路径。

代码验收：

- `RuleJsonParser` 不调用日志、事件、pipe、runtime。
- `RaspSentryBase::ParseRulesJson()` 继续存在。
- 旧入口对外行为保持一致。
- JSON 字段语义保持一致。
- 解析失败通过 `RuleParseResult.error` 返回。

测试验收：

- parser 单测通过。
- 新旧解析路径输出一致。
- 异常 JSON 失败语义一致。
- extension parser 行为一致。
- factory 失败语义一致。

回归验收：

- `scripts/check_rasp_sentry_base_boundaries.ps1` 通过。
- Phase 2 runtime 测试通过。
- scan budget 测试通过。
- async event queue 测试通过。
- normalizer 测试通过。
- session-context 测试通过。
- `rasp_mod_amsi.dll` 构建通过。

## 12. 本批拒绝事项

以下做法在 B0-2 中应直接拒绝：

- 一次性拆掉 `RaspSentryBase` 的 pipe / event / reload / log 主链路。
- 抽 parser 时顺手修改 JSON 字段语义。
- 抽 parser 时顺手修改 `RuleSnapshot` 发布流程。
- `RuleJsonParser` 内部调用 `Log()`。
- `RuleJsonParser` 内部访问 pipe 或 event。
- `RuleJsonParser` include AMSI / COM / EDR SDK / DB 头文件。
- `EventSubmitClient` 或 `LegacyPipeTransport` 被顺手接入主路径。
- 本批提前接入 EDR SDK。
