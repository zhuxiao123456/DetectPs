# Phase 3 Batch 1: 输入归一化与 4KB 检测视图设计方案

## 1. 结论

Phase 3 第一批只做输入完整性治理和规则链路输入改造，不做取证模型升级。

目标：

- 规则看到的 `body` 更可靠。
- 不再依赖原始 `sample` 字节直接进入规则链。
- 统一使用 `sample + sampleLen`，避免 `strlen()` 截断。
- 最大规则输入视图限制为 4KB。
- 超长样本使用 prefix + suffix 策略，而不是只取前缀。
- 支持 UTF-16LE / UTF-8 / ANSI 基础处理。
- NUL 字节不会导致检测链截断。
- 支持 PowerShell `-EncodedCommand` / `-enc` 基础 Base64 解码。

明确不做：

- 不新增数据库字段。
- 不修改持久化事件 schema。
- 不修改 sentry / event_collector / DB 协议。
- 不修改 Phase 2 runtime / queue / budget 状态机。
- 不引入 session cache。
- 不做大样本全量窗口扫描。
- 不做复杂 AST / 语义模拟。
- 不扫描全样本所有疑似 Base64 字符串。
- 不打印完整样本或完整 decoded payload。
- 不把归一化 metadata 写入 pipe / event queue / DB。

## 2. 开发边界

允许做：

- 新增 `ScriptInputNormalizer`
- 新增 `NormalizedScriptInput`
- 4KB 最大扫描视图
- prefix 3072B + marker + suffix 1024B 截断策略
- UTF-16LE / UTF-8 / ANSI 基础识别
- NUL 字节处理
- `-EncodedCommand` / `-enc` token 提取和 Base64 解码
- 基础控制字符 / 空白归一化
- 将 normalized body 接入 `RaspLuaContext.body`
- normalizer 单元测试
- Phase 2 回归测试

禁止做：

- 新增数据库字段
- 修改 detection event schema
- 修改 sentry / event_collector / DB 协议
- session cache
- 大样本全量窗口扫描
- AST / 语义模拟
- 新增规则语言
- 网络 IOC
- 修改 Phase 2 runtime / queue / budget 状态机

## 3. 核心结构

```cpp
struct NormalizedScriptInput {
    std::string normalized;

    size_t rawLen = 0;
    size_t normalizedLen = 0;

    bool truncated = false;
    bool hadNullBytes = false;
    bool decodedBase64 = false;
    bool decodedUtf16Le = false;

    std::string sampleHash;              // SHA-256(raw), memory/test/debug only
    std::string normalizationReason;      // memory/test/debug only
};
```

```cpp
class ScriptInputNormalizer {
public:
    NormalizedScriptInput Normalize(const char* sample, ULONG sampleLen) const;
};
```

`ScriptInputNormalizer` 第一版必须保持轻量，不持有重状态，不在热路径构造复杂正则对象。若后续加入查表、配置或编译正则，应改为 `AmsiRuleEngine` 成员或静态只读实例。

## 4. 固定常量

```cpp
constexpr size_t kMaxNormalizedBodyBytes = 4096;
constexpr size_t kPrefixBytes = 3072;
constexpr size_t kSuffixBytes = 1024;
constexpr size_t kMaxEncodedCommandTokenBytes = 8192;
constexpr const char* kTruncatedMarker = "\n/*<rasp_truncated>*/\n";
constexpr const char* kDecodedMarker = "\n/*<decoded>*/\n";
```

约束：

- `kTruncatedMarker` 不包含 `invoke`、`iex`、`encoded`、`command`、`powershell` 等高危词。
- marker 不模拟 PowerShell 可执行语义。
- EncodedCommand token 超过 8192 bytes 时不解码，不阻断 Scan。

## 5. Hash 策略

`sampleHash` 固定为：

```text
SHA-256(raw sample bytes)
```

用途：

- 单元测试断言稳定性。
- 内存内 debug。
- 后续如需升级取证字段，可复用一致语义。

限制：

- 不落库。
- 不进入 event queue。
- 不写 pipe。
- 不改变 detection event JSON。

## 6. 处理流程

1. 校验 `sample/sampleLen`。
2. `sample == nullptr` 或 `sampleLen == 0` 时安全返回空结果。
3. 使用 `sample + sampleLen`，禁止 `strlen(sample)`。
4. 计算 `rawLen` 和 `SHA-256(raw sample bytes)`。
5. 判断 UTF-16LE。
6. UTF-16LE 成功则转 UTF-8。
7. UTF-16LE 失败则按原始 bytes 构造文本，NUL 替换为空格。
8. 基础控制字符归一化，避免改变 token 边界。
9. 大小写不敏感识别 `-EncodedCommand` / `-enc`。
10. 只解码明确跟随 `-enc` 的 token。
11. Base64 token 支持裸 token、单引号、双引号。
12. token 超过 8192 bytes 时跳过解码。
13. Base64 解码失败时忽略，不抛异常。
14. 解码结果优先按 UTF-16LE 转 UTF-8，否则按 byte 文本处理。
15. 解码成功时构造 primary body：

```text
original_normalized + "\n/*<decoded>*/\n" + decoded_text
```

16. 对 primary body 执行 4KB prefix + suffix 视图限制。
17. 填充 `normalizedLen/truncated/decodedBase64/decodedUtf16Le/normalizationReason`。

## 7. UTF-16LE 判断

不要只用前 16 字节奇数位 NUL 数量判断。

第一版至少结合：

- BOM `FF FE`
- 长度是否为偶数
- 更长范围内 NUL 分布比例
- 解码后可打印字符比例
- 解码后是否包含常见 PowerShell 字符或 token
- 异常时降级 raw，不崩溃

识别失败不能阻断 Scan，也不能 crash。

## 8. NUL 字节处理

所有处理必须使用 `sample + sampleLen`。

如果是 UTF-16LE：

- 正常解码，不把 NUL 当普通字符处理。

如果不是 UTF-16LE 但存在 NUL：

- NUL 替换为空格。
- 记录 `hadNullBytes = true`。

第一版不直接删除 NUL，避免改变 token 边界。

## 9. EncodedCommand 范围

支持：

- `-EncodedCommand <token>`
- `-enc <token>`
- `-EnC <token>`
- `-enc "<token>"`
- `-EncodedCommand '<token>'`

限制：

- 只解码明确跟在 `-enc` / `-EncodedCommand` 后面的 token。
- 不做全样本 Base64 猜测。
- 不扫描所有疑似 Base64 字符串。
- token 最大 8192 bytes。
- 解码失败不抛异常、不阻断 Scan。
- 解码内容也执行 4KB 上限。

## 10. 4KB 视图策略

```text
len <= 4096:
    保留完整 body

len > 4096:
    first 3072 bytes + "\n/*<rasp_truncated>*/\n" + last 1024 bytes
```

说明：

- 样本内容视图为 4096 bytes。
- marker 会让最终字符串略大于 4096。
- 测试断言应使用 `normalizedLen <= 4096 + marker.size()`。
- suffix 必须保留，避免尾部执行链被前截断策略漏掉。

## 11. 接入点

改造 `AmsiRuleEngine::Evaluate(const wchar_t*, const wchar_t*, const char*, ULONG)`。

目标：

```cpp
auto normalized = m_inputNormalizer.Normalize(sample, sampleLen);
ctx.fields.push_back({"body", normalized.normalized, true});
```

建议 `AmsiRuleEngine` 持有轻量成员：

```cpp
ScriptInputNormalizer m_inputNormalizer;
```

只把 `normalized.normalized` 传入 `RaspLuaContext.body`。

不修改：

- `RaspEvalResult`
- `AsyncEvent`
- detection JSON
- sentry 协议
- DB schema

## 12. Debug 策略

允许轻量 debug 摘要：

```text
[normalizer] rawLen=8192 normalizedLen=4119 truncated=1 utf16=0 b64=1 nulls=0
```

禁止：

- 打印完整原始样本
- 打印完整 decoded payload
- 写 pipe
- 入 event queue
- 写 DB

## 13. 测试方案

新增：

- `script_input_normalizer_tests.cpp`

必须覆盖：

- 普通 UTF-8 原样进入 normalized body
- UTF-16LE 有 BOM 可转 UTF-8
- UTF-16LE 无 BOM 但特征明显可识别
- 异常 UTF-16LE 不崩溃并降级
- NUL 字节不会导致截断
- 非 UTF-16LE NUL 替换为空格
- `-EncodedCommand <base64>` 可解码
- `-enc` 大小写混合可识别
- 单引号 / 双引号 token 可识别
- token 超过 8192 bytes 不解码
- 非法 Base64 不崩溃
- Base64 解码后超长仍按 4KB 策略截断
- raw > 4096 保留 prefix + suffix
- 尾部关键字不会因前截断丢失
- marker 不包含高危词
- `sampleHash` 对同一原始输入稳定，且为 SHA-256 语义
- 空输入不崩溃
- `sample == nullptr && sampleLen > 0` 安全返回

回归：

- `engine_runtime_tests`
- `scan_budget_tests`
- `async_event_queue_tests`
- `rasp_mod_amsi.dll` Release build

## 14. 验收标准

构建验收：

- `rasp_mod_amsi.dll` Release build 通过
- `script_input_normalizer_tests` 通过
- `engine_runtime_tests` 通过
- `scan_budget_tests` 通过
- `async_event_queue_tests` 通过

功能验收：

- 普通 UTF-8 原样进入 normalized body
- UTF-16LE 有 BOM 可转 UTF-8
- UTF-16LE 无 BOM 但特征明显可识别
- 异常 UTF-16LE 不崩溃并降级
- NUL 字节不会导致截断
- 非 UTF-16LE NUL 替换为空格
- `-EncodedCommand` / `-enc` 可识别和解码
- 非法 Base64 不崩溃
- raw > 4096 保留 prefix + suffix
- 尾部关键字不会因前截断丢失
- `sampleHash` 对同一原始输入稳定

边界验收：

- 不新增数据库字段
- 不修改 detection event schema
- 不修改 sentry / event_collector / DB 协议
- 不引入 session cache
- 不引入全量窗口扫描
- 不修改 Phase 2 runtime 状态机
- 不扫描全样本所有疑似 Base64 字符串
- 不打印完整样本或完整 decoded payload
- 不把 metadata 写入 pipe / event queue / DB

## 15. 实施顺序

1. 写入本设计文档。
2. 写 `script_input_normalizer_tests.cpp`，确认 RED。
3. 新增 `script_input_normalizer.h/.cpp`。
4. 实现 SHA-256、rawLen、normalizedLen metadata。
5. 实现 4KB prefix + suffix 截断。
6. 实现 UTF-16LE 检测和转换。
7. 实现 NUL / 控制字符处理。
8. 实现 `-EncodedCommand` / `-enc` token 提取和 Base64 解码。
9. 将 `ScriptInputNormalizer` 作为 `AmsiRuleEngine` 成员接入。
10. 只传 `normalized.normalized` 到 `RaspLuaContext.body`。
11. 新增 `scripts/test_phase3_input_normalization.ps1`。
12. 构建、单测、Phase 2 回归。
13. 独立 commit / push。
