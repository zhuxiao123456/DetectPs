# trust_process 全局跳过检测设计方案

## 1. 当前规则文件

规则文件路径：

```text
D:\Code\rasp\DetectPsByAmsiCodex\rasp_rules.json
```

当前读取到的关键结构如下：

```json
{
  "version": 1,
  "globalMode": "block",
  "globalLibraries": [
    "rules/lib/rasp_lib.lua"
  ],
  "trust_process": [
    "c:\\csaca.exe"
  ]
  "rules": [
    {
      "id": "AMSI-P01",
      "sensor": "AmsiProvider",
      "enabled": true,
      "mode": "block"
    },
    {
      "id": "AMSI-P02",
      "sensor": "AmsiProvider",
      "enabled": true,
      "mode": "block"
    }
  ]
}
```

## 2. P1 前置问题

当前 `rasp_rules.json` 不是合法 JSON。

问题位置：

```json
"trust_process": [
  "c:\\csaca.exe"
]
"rules": [
```

`trust_process` 数组结束后缺少逗号。应修正为：

```json
"trust_process": [
  "c:\\csaca.exe"
],
"rules": [
```

如果不先修正这个问题，规则加载和 reload 都不能作为可信测试基础。

## 3. 目标语义

`trust_process` 表示全局白名单。

当满足以下条件时，本次 AMSI scan 直接跳过所有规则检测：

- 当前被扫描宿主是 PowerShell。
- 已成功采集父进程路径 `parentProcessPath`。
- `parentProcessPath` 与 `trust_process` 数组中的任意完整路径等值匹配。

跳过检测的含义：

- 不执行 regex 规则。
- 不执行 Lua 脚本。
- 不生成 detection event。
- 不阻断调用方。
- 返回现有 NoMatch 路径，即 `AMSI_RESULT_NOT_DETECTED`。

## 4. P1 安全约束：禁止子串匹配

`trust_process` 是放行类配置，不能使用 contains 子串匹配。

以下配置风险过高，禁止作为匹配语义：

```json
"trust_process": [
  "c:\\csaca.exe"
]
```

如果使用子串匹配，下面这些路径都会被错误信任：

```text
C:\csaca.exe
C:\windows\csaca.exe
C:\malware\csaca.exe
C:\CSACA.EXE.old
```

这些结果会造成目录放置、后缀绕过、路径混淆等风险。

## 5. 推荐匹配规则

推荐采用完整路径等值匹配。

匹配流程：

1. 对 `parentProcessPath` 做路径规范化。
2. 对每个 `trust_process` 条目做路径规范化。
3. 只有规范化后的完整路径完全相等时，才命中白名单。

伪代码：

```cpp
NormalizeTrustedPath(parentProcessPath) == NormalizeTrustedPath(trustEntry)
```

规范化规则：

- 将 `/` 统一为 `\`。
- 去除路径两端空白。
- 去除外层双引号。
- Windows 路径大小写不敏感比较。
- 可选：去除末尾多余 `\`，但不要影响根路径。

不在本阶段做的事情：

- 不解析 `..`。
- 不解析软链接。
- 不解析硬链接。
- 不解析 8.3 短路径。
- 不做文件签名校验。
- 不做文件 hash 校验。

因此配置必须写成稳定、明确的完整路径。

## 6. trust_process 配置约束

`trust_process` 中每一项必须是完整可识别路径。

建议要求：

- 必须包含盘符或明确的绝对路径前缀。
- 必须以 `.exe` 结尾。
- 不允许只配置文件名，例如 `csaca.exe`。
- 不允许配置目录，例如 `C:\Program Files\CSA\`。
- 不允许配置带通配符的值，例如 `*\csaca.exe`。
- 不允许配置空字符串。
- 不允许配置后缀形式，例如 `csaca.exe.old`。

示例：

```json
"trust_process": [
  "C:\\Program Files\\CSA\\csaca.exe"
]
```

如果当前测试机确实使用根目录进程：

```json
"trust_process": [
  "C:\\csaca.exe"
]
```

这只应匹配：

```text
C:\csaca.exe
```

不应匹配：

```text
C:\windows\csaca.exe
C:\malware\csaca.exe
C:\csaca.exe.old
```

## 7. 可选方案：后缀锚定匹配

如果后续必须兼容“不同安装目录下同一可信子路径”的场景，可以引入独立字段，不建议复用 `trust_process`：

```json
"trust_process_path_suffix": [
  "\\CSA\\csaca.exe"
]
```

后缀锚定匹配必须满足：

- `parentProcessPath` 以该 suffix 结尾。
- suffix 以路径分隔符开头。
- suffix 必须以 `.exe` 结尾。
- 匹配后 `.exe` 后不能再有额外字符。

本阶段建议不做该方案，默认只做完整路径等值匹配。

## 8. PowerShell 限定

需求描述是：

> 如果调用 powershell 的父进程路径包含当前白名单中的一个，自动跳过所有规则检测。

安全修正后，“包含”不再作为实现语义；实际实现应为：

> 如果调用 PowerShell 的父进程完整路径等于当前白名单中的一个，自动跳过所有规则检测。

建议只对 PowerShell 宿主生效。

识别范围：

- `powershell.exe`
- 可选：`pwsh.exe`

判断来源优先级：

1. 优先使用当前进程路径或当前进程名，因为它来自本地采集，可信度高。
2. 如果当前进程路径不可用，再考虑 AMSI `appName`。

如果无法确认当前宿主是 PowerShell，则不信任，继续正常检测。

## 9. 现有代码基础

当前代码已经具备以下基础：

- `ProcessContextSnapshot` 已有 `parentProcessPath`。
- AMSI 扫描上下文已把 `parentProcessPath` 放入 Lua context。
- detection event 已能输出 `parentProcessPath`。
- `AmsiRuleEngine` 已有 rule-local 父路径 gate：
  - `parentPathAllowContains`
  - `parentPathBlockContains`

但这些已有字段是“单条规则级别”的 gate，只会跳过当前规则，后续规则仍会继续检测。

`trust_process` 的新语义是“全局跳过本次 scan 的所有规则”，所以不能直接复用为每条规则的 `parentPathAllowContains`。

## 10. 推荐实现方案

### 10.1 解析层

在 `RuleParseResult` 中增加顶层字段：

```cpp
std::vector<std::string> trustProcessPaths;
```

在 `RuleJsonParser::ParseBundleObject()` 中解析顶层 `trust_process`：

```cpp
if (key == "trust_process") {
    p.read_string_array(result.trustProcessPaths);
}
```

缺失 `trust_process` 时保持空数组，不影响现有规则。

### 10.2 配置校验

构建 snapshot 时校验每个条目：

- 空字符串：忽略并记录诊断日志。
- 非绝对路径：忽略并记录诊断日志。
- 非 `.exe` 结尾：忽略并记录诊断日志。
- 合法路径：规范化后写入 snapshot。

不要因为单个非法白名单项导致整包规则失败，除非后续产品策略要求配置错误必须 fail closed 到整包失败。

### 10.3 Snapshot 层

在 `AmsiRuleEngine::RuleSnapshot` 中增加：

```cpp
std::vector<std::string> trustProcessPaths;
```

保存已经规范化、已经校验过的完整路径。

### 10.4 Scan 层

在 `AmsiRuleEngine::EvaluateWithScanContext()` 中，拿到 snapshot 后、进入规则循环前做全局 gate：

```cpp
if (TrustProcessMatches(snapshot->trustProcessPaths, scanContext)) {
    return {};
}
```

`TrustProcessMatches()` 必须使用完整路径等值比较，不能使用 contains。

返回空结果表示 NoMatch，不进入后续 regex/Lua 规则循环。

## 11. 失败策略

建议采用 fail closed：

- 父进程路径为空：不信任，继续检测。
- 当前宿主进程无法确认是 PowerShell：不信任，继续检测。
- 白名单项非法：该项不生效。
- JSON 语法错误：保持现有规则加载失败行为，不发布坏 snapshot。

允许 fail open 的情况只有：

- `trust_process` 缺失：功能关闭。
- `trust_process` 为空数组：功能关闭。

## 12. 安全假设

本设计基于以下安全假设：

- 父进程路径采集来自可信系统 API，未被 hook 或篡改。
- 攻击者无法在受信任目录创建同名可执行文件。
- 进程注入场景不在本白名单机制的防护范围内。

因此，`trust_process` 只用于降低可信父进程触发 PowerShell 场景下的误报或不必要检测，不应被理解为完整的进程身份认证机制。

## 13. 日志策略

命中 `trust_process` 时不应写 detection event。

但为了排障和审计，命中跳过时应向 exe 上报一条非 detection 的控制/审计日志，由 exe 保存。

建议事件类型：

```text
TRUST_PROCESS_SKIP
```

建议字段：

```json
{
  "msgType": "TRUST_PROCESS_SKIP",
  "module": "rasp_mod_amsi",
  "processPath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "parentProcessPath": "C:\\csaca.exe",
  "matchedTrustProcess": "C:\\csaca.exe",
  "reason": "trusted_parent_process",
  "timestamp": "..."
}
```

保存通道建议：

- 优先走 control status / audit 类日志，而不是 detection event。
- 不写入 `rasp-events-YYYY-MM-DD.jsonl`，避免被误判为规则命中。
- 可写入 `rasp-control-status-YYYY-MM-DD.jsonl` 或后续独立 audit jsonl。

DLL 本地仍可写普通诊断日志，例如：

```text
[RaspAmsi] trust_process skip: parentProcessPath=... matched=...
```

非法白名单项也应写诊断日志，例如：

```text
[RaspAmsi] trust_process ignored invalid entry: csaca.exe
```

这些日志不应进入 `rasp-events-YYYY-MM-DD.jsonl`。

## 14. 测试方案

建议新增以下测试：

1. `trust_process` 缺失时，规则正常命中。
2. `trust_process` 存在但父进程完整路径不相等时，规则正常命中。
3. PowerShell 宿主 + 父进程完整路径等于白名单时，跳过所有规则。
4. 非 PowerShell 宿主 + 父进程路径等于白名单时，不跳过。
5. 父进程路径为空时，不跳过。
6. 大小写不敏感等值匹配。
7. `/` 和 `\` 路径分隔符归一化后等值匹配。
8. `C:\malware\csaca.exe` 不匹配 `C:\csaca.exe`。
9. `C:\csaca.exe.old` 不匹配 `C:\csaca.exe`。
10. 只配置 `csaca.exe` 时该项被忽略，不能触发跳过。
11. 多条规则场景下，命中 `trust_process` 后所有规则都跳过，而不是只跳过第一条规则。

解析器测试：

1. 顶层 `trust_process` 字符串数组能解析到 `RuleParseResult`。
2. 空数组可接受。
3. 非数组值按现有 parser 容忍策略处理。
4. 当前缺逗号的非法 JSON 不应成功发布 snapshot。
5. 命中 `trust_process` 时发送 `TRUST_PROCESS_SKIP` 审计/控制日志，但不发送 detection event。

## 15. 建议修正后的规则文件片段

```json
{
  "version": 1,
  "globalMode": "block",
  "globalLibraries": [
    "rules/lib/rasp_lib.lua"
  ],
  "trust_process": [
    "C:\\csaca.exe"
  ],
  "rules": [
    {
      "id": "AMSI-P01",
      "sensor": "AmsiProvider",
      "enabled": true,
      "mode": "block",
      "description": "System-wide AMSI script execution telemetry and obfuscation detection",
      "urlPatterns": [],
      "methods": [],
      "script": "rules/amsi_p01.lua",
      "scriptEval": "exclusive",
      "scriptTimeoutMs": 10,
      "confidence": 60,
      "config": {
        "severity": "low"
      }
    },
    {
      "id": "AMSI-P02",
      "sensor": "AmsiProvider",
      "enabled": true,
      "mode": "block",
      "description": "AMSI bypass attempts, no Lua required, JSON-level regex only",
      "urlPatterns": [],
      "methods": [],
      "confidence": 85,
      "config": {
        "regexField": "body",
        "regexPatterns": [
          "(?i)(amsiutils|amsiinitfailed|amsicontext)",
          "(?i)(invoke-expression|\\biex\\b)\\s*[({\"']",
          "(?i)\\[ref\\]\\.assembly\\.gettype\\(",
          "(?i)amsi\\.dll.*virtualprotect"
        ]
      }
    }
  ]
}
```

## 16. 实施顺序

1. 修正根目录 `rasp_rules.json` 的 JSON 逗号问题。
2. 给 `RuleJsonParser` 增加顶层 `trust_process` 解析。
3. 给 `AmsiRuleEngine::RuleSnapshot` 增加全局白名单字段。
4. 增加完整路径规范化与配置校验函数。
5. 在 scan 规则循环前增加全局 trust gate。
6. 命中 trust gate 时发送 `TRUST_PROCESS_SKIP` 非 detection 审计/控制日志。
7. 增加 parser、AMSI engine、审计日志单测。
8. 编译并运行：

```powershell
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex --target engine_runtime_tests rule_json_parser_tests --config Release

D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\rule_json_parser_tests.exe
```
