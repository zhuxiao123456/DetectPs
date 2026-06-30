# HostGuard Demo 与 DLL 规则大包测试方案

## 目标

验证 `hostguard_demo` 下发大规则响应、DLL 读取规则响应时，对 `2MB wire payload` 上限的处理是否正确。

本测试覆盖：

- `wire = JSON + "\n"` 小于 `2MB` 时允许。
- `wire = 2MB` 时允许。
- `wire > 2MB` 时拒绝。
- HostGuard 侧拒绝时输出长度日志，不输出规则内容。
- DLL 侧累计读取超过 `2MB` 时 fail-open，不保留残缺响应。
- 真实 `hostguard_demo.exe + rasp_mod_amsi.dll` 联调时，大规则不会导致卡死或长期阻塞。

## 口径

当前限制口径是 `wire bytes`，不是纯 JSON 字节数。

```text
wire = response.json + "\n"
limit = 2 * 1024 * 1024 = 2097152 bytes
```

边界关系：

```text
JSON = 2097150 bytes -> wire = 2097151 bytes -> 允许
JSON = 2097151 bytes -> wire = 2097152 bytes -> 允许
JSON = 2097152 bytes -> wire = 2097153 bytes -> 拒绝
```

## 一、自动化回归测试

### 1. 编译测试目标

```powershell
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo `
  --target hostguard_demo amsi_rule_channel_tests rule_pipe_large_message_spike_tests `
  --config Debug

cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex `
  --target engine_runtime_tests `
  --config Release
```

### 2. 运行 HostGuard channel 边界测试

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug\amsi_rule_channel_tests.exe
```

预期：

```text
amsi_rule_channel_tests passed
```

该测试覆盖：

- `wire < 2MB` 允许。
- `wire = 2MB` 允许。
- `wire > 2MB` 拒绝。
- 拒绝时回调日志包含 `rule response too large`。

### 3. 运行命名管道大消息 spike

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug\rule_pipe_large_message_spike_tests.exe
```

预期：

```text
rule_pipe_large_message_spike_tests passed
groupA chunks=32 bytes=2097152 sawMoreData=1
groupB chunks=32 bytes=2097152 sawMoreData=1
```

说明：

- Group A 验证 `512KB out buffer` 下也能传输 `2MB wire`，客户端通过 `ERROR_MORE_DATA` 分块读取。
- Group B 验证 `2MB out buffer` 对照路径。
- 如果 Group A 失败，说明不能仅靠 DLL 分块读取，需要重新评估 HostGuard pipe out buffer 或协议级分片。

### 4. 运行 DLL 侧读取超限测试

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
```

预期：进程返回码为 `0`，无失败输出。

该测试覆盖：

- DLL 从 rules pipe 累计读取超过 `2MB`。
- `ReadMessagePipeWithLimit` 返回失败。
- `tooLarge=true`。
- `response` 被清空，不保留残缺 JSON。

## 二、hostguard_demo 管道联调

该阶段不需要注册 AMSI DLL，只验证 HostGuard rules pipe 的实际响应行为。

### 1. 生成边界规则文件

在 PowerShell 中执行：

```powershell
$root = "D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo"
$out = Join-Path $root "tmp_large_rules"
New-Item -ItemType Directory -Force -Path $out | Out-Null

function New-AmsiLargeRuleJson {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][int]$TargetJsonBytes
    )

    $prefix = '{"version":1,"globalMode":"block","rules":[{"id":"AMSI-LARGE-TEST","sensor":"AmsiProvider","enabled":true,"mode":"alert","description":"'
    $suffix = '","confidence":1,"severity":1,"config":{"regexPatterns":["large_payload_probe_never_match"]}}]}'

    $enc = [System.Text.Encoding]::UTF8
    $fixedBytes = $enc.GetByteCount($prefix + $suffix)
    if ($TargetJsonBytes -le $fixedBytes) {
        throw "TargetJsonBytes too small. fixedBytes=$fixedBytes"
    }

    $padLen = $TargetJsonBytes - $fixedBytes
    $json = $prefix + ("A" * $padLen) + $suffix
    $actual = $enc.GetByteCount($json)
    if ($actual -ne $TargetJsonBytes) {
        throw "unexpected json size actual=$actual target=$TargetJsonBytes"
    }
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

New-AmsiLargeRuleJson -Path (Join-Path $out "rules_wire_2mb_minus_1.json") -TargetJsonBytes 2097150
New-AmsiLargeRuleJson -Path (Join-Path $out "rules_wire_2mb.json")         -TargetJsonBytes 2097151
New-AmsiLargeRuleJson -Path (Join-Path $out "rules_wire_2mb_plus_1.json")  -TargetJsonBytes 2097152

Get-ChildItem $out | Select-Object Name,Length
```

预期文件大小：

```text
rules_wire_2mb_minus_1.json  2097150
rules_wire_2mb.json          2097151
rules_wire_2mb_plus_1.json   2097152
```

### 2. 启动 HostGuard，测试 `wire = 2MB` 允许

先清理旧进程：

```powershell
taskkill /F /IM hostguard_demo.exe 2>$null
```

启动：

```powershell
cd D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug
.\hostguard_demo.exe `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\tmp_large_rules\rules_wire_2mb.json `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs `
  --production-pipes --amsi-ipc-enabled --amsi-ipc-real-ipc
```

另开一个 PowerShell 请求 rules pipe：

```powershell
cd D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug
.\hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES | Measure-Object -Character
```

预期：

- 请求成功返回。
- 返回长度接近 `2097152`。
- `logs` 下没有 `rule response too large`。

### 3. 测试 `wire > 2MB` 被 HostGuard 拒绝

停止旧 HostGuard：

```powershell
taskkill /F /IM hostguard_demo.exe 2>$null
```

启动超限规则：

```powershell
cd D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug
.\hostguard_demo.exe `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\tmp_large_rules\rules_wire_2mb_plus_1.json `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs `
  --production-pipes --amsi-ipc-enabled --amsi-ipc-real-ipc
```

请求：

```powershell
.\hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES
```

预期：

- 客户端无规则正文返回，或连接被服务端关闭。
- HostGuard 日志中出现：

```text
rule response too large wireBytes=2097153 limit=2097152
```

检查日志：

```powershell
Select-String `
  -Path D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs\*.jsonl `
  -Pattern "rule response too large"
```

## 三、hostguard_demo + DLL 联调

该阶段需要测试机已注册当前 `rasp_mod_amsi.dll`，并确认 PowerShell 会加载该 DLL。

### 1. 正常大包允许场景

使用 `rules_wire_2mb.json` 启动 HostGuard：

```powershell
taskkill /F /IM hostguard_demo.exe 2>$null

cd D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug
.\hostguard_demo.exe `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\tmp_large_rules\rules_wire_2mb.json `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs `
  --production-pipes --amsi-ipc-enabled --amsi-ipc-real-ipc
```

新开 PowerShell，触发 AMSI：

```powershell
"hello amsi large rule load"
```

预期：

- DLL 初始化不报 `rule response too large`。
- 不出现 `ConnectSentry: ReadFile failed`。
- 不出现长时间卡顿。
- 如果规则内容有效，DLL 日志应出现规则加载成功类日志。

### 2. 超限 fail-open 场景

使用 `rules_wire_2mb_plus_1.json` 启动 HostGuard：

```powershell
taskkill /F /IM hostguard_demo.exe 2>$null

cd D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug
.\hostguard_demo.exe `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\tmp_large_rules\rules_wire_2mb_plus_1.json `
  D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs `
  --production-pipes --amsi-ipc-enabled --amsi-ipc-real-ipc
```

新开 PowerShell，触发 AMSI：

```powershell
"hello amsi over limit"
```

预期：

- HostGuard 日志出现：

```text
rule response too large wireBytes=2097153 limit=2097152
```

- DLL 侧应 fail-open，不应阻断 PowerShell 启动。
- 如果 HostGuard 已在服务端拒绝，DLL 侧可能看到 broken pipe / read failed，而不是 DLL 自己的 `tooLarge`。这是预期，因为服务端已经提前拒绝。
- 如果通过测试工具直接向 DLL 发送超过 `2MB` 的 pipe message，则 DLL 日志应出现：

```text
ConnectSentry: rule response too large bytes=... limit=2097152 ...
```

## 四、性能与稳定性观察

### 1. 重复启动 PowerShell

```powershell
1..50 | ForEach-Object {
    powershell.exe -NoProfile -Command "'large-rule-smoke'"
}
```

预期：

- 不崩溃。
- 不持续卡住。
- HostGuard 日志没有持续刷屏。
- 超限规则包场景下，日志应能定位为 `rule response too large`，而不是大量不明 `ReadFile failed`。

### 2. 观察 CPU 与内存

```powershell
Get-Process hostguard_demo,powershell -ErrorAction SilentlyContinue |
  Select-Object ProcessName,Id,CPU,WorkingSet64
```

预期：

- `hostguard_demo` 不因单个慢客户端长期阻塞所有规则请求。
- DLL 侧读取超限后释放 partial response，不应出现持续内存增长。

## 五、验收标准

通过条件：

- 自动化三组测试全部通过：
  - `amsi_rule_channel_tests.exe`
  - `rule_pipe_large_message_spike_tests.exe`
  - `engine_runtime_tests.exe`
- `wire = 2MB` 可成功返回。
- `wire > 2MB` 被拒绝，HostGuard 日志包含 `rule response too large`。
- DLL 直接读取超过 `2MB` 时，返回失败且 `tooLarge=true`。
- 真实 PowerShell 触发 AMSI 时，超限规则包不会导致 PowerShell 崩溃、长时间卡死或错误阻断。

不要求：

- 不要求支持超过 `2MB` 的规则下发。
- 不要求协议级分片。
- 不要求服务端写入改为 overlapped + timeout；该项属于后续优化。
