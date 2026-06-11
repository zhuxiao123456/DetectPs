# AMSI Scan Context 过滤行为说明

本文档说明当前 DLL 侧对 AMSI Scan 内容的三类处理结果：

1. 跳过规则检测，也不拼接上下文。
2. 执行当前内容检测，但不拼接上下文。
3. 执行上下文拼接检测，并在未命中时写入上下文。

## 配置入口

根级配置：

```json
{
  "scanContext": {
    "enabled": true,
    "maxBufferedBytes": 8192,
    "ttlMs": 3000,
    "maxEvalBytes": 16384,
    "clearOnMatch": true,
    "maxAppendBytes": 256,
    "prefixFilterBytes": 128
  }
}
```

字段含义：

- `enabled`：是否启用短 TTL Scan Context 聚合。
- `maxBufferedBytes`：历史上下文最多保留字节数。
- `ttlMs`：距离上次成功 append 超过该时间后清空上下文。
- `maxEvalBytes`：实际参与检测的内容最大长度。
- `clearOnMatch`：任意规则命中后是否清空上下文。
- `maxAppendBytes`：当前 Scan 内容超过该长度时，不写入上下文。
- `prefixFilterBytes`：只检查当前内容前 N 字节的基础设施特征。

## 总体流程

当前 Scan 内容进入规则检测前，会先做分类：

```text
contentName/body prefix 是 PowerShell 基础设施
    => 直接 NoMatch，不执行规则检测，不读取历史 context，不 append。

不是基础设施，但不允许 append
    => 使用 currentBody 单独检测，不读取历史 context，不 append。

允许 append
    => 使用 historyContext + "\n" + currentBody 检测。
       若未命中、未超时、未异常、未限频 bypass，则 append currentBody。
```

## 一、跳过规则检测且不拼接

这类内容通常是 PowerShell 自身模块、命令行编辑、错误格式化、提示符脚本等基础设施噪音。

处理结果：

```text
返回 NoMatch
不执行规则遍历
不读取历史 context
不 append 当前内容
```

### 1. contentName 命中基础设施

以下 contentName 片段命中后直接跳过规则检测，大小写不敏感：

```text
.psm1
.psd1
.ps1xml
psreadline
microsoft.powershell.utility
```

示例：

```text
C:\Program Files\WindowsPowerShell\Modules\PSReadline\1.2\PSReadLine.psm1
C:\Program Files\WindowsPowerShell\Modules\PSReadline\1.2\PSReadLine.psd1
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psm1
C:\Windows\system32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1
```

### 2. body 前缀命中基础设施

只检查当前内容前 `prefixFilterBytes` 字节。默认 `128` 字节。

以下内容命中后直接跳过规则检测，大小写不敏感：

```text
ModuleVersion
GUID
RootModule
NestedModules
FunctionsToExport
CmdletsToExport
AliasesToExport
HelpInfoURI
CompanyName
Copyright
function prompt
$NestedPromptLevel
$host.UI.RawUI
PSConsoleHostReadline
[System.Diagnostics.DebuggerHidden()]
FullyQualifiedErrorId
InvocationInfo
PositionMessage
PSMessageDetails
ErrorCategory_Message
CategoryInfo
http://go.microsoft.com/fwlink/
prompt
PS $($executionContext.SessionState.Path.CurrentLocation)
Set-StrictMode -Version 1
OriginInfo
```

常见场景：

- `CommandNotFoundException` 后 PowerShell 自动生成错误格式化脚本。
- 命令建议脚本。
- prompt 函数。
- 模块清单、导出声明、格式化输出脚本。

## 二、执行当前内容检测但不拼接

这类内容仍然会进入规则检测，但只检测当前 Scan 内容，不会读取历史 context，也不会 append。

### 1. scanContext 未启用

条件：

```text
scanContext.enabled = false
```

处理：

```text
evalBody = currentBody
不拼接历史上下文
```

### 2. maxBufferedBytes 为 0

条件：

```text
scanContext.maxBufferedBytes = 0
```

处理：

```text
evalBody = currentBody
不拼接历史上下文
```

### 3. maxAppendBytes 为 0

条件：

```text
scanContext.maxAppendBytes = 0
```

处理：

```text
evalBody = currentBody
不拼接历史上下文
```

### 4. 当前内容为空

条件：

```text
currentBody.empty()
```

处理：

```text
不 append
```

### 5. 当前内容超过 maxAppendBytes

条件：

```text
currentBody.size() > scanContext.maxAppendBytes
```

处理：

```text
evalBody = currentBody
仍执行规则检测
不读取历史 context
不 append
```

注意：

```text
超过 maxAppendBytes 不是 bypass。
它只是禁止进入上下文，当前内容仍然会被检测。
```

示例：

```powershell
("A" * 300) + " amsiutils"
```

如果 `maxAppendBytes=256`，该内容不会 append，但仍可被规则命中。

## 三、执行拼接检测并写入上下文

满足以下条件时，当前 Scan 内容允许参与上下文聚合：

```text
scanContext.enabled = true
maxBufferedBytes > 0
maxAppendBytes > 0
currentBody 非空
contentName 未命中基础设施
body prefix 未命中基础设施
currentBody.size() <= maxAppendBytes
```

检测内容构造：

```text
evalBody = oldContext + "\n" + currentBody
```

约束：

```text
evalBody 最多保留尾部 maxEvalBytes 字节
oldContext 最多保留尾部 maxBufferedBytes 字节
```

检测结束后：

```text
如果任意规则命中，且 clearOnMatch=true
    => 清空 context

如果未命中，且未发生全局超时、异常、限频 bypass
    => append currentBody
```

示例：

第一次 Scan：

```powershell
test amsi
```

第二次 Scan，TTL 内：

```powershell
utils
```

实际检测内容：

```text
test amsi
utils
```

## 四、不会污染上下文的场景

以下场景不会 append 当前内容：

```text
基础设施 contentName
基础设施 body prefix
scanRateLimit bypass
trust_process bypass
global timeout
规则执行异常
snapshot hash 变化
TTL 到期前的旧上下文被清空
当前内容超过 maxAppendBytes
```

其中基础设施 contentName/body prefix 还会直接跳过规则检测。

## 五、调试日志

默认不写扫描内容 dump，避免同步写大文件导致卡顿。

需要调试时显式设置：

```powershell
$env:RASP_AMSI_SCAN_DUMP_PATH="D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_amsi_scan_content_debug.txt"
```

dump 中重点字段：

```text
appendAllowed=1
appendSkipReason=none
bufferedLen=13
evalLen=16
```

表示参与拼接检测。

```text
appendAllowed=0
appendSkipReason=content_name_infrastructure
bufferedLen=0
```

表示基础设施 contentName，跳过检测，不拼接。

```text
appendAllowed=0
appendSkipReason=body_prefix_infrastructure
bufferedLen=0
```

表示基础设施 body prefix，跳过检测，不拼接。

```text
appendAllowed=0
appendSkipReason=too_large
bufferedLen=0
```

表示当前内容过长，只做单次检测，不拼接。

## 六、测试建议

### 1. 用户输入可拼接

```powershell
test amsi
utils
```

预期：

```text
第二次 Scan 使用历史 context + utils 检测。
TTL 内可命中跨片段规则。
```

### 2. TTL 过期不拼接

```powershell
test amsi
```

等待超过 `ttlMs`，再输入：

```powershell
utils
```

预期：

```text
旧 context 已过期，不命中跨片段规则。
```

### 3. PowerShell 错误格式化不检测

```powershell
test amsiutil
s
```

预期：

```text
CommandNotFoundException 相关错误格式化脚本命中 body_prefix_infrastructure。
不执行规则遍历，不污染 context。
```

### 4. 模块基础设施不检测

启动 PowerShell 或触发模块加载。

预期：

```text
PSReadLine.psm1、PSReadLine.psd1、Microsoft.PowerShell.Utility.psm1/psd1
命中 content_name_infrastructure。
不执行规则遍历，不污染 context。
```

### 5. 超长内容仍检测

```powershell
("A" * 300) + " amsiutils"
```

预期：

```text
如果 maxAppendBytes=256：
不会 append；
但当前内容仍会执行规则检测并可命中。
```

