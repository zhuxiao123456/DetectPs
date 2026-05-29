# AMSI IPC 交互测试脚本使用说明

## 文件位置

测试脚本：

```text
scripts/amsi_ipc_interactive_test.py
```

该脚本用于在业务机器或 demo 环境中手工验证 AMSI IPC named pipe 通信链路。

## 前置条件

先启动其中一个 Host 端程序：

1. 业务机器：

```text
hostguard.exe
```

2. demo 环境：

```cmd
hostguard_demo.exe rasp_rules.json logs --production-pipes --amsi-ipc-enabled --amsi-ipc-real-ipc
```

确认 production pipe 已创建：

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "amsi" }
```

至少应看到：

```text
\\.\pipe\amsi_detect_rules
\\.\pipe\amsi_detect_events
\\.\pipe\amsi_detect_control_status
\\.\pipe\amsi_detect_config
```

当前阶段 `amsi_detect_config` 由 Host 创建。DLL 不再创建该管道，只作为 client 连接并读取控制信号。

## 运行方式

该脚本设计为 PyCharm 直接运行，不依赖命令行参数。

也可以用 PowerShell 直接运行：

```powershell
python .\scripts\amsi_ipc_interactive_test.py
```

只做 Host-owned production pipe 健康检查：

```powershell
python .\scripts\amsi_ipc_interactive_test.py --health
```

运行后会进入交互菜单：

```text
1. GET_RULES
2. GET_ALL_RULES
3. 发送 Detection event
4. 发送 DLL diagnostic log
5. 发送重复 DLL diagnostic log
6. 发送 drain-ack event
7. 发送 unknown event
8. 发送 oversized event
9. 发送 DLL_LOADED status
10. 发送 RULE_LOAD_RESULT success
11. 发送 RULE_LOAD_RESULT failed
12. 发送 CONTROL_STATUS
13. 发送 oversized status
14. 全部基础用例
15. Health check Host-owned production pipes
0. 退出
```

## 推荐测试顺序

### 1. 规则通道

先执行：

```text
1. GET_RULES
2. GET_ALL_RULES
```

预期：

- 脚本输出非空 JSON。
- `GET_RULES` 和 `GET_ALL_RULES` 请求都必须带 `\n`。
- 不要用 `ReadLine()` 判断完整响应，多行 JSON 可能只读到 `{`。

### 2. 基础 event/status 通道

执行：

```text
14. 全部基础用例
```

预期业务日志中出现：

```text
Recv amsi detection event
Recv amsi dll diagnostic payload
Recv amsi control status payload
```

### 3. 重复 DLL diagnostic log 聚合

执行：

```text
5. 发送重复 DLL diagnostic log
```

建议输入：

```text
20
```

预期：

- 不应每条重复 diag 都完整刷业务日志。
- 应出现 suppressed / duplicate 汇总日志。
- 该用例用于验证日志风暴防护。

### 4. 超大 payload 防护

执行：

```text
8. 发送 oversized event
13. 发送 oversized status
```

预期：

- Host 进程不崩溃。
- pipe worker 不应长时间阻塞。
- 业务日志中不应打印完整 70KB payload。
- runtime stats 中 oversized/drop 计数应增加。

### 5. drain-ack 分类

执行：

```text
6. 发送 drain-ack event
```

预期：

- 不进入 detection 队列。
- 不进入 DLL diagnostic log 队列。
- 只做轻量计数或 runtime 内部处理。

## 各菜单项用途

| 菜单 | 用途 |
| --- | --- |
| 1 | 验证 DLL `GET_RULES\n` wire 语义 |
| 2 | 验证 DLL `GET_ALL_RULES\n` wire 语义 |
| 3 | 验证 Detection event 分类和队列处理 |
| 4 | 验证 DLL diagnostic log 分类和日志输出 |
| 5 | 验证重复 DLL diagnostic log 聚合 |
| 6 | 验证 drain-ack 优先级高于 `sensor=RaspLog` |
| 7 | 验证 unknown event 不影响 IPC 热路径 |
| 8 | 验证 oversized event 拒绝和计数 |
| 9 | 验证 `DLL_LOADED` status 上报 |
| 10 | 验证成功 `RULE_LOAD_RESULT` status 上报 |
| 11 | 验证失败 `RULE_LOAD_RESULT` status 上报 |
| 12 | 验证 control status payload 上报 |
| 13 | 验证 oversized status 拒绝和计数 |
| 14 | 一键执行基础链路用例 |

## 常见问题

### 1. 连接 pipe 超时

现象：

```text
Connect pipe timeout
```

检查：

- Host 端是否已启动。
- 是否使用 production pipe。
- 是否已有其他进程占用了同名 pipe。
- 当前权限是否能访问该 pipe。

### 2. GET_RULES 只读到 `{`

原因：

- 使用 `ReadLine()` 读取多行 JSON 会只读到第一行。

处理：

- 使用本脚本的规则通道直接 `ReadFile` 读取。

### 3. GET_RULES 出现 errno 233

现象：

```text
errno 233
管道的另一端上无任何进程
```

原因：

- `AmsiRuleChannel` 的语义是读取 `GET_RULES\n` / `GET_ALL_RULES\n` 后写一次响应，然后服务端断开该连接。
- 如果客户端先调用 `PeekNamedPipe`，可能刚好遇到服务端已经断开，Windows 返回 `ERROR_PIPE_NOT_CONNECTED(233)`。

处理：

- 规则通道应直接 `ReadFile`，不要先 `PeekNamedPipe`。
- 当前脚本已经按该语义处理，233 会作为服务端已断开的正常结束条件。

### 4. 发送 event/status 成功但业务日志无输出

检查：

- 当前 Host 端是否接入了 event/status sink。
- 是否启用了队列 worker。
- payload 是否被分类为 unknown 或 oversized。
- 日志级别是否过滤了 info 日志。

### 5. `amsi_detect_config` 不存在

说明：

- Host 未启动，或 Host 启动失败。
- 当前方案中 `amsi_detect_config` 应由 Host 创建；如果不存在，reload / pause / resume / unload 无法通知 DLL。
- 如果 Host 启动时报 `config pipe is already served`，通常是旧 DLL 或旧 Host 仍占用该管道，需要关闭相关宿主进程或重启测试机。

## 当前边界

本脚本只做 named pipe 手工验证，不做以下事情：

- 不注册 AMSI Provider。
- 不反注册 AMSI Provider。
- 不修改规则文件。
- 不做 EDR event 转换。
- 不做服务端上报。
- 不验证磁盘可靠队列。
- 不验证完整热升级落盘闭环。
