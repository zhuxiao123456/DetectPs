# AMSI Host-Owned Config Pipe Phase 1 Test Plan

## 目标

阶段 1 只验证 `hostguard_demo.exe + rasp_mod_amsi.dll` 的新控制链路，不迁移 `module_amsi_detect`。

核心语义：

- `hostguard_demo.exe` 创建 `\\.\pipe\amsi_detect_config`。
- DLL 不再创建 config pipe，只作为 client 连接并读取 1 字节控制信号。
- Host 不在线时，DLL 进入 bypass / NoMatch，不继续使用旧规则拦截。
- Host 恢复后，DLL 必须通过 `reload` 主动拉取 state/rules，再恢复检测。
- `state=unload` 只用于 DLL 升级窗口，旧 DLL 进入 inert/unload 后不再自动恢复。

## 编译产物

Host:

```text
D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Debug\hostguard_demo.exe
```

DLL:

```text
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\rasp_mod_amsi.dll
```

规则文件示例：

```text
D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\rasp_rules.json
```

## 测试前清理

如果测试机上曾加载旧 DLL，先关闭 PowerShell、wscript、cscript 等测试宿主进程。必要时重启测试机。

旧 DLL 如果仍在进程中，会继续创建 `amsi_detect_config`，新 Host 启动时应失败并提示：

```text
production config pipe is already served: \\.\pipe\amsi_detect_config
```

这是预期保护，表示存在旧进程或其他 Host 占用 config pipe。

## 启动 Host

在测试目录运行：

```powershell
.\hostguard_demo.exe .\rasp_rules.json .\logs --production-pipes --amsi-ipc-enabled --amsi-ipc-real-ipc
```

预期日志：

```text
RuleServer started - 8 threads on amsi_detect_rules
Config notify server started on amsi_detect_config
```

## 健康检查

可使用脚本确认四条 production pipe 可见：

```powershell
python .\scripts\amsi_ipc_interactive_test.py --health
```

或者进入交互菜单选择：

```text
15. Health check Host-owned production pipes
```

脚本只使用 `WaitNamedPipeW` 探测 `amsi_detect_config`，不会连接和读取 config pipe，避免消费 DLL 控制连接。

预期：

```text
[OK] rules: \\.\pipe\amsi_detect_rules
[OK] events: \\.\pipe\amsi_detect_events
[OK] control_status: \\.\pipe\amsi_detect_control_status
[OK] config_host_owned: \\.\pipe\amsi_detect_config
```

## 正常检测验证

1. 注册新 DLL：

```powershell
regsvr32 C:\RaspSentry\rasp_mod_amsi.dll
```

2. 新开 PowerShell，触发测试内容：

```powershell
test amsiutils
```

3. 如果规则命中，PowerShell 应出现 AMSI 拦截；Host 日志中应看到 detection event。

## Host 异常退出验证

1. 强杀 Host，不走正常退出：

```powershell
taskkill /IM hostguard_demo.exe /F
```

2. 等待超过 DLL liveness grace 时间。

3. 在已加载 DLL 的 PowerShell 中再次触发：

```powershell
test amsiutils
```

预期：

- DLL 不继续使用旧规则拦截。
- Scan 返回 NoMatch / allow-no-detect。
- DLL 日志应出现 Host liveness lost / bypass 相关信息。

## Host 恢复验证

1. 重新启动 Host。

2. 在 Host 控制台输入：

```text
reload
```

3. DLL 预期日志：

```text
ConfigPipeClientThread: signal=0x01
ConfigPipeClientThread: reload signal - pulling updated rules
ConnectSentry: host state=running
Reload succeeded - detection resumed
```

4. 在原 PowerShell 中再次触发：

```powershell
test amsiutils
```

预期恢复检测并按规则拦截。

## unload 状态验证

在 Host 控制台输入：

```text
state unload
reload
```

预期：

- DLL 拉到 `state=unload`。
- DLL 进入 inert/unload。
- 后续 scan bypass，不再恢复检测。

恢复 Host 状态：

```text
state running
reload
```

注意：已经进入 inert/unload 的旧 DLL 按当前方案不会自动恢复，需要重启对应宿主进程并加载新 DLL。

## 通过标准

- Host 能创建 `amsi_detect_config`。
- 新 DLL 日志中不再出现 `CreateNamedPipeW failed GLE=5`。
- `reload` 能唤醒已连接 DLL 并拉取 state/rules。
- Host 异常退出后已加载 DLL 不继续旧规则拦截。
- Host 恢复并 `reload` 后，未 inert 的 DLL 可恢复检测。
- `state=unload` 后旧 DLL 不自动恢复。
