# amsi_detect_module P1 IPC 联调方案

## 目标

在 CSA-Engine 的 `amsi_detect_module` 中完成基于业务目录的真实 IPC 启动闭环。本阶段只验证 `data\amsi` 目录已经具备 DLL、规则和版本时，模块可以读取规则快照并启动 HostGuard AMSI IPC 通道。

## 目录约定

```text
安装目录\data\amsi\
├── hss_amsi.dll
└── rules\
    ├── rasp_rules.json
    ├── version.conf
    └── lib\
        └── rasp_lib.lua
```

本阶段 `rasp_lib.lua` 不是硬依赖，缺失时只记录日志，不阻塞启动。

## 本阶段实现

1. 检查 `data\amsi\hss_amsi.dll`、`data\amsi\rules\rasp_rules.json`、`data\amsi\rules\version.conf`。
2. 读取 `version.conf` 得到当前 AMSI 特征库版本。
3. 读取 `rasp_rules.json` 原始内容并做 JSON parse 校验。
4. 构造 `AmsiRuleSnapshot`：
   - `allRulesJson = rasp_rules.json` 原始内容
   - `amsiRulesJson = rasp_rules.json` 原始内容
   - `version = version.conf` 内容
   - `hash = rasp_rules.json` 内容 hash
5. 通过 `AmsiIpcRuntime` 启动真实 IPC：
   - production pipes
   - real IPC
   - strict no fallback
   - 直接封装 `amsi_ipc_host` 的 `AmsiRuleChannel`、`AmsiEventChannel`、`AmsiControlStatusChannel`、`NamedPipeServerPool`、`AmsiConfigBroadcaster`
6. DLL 可通过 `GET_RULES` / `GET_ALL_RULES` 获取规则。
7. event/status/diag callback 第一版只写业务日志。
8. `UnInit()` 中 best effort `PauseDetection()`，然后 `Stop()` IPC。

## 明确不做

1. 不注册 AMSI Provider。
2. 不反注册 AMSI Provider。
3. 不读取或预编译 `rasp_lib.lua`。
4. 不做 Lua bytecode 编译。
5. 不实现 `GET_POLICY`。
6. 不做 EDR event 转换。
7. 不做服务端上报。
8. 不做磁盘可靠队列。
9. 不做完整规则热升级落盘闭环。

## 状态语义

`IPC Ready` 不等于 `Detect Ready`。

本阶段新增：

```text
m_isIpcRunning       只表示 HostGuard AMSI IPC runtime 已启动
m_isAmsiRegistered  预留给后续 AMSI Provider 注册状态，本阶段恒为 false
```

如果 IPC 启动成功，不得对外宣称 AMSI 检测链路完整启用。

## 失败处理

`StartCheck()` 失败时不能删除整个 `data\amsi` 目录。失败只允许：

1. 记录明确错误。
2. 停止已启动的 IPC runtime。
3. 发送 AMSI 特征库下载请求。
4. 通知 feature upgrade 模块初始版本。

正式 pipe 被占用时必须启动失败，禁止 fallback 到 demo pipe。

## 当前 Runtime 实现

`AmsiIpcRuntime` 内部不依赖 demo 版 `HostGuardAmsiIpcAdapter`，避免把 demo 的 callback、队列、broadcast result 类型带入 CSA-Engine 编译环境。

当前封装关系：

```text
AmsiIpcRuntime
  -> RuntimeRuleProvider
  -> RuntimeEventSink
  -> RuntimeControlStatusSink
  -> AmsiRuleChannel
  -> AmsiEventChannel
  -> AmsiControlStatusChannel
  -> NamedPipeServerPool
  -> AmsiConfigBroadcaster
```

规则通道语义：

```text
GET_RULES     -> snapshot.amsiRulesJson
GET_ALL_RULES -> snapshot.allRulesJson
其他命令      -> unsupported
```

event/status 第一版只写业务日志，不做 EDR 转换和服务端上报。

`NamedPipeServerPool` 依赖 `pipe_security.h`，本模块本阶段提供一份最小 `AmsiPipeSecurity.cpp` 实现，避免额外依赖 demo 或 `rasp_sentry_native` 工程。
