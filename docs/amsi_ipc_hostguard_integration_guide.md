# AMSI IPC HostGuard Integration Guide

## 1. 当前阶段

当前阶段是 Batch 5e-1：只固化 HostGuard 调用面和迁移边界，不改生产代码。

当前 `rasp_sentry.exe` 仍是 demo host。它暂时代替未来 HostGuard 创建 AMSI IPC 通道：

- `amsi_detect_rules`
- `amsi_detect_events`
- `amsi_detect_control_status`
- `amsi_detect_config`

HostGuard 化后的目标不是让 HostGuard 直接复用 `RuleServer`、`EventCollector`、`ControlStatusCollector`、`ConfigWatcher` 等 demo 类，而是通过 `AmsiIpcHost` 和注入接口接管规则源、事件接收和状态接收。

## 2. 最小落地目标

HostGuard 未来只需要依赖以下入口：

- `AmsiIpcHost`
- `AmsiIpcHostConfig`
- `AmsiIpcHostAdapters`
- `amsi_ipc::IAmsiRuleProvider`
- `amsi_ipc::IAmsiEventSink`
- `amsi_ipc::IAmsiControlStatusSink`

HostGuard 不应该直接依赖：

- `RuleServer`
- `DemoFileRuleProvider`
- `EventCollector`
- `ControlStatusCollector`
- `ConfigWatcher`
- `AmsiStagingWatcher`

## 3. 当前接口职责

| 接口 / 类型 | 当前位置 | HostGuard 实现方 | 调用方 | 是否允许阻塞 | 说明 |
|---|---|---|---|---|---|
| `AmsiIpcHost` | `src/rasp_sentry_native/include/amsi_ipc_host.h` | 不实现，直接使用 | HostGuard lifecycle | `Start/Stop` 可阻塞有限时间 | IPC facade |
| `AmsiIpcHostConfig` | `src/rasp_sentry_native/include/amsi_ipc_host.h` | HostGuard 填充 | `AmsiIpcHost` | N/A | 当前仍含 demo path |
| `AmsiIpcHostAdapters` | `src/rasp_sentry_native/include/amsi_ipc_host.h` | HostGuard 填充 | `AmsiIpcHost` | N/A | 注入 sink/provider |
| `IAmsiRuleProvider` | `src/amsi_ipc_host/include/amsi_rule_provider.h` | HostGuard rule module | rules channel | 不应长期阻塞 | 生成 rules pipe 响应 |
| `IAmsiEventSink` | `src/amsi_ipc_host/include/amsi_event_sink.h` | HostGuard event bus adapter | event channel | 不应长期阻塞 | 接收 detection/diag payload |
| `IAmsiControlStatusSink` | `src/amsi_ipc_host/include/amsi_control_status_sink.h` | HostGuard status adapter | control status channel | 不应长期阻塞 | 接收 RULE_LOAD_RESULT |

## 4. HostGuard 最小使用方式

### 4.1 实现规则 Provider

```cpp
#include "amsi_rule_provider.h"

class HostGuardRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override
    {
        if (command == "GET_RULES") {
            out.json = BuildAmsiRulesJson();
            return true;
        }
        if (command == "GET_ALL_RULES") {
            out.json = BuildAllRulesJson();
            return true;
        }

        error = "unknown command: " + command;
        return false;
    }

    void InvalidateRuleCache() override
    {
        // HostGuard 可在这里使规则缓存失效。
        // 如果 HostGuard 使用内存规则快照，也可以把此函数实现为 no-op。
    }

private:
    std::string BuildAmsiRulesJson();
    std::string BuildAllRulesJson();
};
```

语义要求：

- `GET_RULES` 返回 AMSI Provider 可加载的规则 JSON。
- `GET_ALL_RULES` 返回完整 assembled JSON。
- 未知 command 返回 `false`。
- 不要在 `BuildRulesResponse()` 内做远程网络拉取。
- 不要在 `BuildRulesResponse()` 内等待长时间锁。

## 5. 实现 Event Sink

```cpp
#include "amsi_event_sink.h"

class HostGuardAmsiEventSink final : public amsi_ipc::IAmsiEventSink {
public:
    void OnEventLine(const amsi_ipc::AmsiEventLine& event) override
    {
        // event.payload 是 DLL 发来的原始 JSON payload。
        // channel 层不解析业务语义。
        SubmitToHostGuardEventBus(event.payload);
    }
};
```

要求：

- `OnEventLine()` 不应长时间阻塞。
- DetectionEvent 优先级应高于 DiagLog。
- sink 负责识别 `cat`、`sensor`、`rule` 等业务字段。
- channel 只负责接收 payload 并透传。

## 6. 实现 Control Status Sink

```cpp
#include "amsi_control_status_sink.h"

class HostGuardAmsiControlStatusSink final : public amsi_ipc::IAmsiControlStatusSink {
public:
    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override
    {
        // status.payload 是 DLL 上报的 RULE_LOAD_RESULT 等控制状态 JSON。
        SubmitToHostGuardStatusBus(status.payload);
    }
};
```

要求：

- sink 负责解析 `RULE_LOAD_RESULT`。
- channel 不理解 `RULE_LOAD_RESULT` 语义。
- 不要在 sink 内反向控制 DLL 内部锁。

## 7. 构造 AmsiIpcHost

```cpp
#include "amsi_ipc_host.h"

class HostGuardAmsiModule {
public:
    bool Start()
    {
        AmsiIpcHostConfig config;
        config.logDir = "";
        config.rulesPath = "";
        config.stagingDir = "";
        config.enableDemoConfigWatcher = false;
        config.enableDemoStagingWatcher = false;

        AmsiIpcHostAdapters adapters;
        adapters.ruleProvider = &ruleProvider_;
        adapters.eventSink = &eventSink_;
        adapters.controlStatusSink = &controlStatusSink_;

        host_.reset(new AmsiIpcHost(config, adapters));
        return host_->Start();
    }

    void Stop()
    {
        if (host_) {
            host_->Stop();
            host_.reset();
        }
    }

private:
    HostGuardRuleProvider ruleProvider_;
    HostGuardAmsiEventSink eventSink_;
    HostGuardAmsiControlStatusSink controlStatusSink_;
    std::unique_ptr<AmsiIpcHost> host_;
};
```

当前注意事项：

- `AmsiIpcHostConfig` 仍保留 demo path 字段。
- HostGuard 模式应关闭 `enableDemoConfigWatcher` 和 `enableDemoStagingWatcher`。
- demo `rasp_sentry.exe` 不设置这两个字段，默认继续启用 watcher。

## 8. Demo-only 组件边界

| 组件 | 当前用途 | HostGuard 化后处理 |
|---|---|---|
| `DemoFileRuleProvider` | 从 `rasp_rules.json` 构造规则响应 | demo fallback，HostGuard 不依赖 |
| `RuleServer` | 兼容 wrapper + rules pipe lifecycle | 逐步退出新路径 |
| `EventCollector` | demo JSONL 落盘 | HostGuard event sink 替代 |
| `ControlStatusCollector` | demo control status JSONL 落盘 | HostGuard status sink 替代 |
| `ConfigWatcher` | demo 文件变更触发 reload | HostGuard 配置中心替代 |
| `AmsiStagingWatcher` | demo DLL staging / drain ack | HostGuard lifecycle 模块替代 |

## 9. 当前通道语义

| Pipe | 方向 | 生产方 | 消费方 | 当前状态 |
|---|---|---|---|---|
| `amsi_detect_rules` | DLL -> host 请求，host -> DLL 响应 | DLL 请求 command | `AmsiRuleChannel` + provider | 已支持 provider 注入 |
| `amsi_detect_events` | DLL -> host | DLL event worker / diag forwarder | `AmsiEventChannel` + sink | 已支持 sink 注入 |
| `amsi_detect_control_status` | DLL -> host | DLL rule load status | `AmsiControlStatusChannel` + sink | 已支持 sink 注入 |
| `amsi_detect_config` | host -> DLL | host broadcaster | DLL config listener | 当前仍为 1-byte reload/unload |

## 10. 当前未完成项

当前还没有完成：

- `AmsiIpcHost::BroadcastReload()`
- `AmsiIpcHost::BroadcastUnload()`
- `AmsiIpcHost::InvalidateRules()`
- demo `ConfigWatcher` 可选化
- demo `AmsiStagingWatcher` 可选化
- `RuleServer` 删除门禁

因此，HostGuard 现在可以基于注入接口验证 IPC 通道，但还不应该直接把当前 facade 当作最终生产 API。

## 11. 下一批建议

### Batch 5e-2：主动控制 API

目标：

- 在 `AmsiIpcHost` 上增加：
  - `BroadcastReload()`
  - `BroadcastUnload()`
  - `InvalidateRules()`

接口语义：

- `InvalidateRules()` 只调用当前有效 `IAmsiRuleProvider::InvalidateRuleCache()`。
- 如果当前使用 injected provider，失效通知发送给 injected provider。
- 如果当前使用 demo fallback provider，失效通知发送给内部 `DemoFileRuleProvider`。
- `AmsiIpcHost` façade 不读取规则文件、不解析 JSON、不重建规则。
- `BroadcastReload()` / `BroadcastUnload()` 只包装 `AmsiConfigBroadcaster`。
- 返回值使用现有 `amsi_ipc::AmsiBroadcastResult`。
- config pipe wire 继续保持 1-byte reload/unload 协议。
- façade API 不新增 ACK，不等待 DLL 完成业务 reload/unload。

推荐调用顺序：

```cpp
host.InvalidateRules();
auto result = host.BroadcastReload();
```

必须先 invalidate，再 broadcast reload。否则 DLL 收到 reload 后可能从 provider 拉到旧缓存。

测试要求：

- injected provider 模式下，`InvalidateRules()` 必须调用 fake provider。
- demo fallback 模式下，`InvalidateRules()` 不崩溃，rules pipe 仍可服务。
- `BroadcastReload()` 返回 broadcaster result。
- `BroadcastUnload()` 返回 broadcaster result。
- 未启动或已停止状态下 API 行为必须明确，不出现未定义访问。

边界：

- 不改 config pipe wire。
- 不改 DLL reload/unload 处理。
- 不改 rules/event/status 通道。

### Batch 5e-3：demo watcher 可选化

状态：已完成。

当前 `AmsiIpcHostConfig` 提供：

- `enableDemoConfigWatcher`
- `enableDemoStagingWatcher`

HostGuard 模式应显式设为 `false`。demo `rasp_sentry.exe` 使用默认值 `true`，行为保持不变。

## 12. 迁移红线

- HostGuard 不直接 include 或 new `RuleServer`。
- HostGuard 不直接 include 或 new `EventCollector`。
- HostGuard 不直接 include 或 new `ControlStatusCollector`。
- HostGuard 不直接 include 或 new `ConfigWatcher`。
- HostGuard 不直接 include 或 new `AmsiStagingWatcher`。
- channel 层不解析业务 JSON。
- sink/provider 层不控制 DLL 内部锁。
- 不改变 `amsi_detect_config` 1-byte reload/unload wire。
- 不删除 demo fallback，直到测试机和灰度环境不再依赖 `rasp_sentry.exe`。

## 13. Batch 5e-1 验收标准

- 本文档存在。
- HostGuard 最小调用方式清晰。
- rule/event/control status 三个注入点职责明确。
- demo-only 组件边界明确。
- 未修改生产代码。
- 未修改 pipe 协议。
