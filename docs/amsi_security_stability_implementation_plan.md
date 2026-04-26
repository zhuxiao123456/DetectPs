# DetectPsByAmsi 安全与稳定性实施计划

文档日期: 2026-04-27

适用目录:
- `D:\Code\rasp\DetectPsByAmsiCodex`

适用分支:
- `codex`

目标范围:
- `src/rasp_mod_amsi`
- `src/rasp_rule_engine`
- `src/rasp_sentry_native`

---

## 1. 背景与目标

本实施计划面向当前 AMSI Provider 方案的安全与稳定性加固，优先解决以下高风险问题:

- `DllMain` 中执行复杂初始化导致 Loader Lock / 宿主卡死风险
- 规则热更新快照与扫描线程并发导致 UAF / 崩溃风险
- 扫描链路默认 fail-open，异常路径易被绕过
- 样本仅扫描前 `1023` 字节，存在经典截断绕过
- 未使用 AMSI Session，存在分段脚本绕过
- 命名管道 ACL 过宽，存在低权限本地滥用面
- 事件与 ACK 缺少结构化校验，存在伪造风险

本计划遵循以下原则:

- 先稳生命周期，再稳并发，再补输入完整性，最后收紧控制面
- 优先选择最小侵入、可验证、可回退的改造
- 所有失败路径必须显式可观测，不允许“静默失败”
- 本轮不追求检测率最大化，优先消除系统性风险

---

## 2. 本轮实施范围

### 2.1 本轮纳入

- 生命周期去风险
- 并发与资源安全
- 输入完整性与失败策略
- IPC 权限与后端健壮性

### 2.2 本轮不纳入

- 高级 PowerShell AST 语义分析
- 云侧联动
- 完整 EDR 主数据面建模
- 大规模规则体系重构
- 模型化评分系统

---

## 3. 总体阶段划分

本轮实施分为四个阶段:

1. `Phase 1: 生命周期去风险`
2. `Phase 2: 并发与资源安全`
3. `Phase 3: 输入完整性与失败策略`
4. `Phase 4: IPC 权限与后端健壮性`

执行顺序固定为:

`Phase 1 -> Phase 2 -> Phase 3 -> Phase 4`

原因:
- `Phase 1` 是宿主稳定性的前提
- `Phase 2` 是后续所有状态变更的并发基础
- `Phase 3` 才开始实质收缩绕过面
- `Phase 4` 负责把本机控制面和数据面滥用面收紧

---

## 4. Phase 1: 生命周期去风险

### 4.1 目标

将 Provider 从“在 `DllMain` 中做重初始化”的高风险模式，改造成“惰性初始化 + 保守卸载 + inert mode”模式。

### 4.2 关键设计

- `DllMain` 极简化
- 初始化延迟到 `CreateInstance()` 或首次 `Scan()`
- `Unload` 优先进入 inert mode
- 进入 inert mode 后立即切断所有外部 IPC 等待
- inert mode 下所有后续 `Scan()` 直接快速返回 `AMSI_RESULT_NOT_DETECTED`

### 4.3 详细改造项

#### A. 精简 `DllMain`

目标文件:
- `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`

当前问题:
- `DllMain(DLL_PROCESS_ATTACH)` 中执行:
  - `new AmsiRuleEngine()`
  - `Initialize()`

计划修改:
- 保留:
  - `g_hModule = hInst`
  - `DisableThreadLibraryCalls(hInst)`
- 删除:
  - `g_engine = new AmsiRuleEngine()`
  - `g_engine->Initialize()`

结果要求:
- `DllMain` 不做 IPC
- `DllMain` 不创建线程
- `DllMain` 不做规则加载

#### B. 引入统一惰性初始化入口

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/include/amsi_rule_engine.h`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

新增设计:
- `EnsureEngineInitialized()`
- `TryGetEngine()`
- `GetEngineState()`

状态枚举建议:
- `Uninitialized`
- `Initializing`
- `Ready`
- `Inert`
- `Stopping`
- `Stopped`

实现要求:
- 使用 `std::once_flag` / `std::call_once`
- `CreateInstance()` 中可先触发一次初始化
- `Scan()` 中必须有兜底初始化

#### C. `OnUnloadSignal()` 改为 inert mode

目标文件:
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`

当前问题:
- 现有链路依赖 `FreeLibraryAndExitThread`
- 背景线程与 DLL 卸载时序复杂，高风险

计划修改:
- 第一版不做激进 DLL 自卸载
- `OnUnloadSignal()` 改为:
  - 状态切换到 `Inert`
  - 停止 config/retry/log 线程
  - 关闭或不再等待外部 pipe
  - Provider 进入“仍驻留，但不工作”状态

`Scan()` 行为:
- 若状态为 `Inert/Stopping/Stopped`
- 直接 `*result = AMSI_RESULT_NOT_DETECTED`
- 立即返回 `S_OK`

#### D. `DllCanUnloadNow()` 保守化

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`

计划修改:
- 第一阶段建议直接保守返回 `S_FALSE`
- 或仅在以下条件全部满足后允许卸载:
  - 无活动 provider
  - engine 状态为 `Stopped`
  - 后台线程全停
  - 无在途 scan

### 4.4 特别注意事项

#### TLS 风险核查

由于当前会继续保留 `DisableThreadLibraryCalls`，必须检查:
- 是否有依赖线程 detach 通知的 TLS 对象
- 是否存在复杂 C++ 线程局部析构逻辑

若存在:
- 改为显式生命周期管理
- 不依赖线程退出回调

### 4.5 验证要求

- sentry 未启动时，PowerShell 加载 Provider 不应卡死
- PowerShell 反复启动/退出，不因 Provider 初始化崩溃
- unload 信号触发后，后续扫描直接 pass-through，不等待外部 pipe

---

## 5. Phase 2: 并发与资源安全

### 5.1 目标

消除:
- 规则热更新 UAF
- 全局引擎实例读写竞争
- shutdown/reload/scan 时序竞态
- 高负载下扫描链路无上限资源消耗

### 5.2 关键设计

- 规则快照使用原子化 `shared_ptr`
- 全局 engine 访问统一封装
- 扫描链路引入在途扫描计数
- 引入扫描超时熔断机制

### 5.3 详细改造项

#### A. 快照改为原子 `shared_ptr`

目标文件:
- `src/rasp_mod_amsi/include/amsi_rule_engine.h`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

当前问题:
- `m_snapshot` 为裸指针
- `SwapRules()` 中 `exchange(next)` 后立即 `delete old`

计划修改:
- `m_snapshot` 改为 `std::shared_ptr<const RuleSnapshot>`
- 读写使用:
  - `std::atomic_load`
  - `std::atomic_store`

要求:
- 不直接裸指针遍历共享快照
- 每次 `Evaluate()` 开头获取本地 `shared_ptr` 副本

#### B. 全局 `g_engine` 访问安全化

目标文件:
- `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

计划修改:
- 不再散落式直接访问 `g_engine`
- 统一封装:
  - `LoadEngine()`
  - `StoreEngine()`
  - `ClearEngine()`
  - `TryGetEngine()`

要求:
- 多线程同时读写全局实例时不崩溃
- 初始化、停止、清理都有明确状态边界

#### C. 在途扫描计数

目标文件:
- `src/rasp_mod_amsi/include/amsi_rule_engine.h`
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

新增设计:
- `active_scan_count`
- `ScanGuard` RAII

停止流程要求:
- 先将状态置为 `Stopping`
- 拒绝新请求进入扫描链
- 等待 `active_scan_count == 0`
- 再关闭后台线程和内部资源

#### D. 超时熔断机制

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
- `src/rasp_rule_engine/src/rasp_lua_engine.cpp`

新增策略:
- 单次扫描总预算建议 `1000ms`
- Lua 子预算建议 `200ms ~ 500ms`

超时行为:
- 标记 `SCAN_TIMEOUT`
- 根据策略决定:
  - `allow`
  - `audit`
  - `block`

补充熔断:
- 规则执行次数阈值
- regex 调用次数阈值
- session 聚合后内容复杂度阈值

#### E. reload 原子切换

目标文件:
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

要求:
- reload 期间只构建新快照
- 旧快照保持可用
- 新快照完全构造成功后再切换
- 若失败，继续使用旧快照

### 5.4 验证要求

- 多线程 `Scan()` + 多次 reload 并发运行不崩溃
- shutdown 中并发 scan 最终平稳收敛
- scan 超时后能进入既定策略而非挂住宿主

---

## 6. Phase 3: 输入完整性与失败策略

### 6.1 目标

在样本最大长度 `4KB` 的约束下:
- 最大化有效检测面
- 收缩经典截断绕过
- 收缩边界切分绕过
- 收缩 session 分段绕过
- 明确失败策略

### 6.2 固定约束

本阶段样本最大长度上限固定为:

- `4KB`

即:
- `kMaxSampleBytes = 4096`

### 6.3 关键设计

- 不再只读前 `1023` 字节
- 统一构造多视图样本
- 超出 `4KB` 的内容使用窗口扫描
- 窗口之间必须有 overlap
- session 聚合必须带内存硬限制与 LRU

### 6.4 详细改造项

#### A. 样本读取上限提升到 `4KB`

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`

计划修改:
- 将当前固定 `sample[1024]` 改为支持 `4096` 字节
- 无论 `CONTENT_ADDRESS` 还是 `Read()`，都以 `4096` 为上限

需记录字段:
- `originalContentSize`
- `sampledBytes`
- `truncated`

#### B. 大于 `4KB` 的窗口扫描与重叠区

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

设计:
- 使用:
  - prefix
  - middle rolling windows
  - suffix

建议参数:
- 窗口大小: `1024`
- overlap: `256` 或 `512`

目标:
- 攻击者将恶意特征卡在 chunk 边界时，仍可在 overlap 中被命中

#### C. 编码处理重构

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

当前问题:
- `WideToUtf8()` 存在越界写风险
- 宽字符识别过于启发式

计划修改:
- 修复 `WideToUtf8()` 内存边界
- 输出多个视图:
  - `body_raw`
  - `body_utf8`
  - `body_utf16le_decoded`
- 若转换失败:
  - 保留 raw
  - 明确记录失败原因

#### D. 最小 session 聚合

新增模块建议:
- `src/rasp_mod_amsi/include/amsi_session_cache.h`
- `src/rasp_mod_amsi/src/amsi_session_cache.cpp`

设计:
- key:
  - `pid`
  - `appName`
  - `sessionId`
- value:
  - 最近 N 个片段
  - 合并文本
  - 最后访问时间
  - 当前聚合字节数

限制要求:
- 单 session 最大聚合长度: `16KB`
- 全局 session 总数上限
- 全局缓存内存硬上限
- LRU 淘汰

接口要求:
- `AddFragment(...)`
- `GetMergedView(...)`
- `CloseSession(...)`
- `EvictIfNeeded()`

#### E. 失败策略配置化

目标文件:
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- 配置文件:
  - 可扩展 `rasp_rules.json`
  - 或新增 Provider 专用配置

建议配置项:
- `fail_policy.engine_not_ready`
- `fail_policy.scan_timeout`
- `fail_policy.decode_failed`
- `fail_policy.rule_runtime_failed`

每项可选值:
- `allow`
- `audit`
- `block`

#### F. reason code 体系

建议新增事件字段:
- `failure_stage`
- `failure_code`
- `fallback_action`
- `truncated`
- `window_strategy`
- `session_aggregated`

### 6.5 验证要求

- `4KB` 内后段恶意内容可进入检测链
- 大于 `4KB` 的跨边界恶意片段通过 overlap 仍可能命中
- 多段 benign-looking fragment 聚合后可命中
- 大量未闭合 session 不导致 OOM
- 各失败路径行为符合配置

---

## 7. Phase 4: IPC 权限与后端健壮性

### 7.1 目标

收紧本机控制面和数据面的滥用面，避免:
- 低权限本地进程读规则
- 低权限本地进程伪造事件
- 低权限本地进程发送 reload/unload
- 非法规则结构破坏运行时

### 7.2 关键设计

- Pipe ACL 按最小权限收敛
- 引入完整性级别限制
- ACK 走结构化校验，不再字符串 contains
- 应用规则前做 schema 校验
- JSON 解析必须防御性封装

### 7.3 详细改造项

#### A. Pipe ACL 收紧

目标文件:
- `src/rasp_sentry_native/src/pipe_security.cpp`

当前问题:
- `Authenticated Users` 可读写规则/事件 pipe

计划修改:
- 删除 `Authenticated Users`
- 改为:
  - `SYSTEM`
  - `Builtin Administrators`
  - service SID

补充建议:
- 若实现条件允许，引入完整性级别限制:
  - 至少 `High IL`

#### B. Config pipe 持续最严格控制

目标文件:
- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`

计划修改:
- 保留 secure SDDL 思路
- 增加对完整性级别的限制
- 中完整性普通进程不得发送 reload/unload

#### C. `drain-ack` 结构化校验

目标文件:
- `src/rasp_sentry_native/src/event_collector.cpp`
- `src/rasp_sentry_native/src/amsi_staging_watcher.cpp`

短期方案:
- 不再通过 `find("\"cat\":\"drain-ack\"")` 判定
- 改为 JSON 解析并校验:
  - `cat == drain-ack`
  - `mod == rasp_mod_amsi`
  - `pid` 合法

中期方案:
- 独立 ACK pipe
- 引入 nonce / challenge 绑定本次 unload

#### D. RuleServer schema 校验

目标文件:
- `src/rasp_sentry_native/src/rule_server.cpp`

计划修改:
- `BuildAssembledJson()` 后，在发布前进行 schema 校验
- 非法结构直接拒绝加载
- 继续保留旧快照

校验点:
- 顶层对象结构
- `rules` 数组存在性
- 每条 rule 的必要字段
- `sensor/mode/confidence/scriptTimeoutMs` 类型和值域

#### E. JSON 防御性封装

目标文件:
- `src/rasp_sentry_native/src/rule_server.cpp`
- `src/rasp_sentry_native/src/event_collector.cpp`

要求:
- 所有 JSON 解析必须被 `try/catch` 包裹
- 坏输入仅记录，不允许线程退出
- 不允许未捕获异常穿透线程边界

#### F. 规则路径 canonicalization

目标文件:
- `src/rasp_sentry_native/src/rule_server.cpp`

计划修改:
- 规范化 `script` / `globalLibraries` 路径
- 目标路径必须位于 `rulesDir` 内
- 路径逃逸直接拒绝

#### G. EventCollector 限流与尺寸控制

目标文件:
- `src/rasp_sentry_native/src/event_collector.cpp`

新增要求:
- 单事件最大长度限制
- 超长直接丢弃并记录
- `drain-ack` / `detection` / `diag` 分类别计数
- 加基础速率限制，避免日志洪泛

### 7.4 验证要求

- 中完整性普通进程连接 pipe 失败
- 伪造 drain-ack 不生效
- 非法 rules JSON 不影响旧规则工作
- 路径逃逸配置被拒绝
- 超长事件不会打崩 collector

---

## 8. 文件级实施清单

### 8.1 第一批高优先级改动文件

- `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`
- `src/rasp_mod_amsi/src/amsi_provider.cpp`
- `src/rasp_mod_amsi/include/amsi_rule_engine.h`
- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
- `src/rasp_rule_engine/src/rasp_lua_engine.cpp`
- `src/rasp_sentry_native/src/pipe_security.cpp`
- `src/rasp_sentry_native/src/rule_server.cpp`
- `src/rasp_sentry_native/src/event_collector.cpp`
- `src/rasp_sentry_native/src/amsi_staging_watcher.cpp`

### 8.2 可能新增文件

- `src/rasp_mod_amsi/include/amsi_session_cache.h`
- `src/rasp_mod_amsi/src/amsi_session_cache.cpp`
- 测试目录与回归样本目录

---

## 9. 测试与验证计划

### T1 生命周期
- sentry 未启动
- 启动 PowerShell
- 结果:
  - 不挂死
  - 不显著卡顿
  - 不崩溃

### T2 惰性初始化
- 第一次 COM 创建实例
- 第一次 `Scan()`
- 结果:
  - engine 只初始化一次

### T3 并发 reload
- 多线程持续 `Scan()`
- 后台持续广播 reload
- 结果:
  - 不崩溃
  - 无 UAF

### T4 inert mode
- 触发 unload
- 后续 `Scan()` 全部快速 pass-through
- 不再访问外部 pipe

### T5 4KB 样本完整性
- 恶意关键字放在 `3KB ~ 4KB`
- 应仍可进入检测链

### T6 overlap windows
- 恶意特征切分在 chunk 边界
- overlap 后仍可命中

### T7 session 聚合
- 多段 benign-looking fragment
- 聚合后命中
- `CloseSession()` 后缓存清理

### T8 session OOM 防御
- 模拟大量未闭合 session
- 内存不失控
- LRU 生效

### T9 fail policy
- 构造:
  - `engine_not_ready`
  - `decode_failed`
  - `timeout`
- 验证行为符合配置

### T10 pipe 权限
- 中完整性普通进程尝试连接:
  - `rules`
  - `events`
  - `config`
- 预期:
  - 被拒绝或仅保留最小允许访问

### T11 schema 校验
- 构造字段缺失/类型错误规则
- 预期:
  - 旧规则继续工作
  - 新规则拒绝发布

---

## 10. 里程碑

### M1
- Provider 从 `DllMain` 重初始化切换到惰性初始化

### M2
- 快照与全局引擎并发安全
- reload/scan/shutdown 可并行

### M3
- 样本上限提升到 `4KB`
- 支持 overlap windows
- 支持最小 session 聚合

### M4
- pipe 权限收紧
- ACK 防伪
- 规则 schema 校验上线

### M5
- 形成稳定性/绕过/权限验证基线

---

## 11. 风险与回退策略

### 11.1 风险

- 生命周期调整可能改变 Provider 被宿主初始化的时机
- inert mode 替代主动卸载后，DLL 驻留时间会变长
- 原子化 `shared_ptr` 会带来少量并发开销
- session 聚合若限制不当，可能引入新的内存压力
- ACL 收紧后，若 SID/IL 配置不当，可能导致合法后端无法连接

### 11.2 回退策略

- 每个 phase 单独提交
- 每个 phase 完成后先做最小验证，再进入下一阶段
- fail policy 默认从保守 audit 开始
- session 聚合默认先开最小容量，再按验证结果放宽
- ACL 先在测试环境验证，再切生产默认值

---

## 12. 推荐执行顺序

1. `Phase 1`
2. `Phase 2`
3. `Phase 3`
4. `Phase 4`

理由:
- 若 `Phase 1` 不先做，后续任何改动都可能继续踩 Loader Lock
- 若 `Phase 2` 不先做，reload/scan 并发下所有新能力都不可靠
- `Phase 3` 在稳定基础上补绕过面最划算
- `Phase 4` 是控制面与防御面收口

---

## 13. 下一步

建议立即按以下顺序进入实施:

1. 先做 `Phase 1`
2. 紧接着做 `Phase 2`
3. `Phase 1 + Phase 2` 验证通过后，再进入 `Phase 3`

这是当前性价比最高、同时对宿主稳定性收益最大的路线。
