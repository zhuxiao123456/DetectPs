# DetectPsByAmsi 工程级审计报告

审计时间: 2026-04-26

审计范围:
- `src/rasp_mod_amsi`
- `src/rasp_rule_engine`
- `src/rasp_sentry_native`
- `rasp_rules.json`
- `rules/*.lua`

说明:
- 本报告基于项目代码本身做工程级审计，不展开 AMSI 基础原理。
- 当前项目并不是主动 `LoadLibrary("amsi.dll")` 后调用 `AmsiScanBuffer/AmsiScanString` 的 AMSI client。
- 当前项目实际模式是: 将 `rasp_mod_amsi.dll` 注册为 Windows AMSI Provider，由 PowerShell/AMSI 框架反向调用 `IAntimalwareProvider::Scan()`。
- 全仓库未发现 `AmsiInitialize`、`AmsiOpenSession`、`AmsiScanString`、`AmsiScanBuffer`、`AmsiCloseSession`、`AmsiUninitialize` 调用链。

---

## 1. 项目总体评价

这套工程已经具备原型级闭环:
- AMSI Provider DLL
- 规则引擎
- Lua/PCRE2 规则运行时
- 本地 sentry 后端
- 规则热更新
- 事件落盘

当前源码可正常构建:
- `src\rasp_mod_amsi\build\Release\rasp_mod_amsi.dll`
- `src\rasp_sentry_native\build\Release\rasp_sentry.exe`

但从安全产品和 EDR 集成视角看，当前版本仍不适合直接进入主防护链，主要问题包括:
- `DllMain` 中做复杂初始化
- 规则热更新存在并发 UAF 风险
- 扫描默认 fail-open
- 仅取前 1KB 样本，易被长度绕过
- 未实现会话级聚合，易被分段绕过
- 命名管道权限过宽，可被低权限进程滥用
- 检测能力仍以关键字/正则为主，语义能力不足
- 日志和事件链路容易被刷爆或伪造

结论:
- 适合作为研究原型和规则实验平台
- 不适合作为现阶段生产级 EDR AMSI 主模块直接落地

---

## 2. AMSI 检测主调用链

当前实际调用链如下:

1. `DllRegisterServer()` 将 Provider CLSID 注册到 COM 和 AMSI Providers
2. PowerShell / AMSI 框架加载 `rasp_mod_amsi.dll`
3. `DllMain(DLL_PROCESS_ATTACH)` 创建全局 `g_engine` 并调用 `Initialize()`
4. `DllGetClassObject()` 返回 `CRaspAmsiProviderFactory`
5. `CRaspAmsiProviderFactory::CreateInstance()` 创建 `CRaspAmsiProvider`
6. AMSI 框架回调 `CRaspAmsiProvider::Scan(IAmsiStream*, AMSI_RESULT*)`
7. `Scan()` 从 `IAmsiStream` 取:
   - `AMSI_ATTRIBUTE_CONTENT_NAME`
   - `AMSI_ATTRIBUTE_APP_NAME`
   - `AMSI_ATTRIBUTE_CONTENT_SIZE`
   - `AMSI_ATTRIBUTE_CONTENT_ADDRESS`
   - 失败时 fallback 到 `stream->Read()`
8. `Scan()` 对样本做简单 UTF-16LE -> UTF-8 压缩
9. `Scan()` 调用 `AmsiRuleEngine::Evaluate(contentName, appName, sample, sampleLen)`
10. `AmsiRuleEngine` 组装 `RaspLuaContext`
11. `AmsiRuleEngine::Evaluate("AmsiProvider", ctx)` 进入规则匹配
12. 先跑 `regexChecks/regexPatterns`
13. 再进入 `RaspLuaEngine::Run()`
14. 命中后调用 `SendDetectionEvent()`
15. 如规则为 `block`，`Scan()` 返回 `AMSI_RESULT_DETECTED`
16. 后端 `EventCollector` 从 `\\.\pipe\rasp_sentry_events` 收到 JSON 事件并落盘

完整流程可还原为:

脚本输入
-> AMSI 框架构造 `IAmsiStream`
-> Provider `Scan()`
-> 提取 `contentName/appName/body`
-> 简单编码判断与压缩
-> 构建 `RaspLuaContext`
-> 正则 gate
-> Lua 规则执行
-> 命中后发送事件
-> 根据 `rule.mode` 决定 audit/block

---

## 3. 核心文件与函数定位

### 3.1 AMSI Provider 与入口

- `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`
  - `DllRegisterServer()`
  - `DllUnregisterServer()`
  - `DllMain()`

- `src/rasp_mod_amsi/src/amsi_provider.cpp`
  - `CRaspAmsiProvider::Scan()`
  - `CRaspAmsiProvider::CloseSession()`
  - `CRaspAmsiProviderFactory::CreateInstance()`
  - `DllGetClassObject()`
  - `DllCanUnloadNow()`

### 3.2 AMSI 规则执行主链

- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
  - `AmsiRuleEngine::Evaluate(const wchar_t*, const wchar_t*, const char*, ULONG)`
  - `AmsiRuleEngine::Evaluate(const std::string&, const RaspLuaContext&)`
  - `AmsiRuleEngine::ParseAndSwap()`
  - `AmsiRuleEngine::SwapRules()`
  - `AmsiRuleEngine::OnReloadSignal()`
  - `AmsiRuleEngine::OnUnloadSignal()`
  - `AmsiRuleEngine::UnloadThreadProc()`

### 3.3 公共基座

- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - `RaspSentryBase::Initialize()`
  - `RaspSentryBase::Shutdown()`
  - `RaspSentryBase::ConnectSentry()`
  - `RaspSentryBase::ParseRulesJson()`
  - `RaspSentryBase::SendDetectionEvent()`
  - `RaspSentryBase::ConfigPipeThreadProc()`
  - `RaspSentryBase::LogForwardThreadProc()`
  - `RaspSentryBase::SentryRetryThreadProc()`

### 3.4 Lua 与正则执行

- `src/rasp_rule_engine/src/rasp_lua_engine.cpp`
  - `RaspLuaEngine::Precompile()`
  - `RaspLuaEngine::Run()`
  - `RaspLuaEngine::MatchesAnyRegex()`
  - `RaspLuaEngine::GetOrCompilePcre2()`

### 3.5 后端 sentry

- `src/rasp_sentry_native/src/main.cpp`
  - `wmain()`

- `src/rasp_sentry_native/src/rule_server.cpp`
  - `RuleServer::ServerLoop()`
  - `RuleServer::BuildAssembledJson()`
  - `RuleServer::FilterAmsiProviderRules()`

- `src/rasp_sentry_native/src/event_collector.cpp`
  - `EventCollector::ServerLoop()`
  - `EventCollector::AppendLine()`

- `src/rasp_sentry_native/src/config_watcher.cpp`
  - `ConfigWatcher::WatchDirectory()`
  - `ConfigWatcher::BroadcastReload()`

- `src/rasp_sentry_native/src/amsi_staging_watcher.cpp`
  - `AmsiStagingWatcher::TriggerUpdate()`
  - `AmsiStagingWatcher::BroadcastUnload()`
  - `AmsiStagingWatcher::WaitForDrainAck()`

### 3.6 规则文件

- `rasp_rules.json`
- `rules/amsi_p01.lua`
- `rules/lib/rasp_lib.lua`

---

## 4. 发现的问题清单

以下按问题标题列出，详细说明见后续章节。

1. `DllMain` 中执行复杂初始化，存在 Loader Lock 风险
2. 规则热更新快照交换存在并发 UAF 风险
3. 扫描路径默认 fail-open
4. 仅扫描前 1023 字节，存在明显长度绕过
5. 未使用 AMSI session，存在分段脚本绕过
6. `WideToUtf8()` 存在 1 字节越界写风险
7. 事件与规则命名管道 ACL 过宽
8. `drain-ack` 可被伪造
9. 自定义 JSON 解析器脆弱且语义不完整
10. 固定大小 IPC 缓冲区存在截断/丢失风险
11. 每次扫描为每条 Lua 规则新建 Lua VM，性能开销高
12. 调试日志泄露样本内容，且可被放大为 DoS
13. 规则配置字段语义漂移，部分字段未真正生效
14. `RuleServer` cache 存在无锁读写竞争
15. 规则文件相对路径拼接缺少目录逃逸防护

---

## 5. 安全漏洞与绕过风险

### 问题 1: `DllMain` 中执行复杂初始化
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`
  - `DllMain()`
- 问题描述:
  - `DllMain(DLL_PROCESS_ATTACH)` 内直接 `new AmsiRuleEngine()` 并调用 `Initialize()`
  - `Initialize()` 内会执行 IPC、线程创建、日志发送
- 可能影响:
  - PowerShell / 宿主进程加载 Provider 时卡死
  - 卸载过程不稳定
  - 触发 Loader Lock 死锁
- 触发条件:
  - DLL 被系统加载
  - sentry 未就绪或命名管道异常
- 修复建议:
  - `DllMain` 只保存 `g_hModule`
  - 把 `Initialize()` 延后到 `CreateInstance()` 或首个 `Scan()`
  - 用 `std::once_flag` 保证只初始化一次
- 推荐优先级: P0

### 问题 2: 规则快照交换存在并发 UAF
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
  - `SwapRules()`
  - `Evaluate(const std::string&, const RaspLuaContext&)`
- 问题描述:
  - `SwapRules()` 中 `m_snapshot.exchange(next)` 后立即 `delete old`
  - 扫描线程只读取裸指针 `snap`
- 可能影响:
  - reload 与 scan 并发时访问已释放内存
  - 进程崩溃
- 触发条件:
  - 规则热更新与高频扫描并发
- 修复建议:
  - 改成 `std::shared_ptr<const RuleSnapshot>` 原子交换
  - 或使用 RCU/epoch 风格延迟释放
- 推荐优先级: P0

### 问题 3: 默认 fail-open
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/src/amsi_provider.cpp`
  - `CRaspAmsiProvider::Scan()`
- 问题描述:
  - `*result` 默认设为 `AMSI_RESULT_NOT_DETECTED`
  - 任意异常路径都倾向直接放行
- 可能影响:
  - 后端掉线、规则损坏、编码失败、引擎未初始化时全部透传
- 触发条件:
  - `g_engine == nullptr`
  - `stream == nullptr`
  - 卸载中
  - 规则/脚本运行失败
- 修复建议:
  - 明确失败策略:
    - `strict-block`
    - `audit-only`
    - `fail-open-with-telemetry`
  - 至少记录失败原因与统计
- 推荐优先级: P0

### 问题 4: 仅扫描前 1023 字节
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/src/amsi_provider.cpp`
  - `CRaspAmsiProvider::Scan()`
- 问题描述:
  - 当前 `sample[1024]`
  - 样本只复制前 `sizeof(sample)-1`
- 可能影响:
  - 恶意主体放在 1KB 后即可绕过
- 触发条件:
  - 长脚本
  - 头部填充无害内容
- 修复建议:
  - 尽量读取完整样本
  - 大样本做窗口扫描/分块扫描
  - 记录 `truncated=true`
- 推荐优先级: P0

### 问题 5: 未使用 AMSI Session
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/include/rasp_mod_amsi.h`
  - `src/rasp_mod_amsi/src/amsi_provider.cpp`
  - `CloseSession()`
- 问题描述:
  - `CloseSession()` 空实现
  - 无任何 session 级缓存与上下文拼接
- 可能影响:
  - 将 payload 分多次输入可绕过
- 触发条件:
  - PowerShell 分段变量拼接、延迟执行
- 修复建议:
  - 引入 `(pid, appName, sessionId)` 级缓存
  - 聚合最近片段和解码结果
  - `CloseSession()` 负责清理
- 推荐优先级: P0

### 问题 6: `WideToUtf8()` 存在 1 字节越界写
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
  - `WideToUtf8()`
- 问题描述:
  - 先分配 `std::string s(len - 1, '\0')`
  - 然后 `WideCharToMultiByte(..., &s[0], len, ...)`
- 可能影响:
  - 堆越界写
  - 进程不稳定
- 触发条件:
  - `contentName/appName` 非空
- 修复建议:
  - 分配 `len`
  - 转换后去掉末尾 `\0`
  - 或输出缓冲长度传 `len - 1`
- 推荐优先级: P0

### 问题 7: 命名管道 ACL 过宽
- 风险等级: High
- 文件和函数:
  - `src/rasp_sentry_native/src/pipe_security.cpp`
  - `MakeAuthenticatedUsersSecurity()`
- 问题描述:
  - `Authenticated Users` 具备读写和创建 pipe instance 权限
- 可能影响:
  - 普通登录用户进程可读取规则、写事件、干扰流程
- 触发条件:
  - 本机任意低权限已认证用户进程
- 修复建议:
  - 限制为 `SYSTEM + Administrators + service SID`
  - 必要时校验 client SID/PID
- 推荐优先级: P0

### 问题 8: `drain-ack` 可伪造
- 风险等级: High
- 文件和函数:
  - `src/rasp_sentry_native/src/event_collector.cpp`
  - `AppendLine()`
- 问题描述:
  - 仅通过字符串查找 `"cat":"drain-ack"` 判断 ACK
- 可能影响:
  - 攻击者伪造卸载完成信号
  - 干扰热更新替换流程
- 触发条件:
  - 攻击者可写 `rasp_sentry_events` 道
- 修复建议:
  - 独立私有 ACK pipe
  - 结构化 JSON 解析与字段校验
  - 加 nonce / PID / token
- 推荐优先级: P0

### 问题 9: 编码与归一化处理过弱
- 风险等级: High
- 文件和函数:
  - `src/rasp_mod_amsi/src/amsi_provider.cpp`
- 问题描述:
  - 仅启发式识别 UTF-16LE
  - 未做 Base64 解码、压缩解码、拼接归一化、去混淆
- 可能影响:
  - `EncodedCommand`
  - `[Convert]::FromBase64String`
  - 字符串拆分/拼接
  - 反引号混淆
  - 反射延迟调用
  等场景漏报
- 触发条件:
  - 经过编码、压缩、拼接或变形的 PowerShell
- 修复建议:
  - 引入多视图扫描:
    - raw bytes
    - UTF-16LE decode
    - Base64 candidate decode
    - whitespace/caret/backtick normalized
    - string-join collapsed
- 推荐优先级: P0

### 问题 10: 固定大小 IPC 缓冲区
- 风险等级: Medium
- 文件和函数:
  - `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - `ConnectSentry()`
  - `src/rasp_sentry_native/src/event_collector.cpp`
- 问题描述:
  - 规则响应缓冲区固定 `512KB`
  - 事件读取缓冲区固定 `64KB`
- 可能影响:
  - 大规则集截断
  - 大事件丢失
- 触发条件:
  - 规则增多
  - payload 较大
- 修复建议:
  - 长度前缀协议
  - 消息循环读取
- 推荐优先级: P1

### 问题 11: 规则文件路径拼接缺少逃逸防护
- 风险等级: Medium
- 文件和函数:
  - `src/rasp_sentry_native/src/rule_server.cpp`
  - `InlineGlobalLibraries()`
  - `InlineScriptFiles()`
- 问题描述:
  - 直接 `rulesDir + "\\" + relPath`
  - 未做 canonicalize 后的目录约束校验
- 可能影响:
  - 若规则文件被篡改，可读取外部任意文件
- 触发条件:
  - 配置文件被攻击者写入恶意相对路径
- 修复建议:
  - 规范化路径
  - 校验目标必须落在 `rulesDir` 下
- 推荐优先级: P1

### 问题 12: 日志泄露与日志 DoS
- 风险等级: Medium
- 文件和函数:
  - `rules/amsi_p01.lua`
  - `rules/lib/rasp_lib.lua`
  - `src/rasp_rule_engine/src/rasp_lua_engine.cpp`
- 问题描述:
  - `dbg()` 每次扫描打印 body 前 80 字节
  - 规则命中/未命中都可能产生大量日志
- 可能影响:
  - 敏感脚本泄露
  - 高并发下 I/O 放大
- 触发条件:
  - 高频扫描
  - 复杂脚本内容
- 修复建议:
  - 生产默认禁用 `dbg`
  - 设置日志采样、限速、截断
- 推荐优先级: P1

### 问题 13: RuleServer cache 存在读写竞争
- 风险等级: Medium
- 文件和函数:
  - `src/rasp_sentry_native/src/rule_server.cpp`
  - `GetAssembledJson()`
  - `GetAmsiRulesJson()`
- 问题描述:
  - 先无锁读取 `m_cachedAssembled/m_cachedAmsiRules`
  - 写操作在锁内
- 可能影响:
  - 并发请求下未定义行为
- 触发条件:
  - 多个客户端同时请求规则
- 修复建议:
  - 全量加锁
  - 或改成原子 `shared_ptr<const std::string>`
- 推荐优先级: P1

### 问题 14: 每次规则执行创建新 Lua VM
- 风险等级: Medium
- 文件和函数:
  - `src/rasp_rule_engine/src/rasp_lua_engine.cpp`
  - `Run()`
- 问题描述:
  - 每次扫描、每条 Lua 规则都 `luaL_newstate()`
- 可能影响:
  - 高 CPU
  - 高内存抖动
  - 高延迟
- 触发条件:
  - 高频 PowerShell 事件
  - 规则较多
- 修复建议:
  - 预编译字节码
  - 每线程 VM 池
  - 限制执行链长度
- 推荐优先级: P1

### 问题 15: 自定义 JSON 解析器脆弱
- 风险等级: Medium
- 文件和函数:
  - `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - `Parser::*`
  - `ParseRulesJson()`
- 问题描述:
  - 只支持非常有限的 JSON 语义
  - 转义、Unicode、错误恢复能力不足
- 可能影响:
  - 规则字段误解析
  - 配置坏掉但表现为静默失效
- 触发条件:
  - 复杂 JSON
  - 特殊字符
- 修复建议:
  - 统一换成成熟 JSON 库
- 推荐优先级: P1

---

## 6. 代码质量问题

### 6.1 模块边界

当前模块边界有雏形，但 `RaspSentryBase` 责任过重，集成了:
- IPC
- JSON 解析
- 日志缓冲
- 配置线程
- 事件发送
- 生命周期管理

建议拆分为:
- `RuleControlClient`
- `EventEmitter`
- `DiagLogger`
- `ConfigSignalServer`
- `RuleSnapshotStore`

### 6.2 AMSI 调用封装

当前 Provider 逻辑直接散落在 `CRaspAmsiProvider::Scan()` 中，建议拆出:
- `AmsiStreamExtractor`
- `AmsiNormalizer`
- `AmsiScanner`
- `AmsiDecisionEngine`

这样可测试性和可维护性会明显提升。

### 6.3 错误处理

很多关键路径是"失败即静默放过":
- `GetAttribute` 失败
- `Read` 失败
- Lua 脚本失败
- 事件发送失败
- sentry 未连接

建议统一 error model:
- `error_code`
- `failure_stage`
- `security_impact`
- `fallback_action`

### 6.4 耦合度

当前:
- 扫描逻辑和日志逻辑耦合
- 规则执行和事件发送耦合
- Provider 生命周期和热更新耦合

不利于后续迁入更大 EDR。

### 6.5 可测试性

未发现:
- 单元测试
- 集成测试
- 回归样本测试
- 性能测试
- 并发压力测试

这是进入生产 EDR 的明显短板。

---

## 7. 检测能力不足点

### 7.1 当前主要依赖

当前检测能力主要依赖:
- `AMSI-P01` Lua 正则/关键字规则
- `AMSI-P02` JSON 级 regex 规则

即:
- 关键字命中
- PCRE2 regex 命中
- 少量 Lua 条件逻辑

### 7.2 可以命中的典型场景

现有规则对以下表层特征有一定覆盖:
- `-EncodedCommand`
- `-enc`
- `IEX`
- `Invoke-Expression`
- `DownloadString`
- `DownloadFile`
- `Invoke-WebRequest`
- `Net.WebClient`
- `VirtualAlloc`
- `WriteProcessMemory`
- `CreateThread`
- `LoadLibrary`
- 常见红队工具名

### 7.3 主要不足

- 仍然偏关键字/正则匹配
- 缺少语义理解
- 缺少上下文关联
- 缺少解码链分析
- 缺少行为评分
- 缺少分段重组

### 7.4 主要漏报风险

- Base64 编码后二次执行
- 字符串拼接:
  - `"I" + "EX"`
  - `"Down" + "loadString"`
- 反引号混淆
- `[char]` 构造
- `Join`/`Replace`/`Format`
- 反射加载
- `Assembly.Load`
- 内存流加载
- 会话级多段构造
- 延迟执行
- 间接调用 `System.Management.Automation`

### 7.5 误报风险

以下规则较容易打到合法管理脚本:
- `invoke-command`
- `downloadfile`
- `loadlibrary`
- `virtualalloc`

缺少上下文判定时，block 模式下误报风险不可忽略。

---

## 8. 改进建议

### 8.1 `amsi.dll` 安全加载方式

当前项目不主动加载 `amsi.dll`，因此这里的建议面向后续扩展:
- 优先静态链接 `amsi.lib`
- 若必须动态加载:
  - 使用 `LoadLibraryExW`
  - 仅允许 `LOAD_LIBRARY_SEARCH_SYSTEM32`
  - 明确拒绝当前目录搜索

### 8.2 AMSI API/Provider 封装建议

建议新增组件:
- `AmsiProviderHost`
- `AmsiStreamExtractor`
- `AmsiNormalizer`
- `AmsiEngine`
- `AmsiDecisionPolicy`

### 8.3 输入归一化建议

至少生成以下扫描视图:
- raw bytes
- UTF-16LE decoded
- UTF-8 normalized
- whitespace normalized
- backtick removed
- Base64 decoded candidate
- join/concat collapsed candidate

### 8.4 扫描失败时安全策略

建议提供可配置策略:
- `strict_block`
- `audit_on_failure`
- `fail_open_with_evidence`

默认不要"静默放行"。

### 8.5 日志与证据字段

建议事件中增加:
- `pid`
- `ppid`
- `tid`
- `sessionId`
- `processPath`
- `hostProcessName`
- `sample_len`
- `truncated`
- `decode_chain`
- `engine_failure_reason`
- `rule_version`
- `engine_version`
- `sha256(sample)`

### 8.6 多线程与资源生命周期

- 禁止在 `DllMain` 内创建线程
- `g_engine` 使用安全生命周期容器
- 快照改 `shared_ptr`
- 热更新与扫描解耦
- 自卸载链路单独重构

### 8.7 检测规则与评分模型

建议从"单条规则直接 block"升级为:
- regex gate
- feature extraction
- semantic hints
- score aggregation
- policy threshold

### 8.8 性能优化

- Lua 预编译字节码
- 每线程 `lua_State` 池
- 事件发送改内存队列
- 日志采样和限速
- 大脚本分层扫描

### 8.9 与 EDR 集成时的模块拆分

建议拆为:
- `provider-adapter`
- `scanner-core`
- `rule-runtime`
- `telemetry-client`
- `control-plane-client`

### 8.10 分阶段改造路线

短期:
- 修 `DllMain`
- 修 UAF
- 修 fail-open
- 修 1KB 截断
- 修 ACL
- 修 UTF-8 越界

中期:
- 引入 session 聚合
- 引入多视图归一化
- 引入规则 schema 校验
- 引入异步事件队列
- 加测试体系

长期:
- 上评分模型
- 上上下文关联
- 和 EDR 进程/脚本/网络/行为证据联动

---

## 9. 优先级排序

### P0
- `DllMain` 复杂初始化
- 规则快照 UAF
- fail-open
- 样本仅 1KB
- session 未聚合
- `WideToUtf8` 越界
- 规则/事件 pipe ACL 过宽
- `drain-ack` 伪造

### P1
- 事件/规则固定缓冲区
- 路径逃逸
- 日志泄露与 DoS
- RuleServer cache 竞争
- 自定义 JSON 解析器
- Lua VM 每次重建

### P2
- 多视图归一化
- 行为评分
- 回归样本库
- 性能基准

### P3
- 与更大 EDR 的统一主数据模型集成
- 更强的上下文关联检测

---

## 10. 建议修改的文件 / 函数 / 模块

### 10.1 立即修改

- `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`
  - `DllMain()`
  - `DllCanUnloadNow()`

- `src/rasp_mod_amsi/src/amsi_provider.cpp`
  - `CRaspAmsiProvider::Scan()`
  - `CRaspAmsiProvider::CloseSession()`

- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
  - `WideToUtf8()`
  - `SwapRules()`
  - `Evaluate(...)`
  - `OnUnloadSignal()`

- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`
  - `ConnectSentry()`
  - `ParseRulesJson()`
  - `SendDetectionEvent()`
  - `Initialize()`
  - `Shutdown()`

- `src/rasp_sentry_native/src/pipe_security.cpp`
  - `MakeAuthenticatedUsersSecurity()`

- `src/rasp_sentry_native/src/event_collector.cpp`
  - `AppendLine()`
  - `ServerLoop()`

- `src/rasp_sentry_native/src/rule_server.cpp`
  - `GetAssembledJson()`
  - `GetAmsiRulesJson()`
  - `InlineGlobalLibraries()`
  - `InlineScriptFiles()`

### 10.2 后续重构

- 新增 `AmsiNormalizer`
- 新增 `AmsiSessionCache`
- 新增 `EventQueue`
- 新增规则 schema 校验模块
- 新增测试工程:
  - 单元测试
  - 集成测试
  - 回归样本测试
  - 并发测试
  - 性能测试

---

## 附加结论

本项目最需要纠正的一个认知是:

当前它不是"主动调用 AMSI API 扫 PowerShell 脚本"的普通扫描器，
而是"作为 AMSI Provider 被系统回调"的内联拦截模块。

这意味着它的工程要求更高:
- 宿主进程稳定性要极强
- 加载/卸载流程必须极谨慎
- 任何崩溃都可能直接打崩 PowerShell
- 任何阻塞都可能直接卡住业务进程

因此，当前最重要的不是继续加规则，而是先把:
- 生命周期
- 并发安全
- 失败策略
- IPC 权限
- 样本完整性

这五块补齐。