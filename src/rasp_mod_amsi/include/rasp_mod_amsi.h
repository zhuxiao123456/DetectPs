#pragma once
// =========================================================================
// rasp_mod_amsi.h — Windows AMSI Provider
//
// Implements IAntimalwareProvider (amsi.h) as a COM in-process server.
// Registered under HKLM\SOFTWARE\Microsoft\AMSI\Providers\{CLSID}.
//
// For every AMSI scan in any registered process:
//   1. Extracts content (script text, app name, content name) from IAmsiStream.
//   2. Evaluates AmsiProvider sensor rules in-process via amsi_rule_engine.
//   3. Returns AMSI_RESULT_DETECTED to block, AMSI_RESULT_NOT_DETECTED to allow.
//   4. Sends a fire-and-forget RaspEvent JSON line to amsi_detect_events pipe.
//
// CLSID:  {C0FFEE02-0000-0000-0000-000000000002}
//
// Build:  cmake -S . -B build -G "Visual Studio 17 2022" -A x64
//         cmake --build build --config Release
// Install: regsvr32 rasp_mod_amsi.dll
// =========================================================================

// #define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <amsi.h>
#include <unknwn.h>
// #include <objbase.h>

// {C0FFEE02-0000-0000-0000-000000000002}
DEFINE_GUID(CLSID_RaspAmsiProvider,
            0xC0FFEE02, 0x0000, 0x0000,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02);

// ── 继承自 IAntimalwareProvider，实现了标准的 COM 内存管理和业务接口 ───────────────────────────────────────────────────

class CRaspAmsiProviderFactory;

class CRaspAmsiProvider : public IAntimalwareProvider
{
public:
    CRaspAmsiProvider();
    ~CRaspAmsiProvider();

    // // 标准的 COM 引用计数生命周期管理
    IFACEMETHODIMP         QueryInterface(_In_ REFIID riid, _Outptr_ void **ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // IAntimalwareProvider
    IFACEMETHODIMP         Scan(IAmsiStream *stream, AMSI_RESULT *result) override;
    // AMSI 提供了一个高级特性叫“会话（Session）”。当 PowerShell 执行一个复杂的、分步骤加载的脚本时，
    // 会将这些请求打上相同的 session ID 发给杀毒软件。CloseSession 用于通知安全软件这个会话结束了，可以清理内存
    // Mark: 将一个高危的 Payload 拆分成 10 块，每块定义一个无害的变量，分 10 次在同一个 PowerShell 窗口里运行。每一次输入都会触发 Scan，但因为单看碎片毫无恶意，引擎会次次放行
    void STDMETHODCALLTYPE CloseSession(ULONGLONG session) override;
    IFACEMETHODIMP         DisplayName(LPWSTR *displayName) override;

private:
    LONG _refCount;  // 通过 _refCount 维护对象的存活，当 PowerShell 不再需要查杀服务时（Release() 返回 0），自动 delete this
};
