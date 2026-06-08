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
//   4. Sends a fire-and-forget RaspEvent JSON line to rasp_sentry_events pipe.
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

// 声明，继承 IAntimalwareProvider，实现标准的 COM 进程内服务接口
class CRaspAmsiProviderFactory;

class CRaspAmsiProvider : public IAntimalwareProvider
{
public:
    CRaspAmsiProvider();
    ~CRaspAmsiProvider();

    // 标准的 COM 接口，用于对象生命周期管理和接口查询
    IFACEMETHODIMP         QueryInterface(_In_ REFIID riid, _Outptr_ void **ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // IAntimalwareProvider 核心接口
    IFACEMETHODIMP         Scan(IAmsiStream *stream, AMSI_RESULT *result) override;

    // AMSI 提供了一个逻辑上的“会话 (Session)”概念。当 PowerShell 执行一个被切割成碎片的脚本时，
    // 会将这些碎片带上相同的 session ID 传给杀毒软件。CloseSession 用于通知整个逻辑会话结束，用于清理内存。
    // Mark: 这是一个高危点。如果 Payload 被分成 10 块，每块都是一个无害的变量声明，这 10 块具有同一个 PowerShell 会话 ID。每一块传入都会触发 Scan，如果不做碎片化拼装，会造成漏报。
    void STDMETHODCALLTYPE CloseSession(ULONGLONG session) override;

    IFACEMETHODIMP         DisplayName(LPWSTR *displayName) override;

private:
    LONG _refCount;  // 通过 _refCount 维护对象的存活，当 PowerShell 引擎不再需要杀软时，Release() 降为 0，会自动 delete this
};
