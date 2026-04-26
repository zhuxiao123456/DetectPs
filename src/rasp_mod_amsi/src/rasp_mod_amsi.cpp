// =========================================================================
// rasp_mod_amsi.cpp — DLL entry, COM factory, DllRegisterServer/UnregisterServer
// 将当前的 DLL 设置成一个合法的反恶意软件提供者，并注入到 Windows 体系中
// =========================================================================

#define INITGUID
#include "../include/rasp_mod_amsi.h"
#include "../include/amsi_rule_engine.h"

#include <atomic>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

// ── Globals ───────────────────────────────────────────────────────────────

HINSTANCE g_hModule = nullptr;           // extern'd by amsi_rule_engine.cpp for FreeLibraryAndExitThread
AmsiRuleEngine *g_engine = nullptr;
std::atomic<bool> g_unloadInProgress{false};

/*
 * 在 Windows 注册表中创建（或打开）一个指定的子键，并向其中写入一个宽字符串（REG_SZ）类型的值
 * 在执行 DllRegisterServer() 时，将amsi探针的 COM CLSID 注册到操作系统的 HKEY_LOCAL_MACHINE 中，
 * 从而让 Windows Defender 和 PowerShell 能够发现并加载这个探针
 * hRoot: 注册表根键句柄（如 HKEY_LOCAL_MACHINE 或 HKEY_CURRENT_USER）。
 * subkey: 子键的相对路径（例如 Software\Microsoft\AMSI\Providers\...）。
 * valueName: 要设置的具体键值的名称。如果传入 NULL 或空字符串 ""，则修改该子键的**“(默认)”**值。
 * data: 要写入的实际字符串数据（UTF-16 宽字符指针 wchar_t*）。
*/
static HRESULT WriteRegistryString(HKEY hRoot, const wchar_t *subkey,
                                   const wchar_t *valueName, const wchar_t *data)
{
    // 1: 打开或创建注册表
    HKEY hKey = nullptr;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExW(hRoot, subkey, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, &disp);
    if (rc != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(rc);
    // 2: 写入字符串数据
    rc = RegSetValueExW(hKey, valueName, 0, REG_SZ,
                        (const BYTE *)data, (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return (rc == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(rc);
}

/*
    将 DLL 的 COM CLSID 注册到 Software\Classes\CLSID，并将其加入到 Windows AMSI 的提供者列表 Software\Microsoft\AMSI\Providers 中
    问题1：攻击者通过提权或使用未被监控的特权进程，直接删除 HKLM\Software\Microsoft\AMSI\Providers\[你的CLSID]，RASP 的 AMSI 防护将在此后所有新启动的 PowerShell 进程中彻底失效
*/
STDAPI DllRegisterServer()
{
    wchar_t dllPath[MAX_PATH] = {};
    wchar_t comKey[256];
    wchar_t clsidStr[64] = {};
    wchar_t amsiKey[256];
    HKEY hKey;

    GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);

    // CLSID string
    StringFromGUID2(CLSID_RaspAmsiProvider, clsidStr, 64);

    // COM InprocServer32
    OutputDebugStringA("[AMSI] Write to com interface\n");
    wsprintfW(comKey, L"Software\\Classes\\CLSID\\%s\\InprocServer32", clsidStr);
    HRESULT hr = WriteRegistryString(HKEY_LOCAL_MACHINE, comKey, nullptr, dllPath);
    if (FAILED(hr))
        return hr;
    hr = WriteRegistryString(HKEY_LOCAL_MACHINE, comKey, L"ThreadingModel", L"Both");
    if (FAILED(hr))
        return hr;

    // AMSI provider registration
    OutputDebugStringA("[AMSI] register amsi provider\n");
    wsprintfW(amsiKey, L"Software\\Microsoft\\AMSI\\Providers\\%s", clsidStr);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, amsiKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
    }

    OutputDebugStringA("[AMSI] Registration done...\n");
    return S_OK;
}

STDAPI DllUnregisterServer()
{
    wchar_t clsidStr[64] = {};
    StringFromGUID2(CLSID_RaspAmsiProvider, clsidStr, 64);

    wchar_t comKey[256];
    wsprintfW(comKey, L"Software\\Microsoft\\AMSI\\Providers\\%s", clsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, comKey);

    wsprintfW(comKey, L"Software\\Classes\\CLSID\\%s\\InprocServer32", clsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, comKey);

    wchar_t amsiKey[256];
    wsprintfW(amsiKey, L"Software\\Classes\\CLSID\\%s", clsidStr);
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, amsiKey);

    return S_OK;
}

// ── DllMain ───────────────────────────────────────────────────────────────
/*
功能：DLL 被加载（如 PowerShell.exe 启动并加载 AMSI Provider）或卸载时的初始化/清理工作。
流程与功能：在 DLL_PROCESS_ATTACH 时，实例化 g_engine = new AmsiRuleEngine(); 并调用 g_engine->Initialize();
问题: 不要在 DllMain 中执行复杂的初始化,g_engine->Initialize() 内部会启动多个后台线程（如 ConfigPipeThread, LogForwardThread）。
    这极易引发 OS Loader Lock 死锁。当 PowerShell 尝试加载这个 DLL 时，如果底层 IPC 管道发生阻塞，整个 PowerShell 进程将会在启动瞬间永久卡死
*/
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_hModule = hInst;
        DisableThreadLibraryCalls(hInst);

        // All configuration is pulled from rasp_sentry via IPC — no file path needed.
        g_engine = new AmsiRuleEngine();
        if (g_engine)
            g_engine->Initialize();
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        if (g_engine)
        {
            g_engine->Shutdown();
            delete g_engine;
            g_engine = nullptr;
        }
    }
    return TRUE;
}
