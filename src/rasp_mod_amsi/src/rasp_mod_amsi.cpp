// =========================================================================
// rasp_mod_amsi.cpp - DLL entry and AMSI provider registration
// =========================================================================

#define INITGUID
#include "../include/rasp_mod_amsi.h"
#include "../include/amsi_rule_engine.h"

#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

HINSTANCE g_hModule = nullptr;

static HRESULT WriteRegistryString(HKEY hRoot, const wchar_t* subkey,
                                   const wchar_t* valueName, const wchar_t* data)
{
    HKEY hKey = nullptr;
    DWORD disp = 0;
    LONG rc = RegCreateKeyExW(hRoot, subkey, 0, nullptr,
                              REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                              &hKey, &disp);
    if (rc != ERROR_SUCCESS)
        return HRESULT_FROM_WIN32(rc);

    rc = RegSetValueExW(hKey, valueName, 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(data),
                        static_cast<DWORD>((wcslen(data) + 1) * sizeof(wchar_t)));
    RegCloseKey(hKey);
    return (rc == ERROR_SUCCESS) ? S_OK : HRESULT_FROM_WIN32(rc);
}

STDAPI DllRegisterServer()
{
    wchar_t dllPath[MAX_PATH] = {};
    wchar_t comKey[256];
    wchar_t clsidStr[64] = {};
    wchar_t amsiKey[256];
    HKEY hKey;

    GetModuleFileNameW(g_hModule, dllPath, MAX_PATH);

    StringFromGUID2(CLSID_RaspAmsiProvider, clsidStr, 64);

#ifdef _DEBUG
    OutputDebugStringA("[AMSI] Write to com interface\n");
#endif

    wsprintfW(comKey, L"Software\\Classes\\CLSID\\%s\\InprocServer32", clsidStr);
    HRESULT hr = WriteRegistryString(HKEY_LOCAL_MACHINE, comKey, nullptr, dllPath);
    if (FAILED(hr))
        return hr;

    hr = WriteRegistryString(HKEY_LOCAL_MACHINE, comKey, L"ThreadingModel", L"Both");
    if (FAILED(hr))
        return hr;

#ifdef _DEBUG
    OutputDebugStringA("[AMSI] register amsi provider\n");
#endif

    wsprintfW(amsiKey, L"Software\\Microsoft\\AMSI\\Providers\\%s", clsidStr);
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, amsiKey, 0, NULL, 0,
                        KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
    }

#ifdef _DEBUG
    OutputDebugStringA("[AMSI] Registration done...\n");
#endif

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
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, amsiKey);

    return S_OK;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = hInst;
        DisableThreadLibraryCalls(hInst);
    }
    return TRUE;
}
