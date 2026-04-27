#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>

class AmsiRuleEngine;

enum class EngineState {
    Uninitialized,
    Initializing,
    Ready,
    Reloading,
    Stopping,
    Inert,
    Stopped,
    Faulted
};

class EngineRuntime;

class ScanGuard {
public:
    ScanGuard() = default;
    ScanGuard(const ScanGuard&) = delete;
    ScanGuard& operator=(const ScanGuard&) = delete;

    ScanGuard(ScanGuard&& other) noexcept;
    ScanGuard& operator=(ScanGuard&& other) noexcept;
    ~ScanGuard();

    bool IsActive() const { return m_runtime != nullptr; }
    explicit operator bool() const { return IsActive(); }
    AmsiRuleEngine* Engine() const { return m_engine; }

private:
    friend class EngineRuntime;

    ScanGuard(EngineRuntime* runtime, AmsiRuleEngine* engine)
        : m_runtime(runtime), m_engine(engine) {}

    void Reset();

    EngineRuntime* m_runtime = nullptr;
    AmsiRuleEngine* m_engine = nullptr;
};

class EngineRuntime {
public:
    using EngineFactory = std::function<std::unique_ptr<AmsiRuleEngine>()>;
    using EngineInitializer = std::function<bool(AmsiRuleEngine&)>;

    EngineRuntime();
    EngineRuntime(EngineFactory factory, EngineInitializer initializer);
    ~EngineRuntime();

    EngineRuntime(const EngineRuntime&) = delete;
    EngineRuntime& operator=(const EngineRuntime&) = delete;

    bool EnsureInitialized();
    ScanGuard TryEnterScan();
    bool BeginShutdown(const char* reason, DWORD drainTimeoutMs);
    bool WaitForActiveScansToDrain(DWORD timeoutMs);
    void EnterInert(const char* reason);

    bool TryBeginReload();
    void EndReload(bool success);

    EngineState GetState() const;
    long ActiveScanCount() const { return m_activeScans.load(); }
    void Log(const char* fmt, ...) const;

private:
    friend class ScanGuard;

    void ReleaseScan();
    void SetStateLocked(EngineState next, const char* reason);
    AmsiRuleEngine* EngineLocked() const { return m_engine.get(); }

    mutable std::mutex m_mutex;
    std::condition_variable m_scanDrained;
    std::atomic<long> m_activeScans{0};
    EngineState m_state = EngineState::Uninitialized;
    std::unique_ptr<AmsiRuleEngine> m_engine;
    EngineFactory m_factory;
    EngineInitializer m_initializer;
};

EngineRuntime& GetAmsiEngineRuntime();
const char* EngineStateName(EngineState state);
