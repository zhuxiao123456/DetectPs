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

class ReloadGuard {
public:
    ReloadGuard() = default;
    ReloadGuard(const ReloadGuard&) = delete;
    ReloadGuard& operator=(const ReloadGuard&) = delete;

    ReloadGuard(ReloadGuard&& other) noexcept;
    ReloadGuard& operator=(ReloadGuard&& other) noexcept = delete;
    ~ReloadGuard();

    bool IsActive() const { return m_runtime != nullptr; }
    explicit operator bool() const { return IsActive(); }
    void Complete(bool success, const char* detail = nullptr);

private:
    friend class EngineRuntime;

    ReloadGuard(EngineRuntime* runtime, const char* reason)
        : m_runtime(runtime), m_reason(reason) {}

    void Reset(bool success, const char* detail);

    EngineRuntime* m_runtime = nullptr;
    const char* m_reason = nullptr;
    bool m_completed = false;
};

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
    bool CanAttemptReload() const;
    ReloadGuard TryEnterReload(const char* reason);
    bool BeginShutdown(const char* reason, DWORD drainTimeoutMs);
    bool WaitForActiveScansToDrain(DWORD timeoutMs);
    void EnterInert(const char* reason);
    void EnterFaulted(const char* reason);
    void PauseDetection();
    void ResumeDetection();
    bool IsDetectionPaused() const;

    void EmitTelemetry(const char* event, const char* detail = nullptr) const;
    bool TryBeginReload();
    void EndReload(bool success);

    EngineState GetState() const;
    long ActiveScanCount() const { return m_activeScans.load(); }
    void Log(const char* fmt, ...) const;

private:
    friend class ScanGuard;
    friend class ReloadGuard;

    void ReleaseScan();
    void CompleteReload(bool success, const char* reason, const char* detail);
    void SetStateLocked(EngineState next, const char* reason);
    AmsiRuleEngine* EngineLocked() const { return m_engine.get(); }

    mutable std::mutex m_mutex;
    std::condition_variable m_scanDrained;
    std::atomic<long> m_activeScans{0};
    EngineState m_state = EngineState::Uninitialized;
    std::unique_ptr<AmsiRuleEngine> m_engine;
    EngineFactory m_factory;
    EngineInitializer m_initializer;
    std::atomic<bool> m_detectionPaused{false};
    std::atomic<DWORD> m_lastScanRejectTelemetryTick{0};
    std::atomic<uint64_t> m_suppressedScanRejectTelemetry{0};
};

EngineRuntime& GetAmsiEngineRuntime();
const char* EngineStateName(EngineState state);
