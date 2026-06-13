#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

enum class ProcessCaptureStatus : uint8_t {
    Uninitialized,
    Initializing,
    Success,
    NtdllUnavailable,
    NtQuerySymbolUnavailable,
    PpidQueryFailed,
    ParentPidZero,
    ParentSystem,
    ParentOpenDenied,
    ParentProcessExited,
    ParentPathQueryFailed,
    InternalError
};

enum class ProcessRetryState : uint8_t {
    None,
    Pending,
    Exhausted
};

enum class ProcessErrorDomain : uint8_t {
    None,
    Win32,
    NtStatus
};

enum class ParentPidQueryResult : uint8_t {
    Success,
    NtdllUnavailable,
    SymbolUnavailable,
    QueryFailed
};

enum class ProcessPathQueryResult : uint8_t {
    Success,
    AccessDenied,
    ProcessExited,
    PathQueryFailed,
    InternalError
};

const char* ProcessCaptureStatusToString(ProcessCaptureStatus status);
const char* ProcessRetryStateToString(ProcessRetryState state);

struct ProcessContextSnapshot {
    uint32_t currentPid = 0;
    std::string currentProcessName;
    std::string currentProcessPath;

    uint32_t parentPid = 0;
    std::string parentProcessName;
    std::string parentProcessPath;

    ProcessCaptureStatus status = ProcessCaptureStatus::Uninitialized;
    ProcessErrorDomain errorDomain = ProcessErrorDomain::None;
    uint32_t nativeError = 0;
    ProcessRetryState retryState = ProcessRetryState::None;

    bool valid = false;
    bool parentResolved = false;
};

class IProcessContextPlatform {
public:
    virtual ~IProcessContextPlatform() = default;

    virtual uint32_t GetCurrentPid() = 0;
    virtual bool GetCurrentProcessPath(std::wstring& path, uint32_t& error) = 0;
    virtual ParentPidQueryResult QueryParentPid(uint32_t& pid, uint32_t& error) = 0;
    virtual ProcessPathQueryResult QueryProcessPath(uint32_t pid, std::wstring& path, uint32_t& error) = 0;
    virtual uint64_t MonotonicTickMs() = 0;
};

class ProcessContextProvider {
public:
    explicit ProcessContextProvider(IProcessContextPlatform& platform);

    std::shared_ptr<const ProcessContextSnapshot> GetSnapshot();
    size_t SnapshotCountForTesting() const;

private:
    bool ShouldRetryLocked(uint64_t now) const;
    ProcessContextSnapshot CaptureOnce();
    void PublishSnapshotLocked(ProcessContextSnapshot snapshot);
    void PublishFailureLocked(ProcessContextSnapshot snapshot, uint64_t now);
    void PublishSuccessLocked(ProcessContextSnapshot snapshot);

    IProcessContextPlatform& platform_;
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<const ProcessContextSnapshot>> snapshots_;
    std::shared_ptr<const ProcessContextSnapshot> publishedSnapshot_;
    uint32_t failedAttempts_ = 0;
    uint64_t nextRetryTickMs_ = 0;
};

IProcessContextPlatform& GetDefaultProcessContextPlatform();
ProcessContextProvider& GetProcessContextProvider();
