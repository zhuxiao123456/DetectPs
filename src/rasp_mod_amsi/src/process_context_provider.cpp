#include "../include/process_context_provider.h"

#include <Windows.h>

#include <algorithm>
#include <array>

namespace {

constexpr uint32_t kMaxFailedAttempts = 3;
constexpr uint64_t kRetryBackoffMs[] = {1000, 5000, 30000};
constexpr uint32_t kErrorAccessDenied = 5;
constexpr uint32_t kErrorInvalidParameter = 87;

using NtQueryInformationProcessFn = LONG (WINAPI*)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

struct ProcessBasicInformationLite {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

ProcessContextSnapshot MakeSnapshot(ProcessCaptureStatus status)
{
    ProcessContextSnapshot snapshot;
    snapshot.status = status;
    return snapshot;
}

bool IsTerminalSnapshotStatus(ProcessCaptureStatus status)
{
    switch (status) {
    case ProcessCaptureStatus::Success:
    case ProcessCaptureStatus::ParentPidZero:
    case ProcessCaptureStatus::ParentSystem:
    case ProcessCaptureStatus::ParentOpenDenied:
    case ProcessCaptureStatus::ParentProcessExited:
    case ProcessCaptureStatus::ParentPathQueryFailed:
        return true;
    default:
        return false;
    }
}

std::string WideToUtf8(const std::wstring& value)
{
    if (value.empty())
        return {};

    int bytes = WideCharToMultiByte(CP_UTF8,
                                    0,
                                    value.c_str(),
                                    static_cast<int>(value.size()),
                                    nullptr,
                                    0,
                                    nullptr,
                                    nullptr);
    if (bytes <= 0)
        return {};

    std::string out(static_cast<size_t>(bytes), '\0');
    int written = WideCharToMultiByte(CP_UTF8,
                                      0,
                                      value.c_str(),
                                      static_cast<int>(value.size()),
                                      out.data(),
                                      bytes,
                                      nullptr,
                                      nullptr);
    if (written <= 0)
        return {};
    return out;
}

std::string BasenameFromPath(const std::string& path)
{
    const size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos)
        return path;
    if (slash + 1 >= path.size())
        return {};
    return path.substr(slash + 1);
}

bool FillCurrentProcess(IProcessContextPlatform& platform, ProcessContextSnapshot& snapshot)
{
    snapshot.currentPid = platform.GetCurrentPid();

    std::wstring path;
    uint32_t error = 0;
    if (!platform.GetCurrentProcessPath(path, error)) {
        snapshot.errorDomain = ProcessErrorDomain::Win32;
        snapshot.nativeError = error;
        snapshot.status = ProcessCaptureStatus::InternalError;
        return false;
    }

    snapshot.currentProcessPath = WideToUtf8(path);
    snapshot.currentProcessName = BasenameFromPath(snapshot.currentProcessPath);
    snapshot.valid = snapshot.currentPid != 0 && !snapshot.currentProcessName.empty();
    if (!snapshot.valid) {
        snapshot.status = ProcessCaptureStatus::InternalError;
        return false;
    }
    return true;
}

class DefaultProcessContextPlatform final : public IProcessContextPlatform {
public:
    uint32_t GetCurrentPid() override
    {
        return GetCurrentProcessId();
    }

    bool GetCurrentProcessPath(std::wstring& path, uint32_t& error) override
    {
        std::wstring buffer(32768, L'\0');
        DWORD len = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (len == 0) {
            error = GetLastError();
            path.clear();
            return false;
        }
        if (len >= buffer.size()) {
            error = ERROR_INSUFFICIENT_BUFFER;
            path.clear();
            return false;
        }
        error = 0;
        path.assign(buffer.data(), buffer.data() + len);
        return true;
    }

    ParentPidQueryResult QueryParentPid(uint32_t& pid, uint32_t& error) override
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) {
            error = GetLastError();
            pid = 0;
            return ParentPidQueryResult::NtdllUnavailable;
        }

        auto query = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!query) {
            error = GetLastError();
            pid = 0;
            return ParentPidQueryResult::SymbolUnavailable;
        }

        ProcessBasicInformationLite pbi = {};
        LONG status = query(GetCurrentProcess(),
                            0,
                            &pbi,
                            static_cast<ULONG>(sizeof(pbi)),
                            nullptr);
        if (status != 0) {
            error = static_cast<uint32_t>(status);
            pid = 0;
            return ParentPidQueryResult::QueryFailed;
        }

        error = 0;
        pid = static_cast<uint32_t>(pbi.InheritedFromUniqueProcessId);
        return ParentPidQueryResult::Success;
    }

    ProcessPathQueryResult QueryProcessPath(uint32_t pid, std::wstring& path, uint32_t& error) override
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) {
            error = GetLastError();
            path.clear();
            if (error == kErrorAccessDenied)
                return ProcessPathQueryResult::AccessDenied;
            if (error == kErrorInvalidParameter)
                return ProcessPathQueryResult::ProcessExited;
            return ProcessPathQueryResult::InternalError;
        }

        std::wstring buffer(32768, L'\0');
        DWORD size = static_cast<DWORD>(buffer.size());
        BOOL ok = QueryFullProcessImageNameW(process, 0, buffer.data(), &size);
        DWORD queryError = ok ? 0 : GetLastError();
        CloseHandle(process);

        if (!ok) {
            error = queryError;
            path.clear();
            return ProcessPathQueryResult::PathQueryFailed;
        }

        error = 0;
        path.assign(buffer.data(), buffer.data() + size);
        return ProcessPathQueryResult::Success;
    }

    uint64_t MonotonicTickMs() override
    {
        return GetTickCount64();
    }
};

} // namespace

const char* ProcessCaptureStatusToString(ProcessCaptureStatus status)
{
    switch (status) {
    case ProcessCaptureStatus::Uninitialized: return "uninitialized";
    case ProcessCaptureStatus::Initializing: return "initializing";
    case ProcessCaptureStatus::Success: return "success";
    case ProcessCaptureStatus::NtdllUnavailable: return "ntdll-unavailable";
    case ProcessCaptureStatus::NtQuerySymbolUnavailable: return "ntquery-symbol-unavailable";
    case ProcessCaptureStatus::PpidQueryFailed: return "ppid-query-failed";
    case ProcessCaptureStatus::ParentPidZero: return "parent-pid-zero";
    case ProcessCaptureStatus::ParentSystem: return "parent-system";
    case ProcessCaptureStatus::ParentOpenDenied: return "parent-open-denied";
    case ProcessCaptureStatus::ParentProcessExited: return "parent-process-exited";
    case ProcessCaptureStatus::ParentPathQueryFailed: return "parent-path-query-failed";
    case ProcessCaptureStatus::InternalError: return "internal-error";
    default: return "internal-error";
    }
}

const char* ProcessRetryStateToString(ProcessRetryState state)
{
    switch (state) {
    case ProcessRetryState::None: return "none";
    case ProcessRetryState::Pending: return "pending";
    case ProcessRetryState::Exhausted: return "exhausted";
    default: return "none";
    }
}

ProcessContextProvider::ProcessContextProvider(IProcessContextPlatform& platform)
    : platform_(platform),
      publishedSnapshot_(nullptr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    PublishSnapshotLocked(MakeSnapshot(ProcessCaptureStatus::Initializing));
}

std::shared_ptr<const ProcessContextSnapshot> ProcessContextProvider::GetSnapshot()
{
    auto current = std::atomic_load_explicit(&publishedSnapshot_, std::memory_order_acquire);
    if (current && current->valid &&
        (IsTerminalSnapshotStatus(current->status) ||
         current->retryState == ProcessRetryState::Exhausted))
        return current;

    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock())
        return current;

    current = std::atomic_load_explicit(&publishedSnapshot_, std::memory_order_acquire);
    if (current && current->valid &&
        (IsTerminalSnapshotStatus(current->status) ||
         current->retryState == ProcessRetryState::Exhausted))
        return current;

    const uint64_t now = platform_.MonotonicTickMs();
    if (!ShouldRetryLocked(now))
        return current;

    ProcessContextSnapshot initializing = current ? *current : MakeSnapshot(ProcessCaptureStatus::Uninitialized);
    initializing.status = ProcessCaptureStatus::Initializing;
    PublishSnapshotLocked(std::move(initializing));

    ProcessContextSnapshot captured = CaptureOnce();
    if (captured.valid && IsTerminalSnapshotStatus(captured.status)) {
        PublishSuccessLocked(captured);
    } else {
        PublishFailureLocked(captured, now);
    }

    return std::atomic_load_explicit(&publishedSnapshot_, std::memory_order_acquire);
}

size_t ProcessContextProvider::SnapshotCountForTesting() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshots_.size();
}

bool ProcessContextProvider::ShouldRetryLocked(uint64_t now) const
{
    if (failedAttempts_ >= kMaxFailedAttempts)
        return false;
    if (nextRetryTickMs_ == 0)
        return true;
    return now >= nextRetryTickMs_;
}

ProcessContextSnapshot ProcessContextProvider::CaptureOnce()
{
    ProcessContextSnapshot snapshot;
    if (!FillCurrentProcess(platform_, snapshot))
        return snapshot;

    uint32_t error = 0;
    ParentPidQueryResult parentPidResult = platform_.QueryParentPid(snapshot.parentPid, error);
    if (parentPidResult != ParentPidQueryResult::Success) {
        snapshot.nativeError = error;
        if (parentPidResult == ParentPidQueryResult::QueryFailed)
            snapshot.errorDomain = ProcessErrorDomain::NtStatus;
        else
            snapshot.errorDomain = ProcessErrorDomain::Win32;

        if (parentPidResult == ParentPidQueryResult::NtdllUnavailable)
            snapshot.status = ProcessCaptureStatus::NtdllUnavailable;
        else if (parentPidResult == ParentPidQueryResult::SymbolUnavailable)
            snapshot.status = ProcessCaptureStatus::NtQuerySymbolUnavailable;
        else
            snapshot.status = ProcessCaptureStatus::PpidQueryFailed;
        return snapshot;
    }

    if (snapshot.parentPid == 0) {
        snapshot.status = ProcessCaptureStatus::ParentPidZero;
        snapshot.parentResolved = false;
        return snapshot;
    }

    if (snapshot.parentPid == 4) {
        snapshot.parentProcessName = "System";
        snapshot.parentResolved = true;
        snapshot.status = ProcessCaptureStatus::ParentSystem;
        return snapshot;
    }

    std::wstring parentPath;
    ProcessPathQueryResult pathResult = platform_.QueryProcessPath(snapshot.parentPid, parentPath, error);
    if (pathResult != ProcessPathQueryResult::Success) {
        snapshot.errorDomain = ProcessErrorDomain::Win32;
        snapshot.nativeError = error;
        snapshot.parentResolved = false;
        if (pathResult == ProcessPathQueryResult::AccessDenied)
            snapshot.status = ProcessCaptureStatus::ParentOpenDenied;
        else if (pathResult == ProcessPathQueryResult::ProcessExited)
            snapshot.status = ProcessCaptureStatus::ParentProcessExited;
        else if (pathResult == ProcessPathQueryResult::PathQueryFailed)
            snapshot.status = ProcessCaptureStatus::ParentPathQueryFailed;
        else
            snapshot.status = ProcessCaptureStatus::InternalError;
        return snapshot;
    }

    snapshot.parentProcessPath = WideToUtf8(parentPath);
    snapshot.parentProcessName = BasenameFromPath(snapshot.parentProcessPath);
    if (snapshot.parentProcessName.empty()) {
        snapshot.status = ProcessCaptureStatus::ParentPathQueryFailed;
        snapshot.parentResolved = false;
        return snapshot;
    }

    snapshot.parentResolved = true;
    snapshot.status = ProcessCaptureStatus::Success;
    return snapshot;
}

void ProcessContextProvider::PublishFailureLocked(ProcessContextSnapshot snapshot, uint64_t now)
{
    ++failedAttempts_;
    if (failedAttempts_ >= kMaxFailedAttempts) {
        snapshot.retryState = ProcessRetryState::Exhausted;
        nextRetryTickMs_ = 0;
    } else {
        snapshot.retryState = ProcessRetryState::Pending;
        const size_t index = std::min<size_t>(failedAttempts_ - 1, std::size(kRetryBackoffMs) - 1);
        nextRetryTickMs_ = now + kRetryBackoffMs[index];
    }
    PublishSnapshotLocked(std::move(snapshot));
}

void ProcessContextProvider::PublishSuccessLocked(ProcessContextSnapshot snapshot)
{
    failedAttempts_ = 0;
    nextRetryTickMs_ = 0;
    snapshot.retryState = ProcessRetryState::None;
    snapshot.valid = snapshot.valid && !snapshot.currentProcessName.empty();
    PublishSnapshotLocked(std::move(snapshot));
}

void ProcessContextProvider::PublishSnapshotLocked(ProcessContextSnapshot snapshot)
{
    auto owned = std::make_shared<ProcessContextSnapshot>(std::move(snapshot));
    snapshots_.push_back(std::move(owned));
    std::shared_ptr<const ProcessContextSnapshot> published = snapshots_.back();
    constexpr size_t kMaxSnapshots = 4;
    while (snapshots_.size() > kMaxSnapshots) {
        snapshots_.erase(snapshots_.begin());
    }
    std::atomic_store_explicit(&publishedSnapshot_, published, std::memory_order_release);
}

IProcessContextPlatform& GetDefaultProcessContextPlatform()
{
    static DefaultProcessContextPlatform platform;
    return platform;
}

ProcessContextProvider& GetProcessContextProvider()
{
    static ProcessContextProvider provider(GetDefaultProcessContextPlatform());
    return provider;
}
