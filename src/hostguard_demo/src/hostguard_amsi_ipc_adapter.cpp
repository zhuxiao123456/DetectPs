#include "hostguard_amsi_ipc_adapter.h"

#include <chrono>
#include <sstream>
#include <utility>

namespace hostguard_demo {
namespace {

std::string ExtractJsonString(const std::string& json, const char* name)
{
    // Minimal field extraction for event classification only; not a general JSON parser.
    const std::string key = std::string("\"") + name + "\"";
    const std::size_t keyPos = json.find(key);
    if (keyPos == std::string::npos) {
        return {};
    }
    const std::size_t colon = json.find(':', keyPos + key.size());
    if (colon == std::string::npos) {
        return {};
    }
    std::size_t quote = json.find('"', colon + 1);
    if (quote == std::string::npos) {
        return {};
    }
    std::string value;
    for (++quote; quote < json.size(); ++quote) {
        const char ch = json[quote];
        if (ch == '\\' && quote + 1 < json.size()) {
            value.push_back(json[++quote]);
            continue;
        }
        if (ch == '"') {
            break;
        }
        value.push_back(ch);
    }
    return value;
}

std::string NowString()
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

std::size_t EnvelopeBytes(const HostGuardAmsiEventEnvelope& envelope)
{
    return envelope.rawJson.size();
}

std::size_t StringBytes(const std::string& value)
{
    return value.size();
}

} // namespace

bool HostGuardRuleProvider::UpdateRules(std::string allRulesJson,
                                        std::string amsiRulesJson,
                                        std::string version,
                                        std::string hash,
                                        std::string& error)
{
    if (allRulesJson.empty() || amsiRulesJson.empty() || version.empty() || hash.empty()) {
        error = "rule snapshot fields must not be empty";
        return false;
    }

    auto snapshot = std::make_shared<HostGuardRuleSnapshot>();
    snapshot->allRulesJson = std::move(allRulesJson);
    snapshot->amsiRulesJson = std::move(amsiRulesJson);
    snapshot->version = std::move(version);
    snapshot->hash = std::move(hash);

    std::unique_lock<std::shared_mutex> lock(mutex_);
    snapshot_ = std::move(snapshot);
    return true;
}

bool HostGuardRuleProvider::BuildRulesResponse(const std::string& command,
                                               amsi_ipc::AmsiRuleResponse& out,
                                               std::string& error)
{
    std::shared_ptr<const HostGuardRuleSnapshot> snapshot;
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        snapshot = snapshot_;
    }

    if (!snapshot) {
        error = "RULES_NOT_READY";
        return false;
    }
    if (command == "GET_RULES" || command == "GET_RULES\n") {
        out.json = snapshot->amsiRulesJson;
        return true;
    }
    if (command == "GET_ALL_RULES" || command == "GET_ALL_RULES\n") {
        out.json = snapshot->allRulesJson;
        return true;
    }
    error = "UNSUPPORTED_COMMAND";
    return false;
}

std::string HostGuardRuleProvider::version() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return snapshot_ ? snapshot_->version : std::string();
}

std::string HostGuardRuleProvider::hash() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return snapshot_ ? snapshot_->hash : std::string();
}

AdapterDiagRingBuffer::AdapterDiagRingBuffer(std::size_t capacity)
    : capacity_(capacity)
{
}

void AdapterDiagRingBuffer::SetCapacity(std::size_t capacity)
{
    std::lock_guard<std::mutex> lock(mutex_);
    capacity_ = capacity;
    while (capacity_ > 0 && entries_.size() > capacity_) {
        entries_.pop_front();
        ++dropped_;
    }
}

void AdapterDiagRingBuffer::Add(std::string level, std::string component, std::string message)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (capacity_ == 0) {
        ++dropped_;
        return;
    }
    if (entries_.size() >= capacity_) {
        entries_.pop_front();
        ++dropped_;
    }
    entries_.push_back(HostGuardAmsiAdapterDiag{NowString(), std::move(level), std::move(component), std::move(message)});
}

std::vector<HostGuardAmsiAdapterDiag> AdapterDiagRingBuffer::Recent() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return std::vector<HostGuardAmsiAdapterDiag>(entries_.begin(), entries_.end());
}

std::uint64_t AdapterDiagRingBuffer::dropped() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return dropped_;
}

HostGuardAmsiEventEnvelope EventPipeClassifier::Classify(const std::string& rawJson)
{
    HostGuardAmsiEventEnvelope envelope;
    envelope.rawJson = rawJson;
    envelope.cat = ExtractJsonString(rawJson, "cat");
    envelope.sensor = ExtractJsonString(rawJson, "sensor");
    envelope.pattern = ExtractJsonString(rawJson, "pattern");
    envelope.broadcastId = ExtractJsonString(rawJson, "broadcastId");

    if (envelope.cat == "Detection") {
        envelope.kind = HostGuardAmsiMessageKind::Detection;
    } else if (envelope.cat == "drain-ack") {
        envelope.kind = HostGuardAmsiMessageKind::DrainAck;
    } else if (envelope.cat == "diag") {
        envelope.kind = HostGuardAmsiMessageKind::DiagnosticLog;
    } else if (envelope.sensor == "RaspLog") {
        envelope.kind = HostGuardAmsiMessageKind::DiagnosticLog;
    } else {
        envelope.kind = HostGuardAmsiMessageKind::Unknown;
    }
    return envelope;
}

bool BroadcastTracker::BeginBroadcast(const std::string& broadcastId,
                                      const std::string& command,
                                      std::uint32_t attempted,
                                      std::string& error)
{
    if (broadcastId.empty()) {
        error = "broadcastId must not be empty";
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (contexts_.find(broadcastId) != contexts_.end()) {
        error = "duplicate broadcastId";
        return false;
    }
    Context context;
    context.result.broadcastId = broadcastId;
    context.result.command = command;
    context.result.attempted = attempted;
    contexts_.emplace(broadcastId, std::move(context));
    return true;
}

void BroadcastTracker::OnAck(const std::string& broadcastId, const HostGuardAmsiAckInfo&)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contexts_.find(broadcastId);
    if (it != contexts_.end()) {
        ++it->second.result.acked;
    }
}

HostGuardAmsiBroadcastResult BroadcastTracker::WaitResult(const std::string& broadcastId,
                                                          std::uint32_t timeoutMs)
{
    const auto start = std::chrono::steady_clock::now();
    if (timeoutMs > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeoutMs));
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = contexts_.find(broadcastId);
    if (it == contexts_.end()) {
        HostGuardAmsiBroadcastResult result;
        result.broadcastId = broadcastId;
        result.error = "broadcast not found";
        return result;
    }
    it->second.completed = true;
    it->second.result.elapsedMs = static_cast<std::uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
    return it->second.result;
}

void BroadcastTracker::ExpireOldBroadcasts()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = contexts_.begin(); it != contexts_.end();) {
        if (it->second.completed) {
            it = contexts_.erase(it);
        } else {
            ++it;
        }
    }
}

HostGuardAmsiIpcAdapter::HostGuardAmsiIpcAdapter()
    : diag_(1024)
{
}

HostGuardAmsiIpcAdapter::~HostGuardAmsiIpcAdapter()
{
    Stop();
}

bool HostGuardAmsiIpcAdapter::Init(const HostGuardAmsiIpcConfig& config, std::string& error)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (status_.initialized) {
        error = "adapter already initialized";
        return false;
    }
    config_ = config;
    status_ = HostGuardAmsiIpcStatus{};
    status_.initialized = true;
    status_.productionPipes = config.useProductionPipes;
    status_.lifecycleState = "Initialized";
    diag_.SetCapacity(config.adapterDiagRingCapacity);
    detectionQueue_.Reset(config.detectionEventQueueCapacity, config.detectionEventQueueMaxBytes, EnvelopeBytes);
    dllLogQueue_.Reset(config.dllDiagnosticLogQueueCapacity, config.dllDiagnosticLogQueueMaxBytes, EnvelopeBytes);
    statusQueue_.Reset(config.statusQueueCapacity, config.statusQueueMaxBytes, StringBytes);
    return true;
}

bool HostGuardAmsiIpcAdapter::Start(std::string& error)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!status_.initialized) {
        error = "adapter not initialized";
        return false;
    }
    if (status_.started) {
        error = "adapter already started";
        return false;
    }
    status_.stopping = false;
    status_.started = true;
    status_.lifecycleState = "Running";
    detectionQueue_.Reset(config_.detectionEventQueueCapacity, config_.detectionEventQueueMaxBytes, EnvelopeBytes);
    dllLogQueue_.Reset(config_.dllDiagnosticLogQueueCapacity, config_.dllDiagnosticLogQueueMaxBytes, EnvelopeBytes);
    statusQueue_.Reset(config_.statusQueueCapacity, config_.statusQueueMaxBytes, StringBytes);
    detectionForwarder_ = std::thread(&HostGuardAmsiIpcAdapter::DetectionForwarder, this);
    dllLogForwarder_ = std::thread(&HostGuardAmsiIpcAdapter::DllDiagnosticLogForwarder, this);
    statusForwarder_ = std::thread(&HostGuardAmsiIpcAdapter::StatusForwarder, this);
    return true;
}

void HostGuardAmsiIpcAdapter::Stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!status_.initialized || !status_.started) {
            return;
        }
        status_.stopping = true;
        status_.started = false;
        status_.lifecycleState = "Stopped";
    }

    detectionQueue_.Close();
    dllLogQueue_.Close();
    statusQueue_.Close();

    if (detectionForwarder_.joinable()) {
        detectionForwarder_.join();
    }
    if (dllLogForwarder_.joinable()) {
        dllLogForwarder_.join();
    }
    if (statusForwarder_.joinable()) {
        statusForwarder_.join();
    }

    std::lock_guard<std::mutex> lock(mutex_);
    status_.stopping = false;
}

bool HostGuardAmsiIpcAdapter::UpdateRules(std::string allRulesJson,
                                          std::string amsiRulesJson,
                                          std::string version,
                                          std::string hash,
                                          std::string& error)
{
    if (!ruleProvider_.UpdateRules(std::move(allRulesJson), std::move(amsiRulesJson), std::move(version), std::move(hash), error)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    status_.lastRuleVersion = ruleProvider_.version();
    status_.lastRuleHash = ruleProvider_.hash();
    return true;
}

bool HostGuardAmsiIpcAdapter::SetDetectionEnabled(bool, std::string policyVersion, std::string&)
{
    std::lock_guard<std::mutex> lock(mutex_);
    status_.lastPolicyVersion = std::move(policyVersion);
    return true;
}

void HostGuardAmsiIpcAdapter::SetDetectionEventCallback(std::function<void(const HostGuardAmsiEventEnvelope&)> cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    detectionCallback_ = std::move(cb);
}

void HostGuardAmsiIpcAdapter::SetDllDiagnosticLogCallback(std::function<void(const HostGuardAmsiEventEnvelope&)> cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    dllLogCallback_ = std::move(cb);
}

void HostGuardAmsiIpcAdapter::SetStatusCallback(std::function<void(const std::string&)> cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    statusCallback_ = std::move(cb);
}

void HostGuardAmsiIpcAdapter::SetAdapterDiagCallback(std::function<void(const HostGuardAmsiAdapterDiag&)> cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    adapterDiagCallback_ = std::move(cb);
}

bool HostGuardAmsiIpcAdapter::InjectRawEventForTest(const std::string& rawJson)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!status_.started || status_.stopping) {
            return false;
        }
        ++status_.eventReceived;
    }

    auto envelope = EventPipeClassifier::Classify(rawJson);
    switch (envelope.kind) {
    case HostGuardAmsiMessageKind::Detection: {
        bool pushed = false;
        if (config_.detectionQueueFullPolicy == DetectionQueueFullPolicy::DropImmediately) {
            pushed = detectionQueue_.Push(envelope);
        } else if (config_.detectionQueueFullPolicy == DetectionQueueFullPolicy::BlockForever) {
            pushed = detectionQueue_.PushBlock(envelope);
        } else {
            pushed = detectionQueue_.PushWaitFor(envelope, config_.detectionEnqueueTimeoutMs);
        }
        bool dropped = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (pushed) {
                ++status_.detectionEventReceived;
            } else {
                ++status_.detectionEventDropped;
                status_.lastError = "detection event queue full";
                dropped = true;
            }
        }
        if (dropped) {
            AddDiag("warn", "adapter", "detection event dropped");
        }
        return pushed;
    }
    case HostGuardAmsiMessageKind::DiagnosticLog: {
        const bool pushed = dllLogQueue_.Push(envelope);
        bool dropped = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (pushed) {
                ++status_.dllDiagnosticLogReceived;
            } else {
                ++status_.dllDiagnosticLogDropped;
                dropped = true;
            }
        }
        if (dropped) {
            AddDiag("warn", "adapter", "DLL diagnostic log dropped");
        }
        return pushed || config_.dropDllDiagnosticLogOnQueueFull;
    }
    case HostGuardAmsiMessageKind::DrainAck:
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++status_.drainAckReceived;
            if (envelope.broadcastId.empty()) {
                ++status_.drainAckUncorrelated;
            } else {
                ++status_.drainAckCorrelated;
            }
        }
        return true;
    case HostGuardAmsiMessageKind::Unknown:
    default:
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++status_.unknownEventReceived;
            ++status_.unknownEventDropped;
        }
        return true;
    }
}

bool HostGuardAmsiIpcAdapter::InjectStatusForTest(const std::string& rawJson)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!status_.started || status_.stopping) {
            return false;
        }
    }
    bool pushed = false;
    if (config_.statusQueueFullPolicy == QueueFullPolicy::DropImmediately) {
        pushed = statusQueue_.Push(rawJson);
    } else if (config_.statusQueueFullPolicy == QueueFullPolicy::BlockForever) {
        pushed = statusQueue_.PushBlock(rawJson);
    } else {
        pushed = statusQueue_.PushWaitFor(rawJson, config_.statusEnqueueTimeoutMs);
    }
    bool dropped = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pushed) {
            ++status_.statusReceived;
        } else {
            ++status_.statusDropped;
            dropped = true;
        }
    }
    if (dropped) {
        AddDiag("warn", "adapter", "status payload dropped");
    }
    return pushed;
}

std::vector<HostGuardAmsiAdapterDiag> HostGuardAmsiIpcAdapter::GetRecentAdapterDiag() const
{
    return diag_.Recent();
}

HostGuardAmsiIpcStatus HostGuardAmsiIpcAdapter::GetStatus() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto status = status_;
    status.adapterDiagDropped = diag_.dropped();
    return status;
}

void HostGuardAmsiIpcAdapter::DetectionForwarder()
{
    HostGuardAmsiEventEnvelope envelope;
    while (detectionQueue_.Pop(envelope)) {
        std::function<void(const HostGuardAmsiEventEnvelope&)> cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = detectionCallback_;
        }
        if (cb) {
            cb(envelope);
        }
    }
}

void HostGuardAmsiIpcAdapter::DllDiagnosticLogForwarder()
{
    HostGuardAmsiEventEnvelope envelope;
    while (dllLogQueue_.Pop(envelope)) {
        std::function<void(const HostGuardAmsiEventEnvelope&)> cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = dllLogCallback_;
        }
        if (cb) {
            cb(envelope);
        }
    }
}

void HostGuardAmsiIpcAdapter::StatusForwarder()
{
    std::string payload;
    while (statusQueue_.Pop(payload)) {
        std::function<void(const std::string&)> cb;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cb = statusCallback_;
        }
        if (cb) {
            cb(payload);
        }
    }
}

void HostGuardAmsiIpcAdapter::AddDiag(const std::string& level,
                                      const std::string& component,
                                      const std::string& message)
{
    diag_.Add(level, component, message);
    std::function<void(const HostGuardAmsiAdapterDiag&)> cb;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cb = adapterDiagCallback_;
    }
    if (cb) {
        const auto recent = diag_.Recent();
        if (!recent.empty()) {
            cb(recent.back());
        }
    }
}

} // namespace hostguard_demo
