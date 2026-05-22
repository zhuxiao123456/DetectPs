//
// Created by Codex on 2026/5/22.
//

#include "AmsiIpcRuntimeQueue.h"

#include <chrono>
#include <utility>

namespace Engine {

    BoundedPayloadQueue::BoundedPayloadQueue() = default;

    BoundedPayloadQueue::BoundedPayloadQueue(size_t capacity, size_t maxBytes)
        : capacity_(capacity), maxBytes_(maxBytes)
    {
    }

    void BoundedPayloadQueue::Reset(size_t capacity, size_t maxBytes)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        capacity_ = capacity;
        maxBytes_ = maxBytes;
        bytes_ = 0;
        stopped_ = false;
    }

    bool BoundedPayloadQueue::CanPushLocked(size_t itemBytes) const
    {
        if (capacity_ == 0 || maxBytes_ == 0) {
            return false;
        }
        if (queue_.size() >= capacity_) {
            return false;
        }
        if (itemBytes > maxBytes_) {
            return false;
        }
        return bytes_ + itemBytes <= maxBytes_;
    }

    bool BoundedPayloadQueue::Push(RuntimePayloadEnvelope item, uint32_t timeoutMs, bool waitWhenFull)
    {
        const size_t itemBytes = item.rawJson.size();
        std::unique_lock<std::mutex> lock(mutex_);
        if (stopped_) {
            return false;
        }

        if (!CanPushLocked(itemBytes)) {
            if (!waitWhenFull) {
                return false;
            }
            const auto timeout = std::chrono::milliseconds(timeoutMs);
            if (!notFull_.wait_for(lock, timeout, [this, itemBytes]() {
                    return stopped_ || CanPushLocked(itemBytes);
                })) {
                return false;
            }
            if (stopped_ || !CanPushLocked(itemBytes)) {
                return false;
            }
        }

        bytes_ += itemBytes;
        queue_.push_back(std::move(item));
        notEmpty_.notify_one();
        return true;
    }

    bool BoundedPayloadQueue::TryPush(RuntimePayloadEnvelope item)
    {
        return Push(std::move(item), 0, false);
    }

    bool BoundedPayloadQueue::Pop(RuntimePayloadEnvelope &out)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        notEmpty_.wait(lock, [this]() {
            return stopped_ || !queue_.empty();
        });

        if (queue_.empty()) {
            return false;
        }

        out = std::move(queue_.front());
        bytes_ -= out.rawJson.size();
        queue_.pop_front();
        notFull_.notify_one();
        return true;
    }

    void BoundedPayloadQueue::Stop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

    void BoundedPayloadQueue::StopAndDrop()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        queue_.clear();
        bytes_ = 0;
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

    void BoundedPayloadQueue::Clear()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        bytes_ = 0;
        notFull_.notify_all();
    }

    size_t BoundedPayloadQueue::Size() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    size_t BoundedPayloadQueue::Bytes() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return bytes_;
    }

} // namespace Engine
