//
// Created by z00840245 on 2026/5/22.
//

#include "AmsiIpcRuntimeQueue.h"

#include <chrono>
#include <utility>

namespace Engine {

    BoundedPayloadQueue::BoundedPayloadQueue() = default;

    /**
     * 重置队列状态。当引擎配置热更新、或者重启服务时使用。它会清空现有数据，重新设定边界，并将停止标志置为 false。
     * 该函数具有互斥锁保护，是线程安全的
     * @param capacity  新的元素个数上限
     * @param maxBytes  新的内存总字节数上限
     */
    void BoundedPayloadQueue::Reset(size_t capacity, size_t maxBytes)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        capacity_ = capacity;
        maxBytes_ = maxBytes;
        bytes_ = 0;
        stopped_ = false;
    }

    /**
     * 评估当前队列状态是否能放得下某个特定大小的新元素。
     * 注意：该函数由于带 Locked 后缀，内部不加锁，必须由调用者在持有 mutex_ 的安全区域内调用
     * @param itemBytes  准备入队的元素其 rawJson 的字节大小
     * @return  如果容量和内存都允许放入，返回 true；否则返回 false
     */
    bool BoundedPayloadQueue::CanPushLocked(size_t itemBytes) const
    {
        if (capacity_ == 0 || maxBytes_ == 0) {
            return false;  // 队列未配置
        }
        if (queue_.size() >= capacity_) {
            return false;  // 队列超限
        }
        if (itemBytes > maxBytes_) {
            return false;  // 单个新元素的体积超过了整个队列的最大限制 maxBytes_
        }
        return bytes_ <= maxBytes_ - itemBytes;
    }

    /**
     * 生产者接口: 数据入队
     * @param item 插入元素
     * @param timeoutMs  最大等待超时时间
     * @param waitWhenFull  队列满时是否等待
     * @return 可以插入返回true
     */
    bool BoundedPayloadQueue::Push(RuntimePayloadEnvelope &&item, uint32_t timeoutMs, bool waitWhenFull) {
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

    /**
     * 非阻塞、零等待式入队。等价于调用 Push(item, 0, false);
     * 多用于在严苛环境（如高频通信回调线程）中快速尝试投递数据，若失败则由上层逻辑直接执行 Dropped 计数
     * @param item 准备入队的数据
     * @return 成功返回 true，队列无剩余空间则直接返回 false
     */
    bool BoundedPayloadQueue::TryPush(RuntimePayloadEnvelope &&item) {
        return Push(std::move(item), 0, false);
    }

    /**
     * 消费者接口: 数据出队; 从队列头部取出一个数据对象。如果队列当前为空，消费者线程会通过条件变量 notEmpty_ 无限期阻塞挂起，
     * 直到有生产者 Push 了新数据并引发通知。当队列被 Stop 且无遗留数据时，会安全解除阻塞返回失败
     * @param out 传出参数（引用传递）
     * @return 成功获取数据返回 true；如果队列已被停止且队列中的残留数据已全部消费完毕，返回 false
     */
    bool BoundedPayloadQueue::Pop(RuntimePayloadEnvelope &out) {
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

    /**
     * 通知队列准备退出。将停止标志 stopped_ 置为 true，并通过 notify_all() 强行唤醒所有
     * 正卡在 Push 挂起或 Pop 挂起状态下的生产者和消费者线程。该函数允许消费者线程继续处理完队列中当前已经积压的残留数据
     */
    void BoundedPayloadQueue::Stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

    /**
     * 不仅设置停止标志并唤醒所有线程，还会瞬间清空 (clear()) 内部容器并将总字节计数归零。
     * 所有尚未被消费者消费的数据都会被直接丢弃，多用于引擎发生致命错误需要紧急退出或卸载模块的场景
     */
    void BoundedPayloadQueue::StopAndDrop() {
        std::lock_guard<std::mutex> lock(mutex_);
        stopped_ = true;
        queue_.clear();
        bytes_ = 0;
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

    /**
     * 在不停止队列运行状态的前提下，直接清空队列内的现有元素并重置内存计数器，
     * 同时通知正在因满额而挂起的生产者线程（notFull_.notify_all()）可以开始写数据
     */
    void BoundedPayloadQueue::Clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        bytes_ = 0;
        notFull_.notify_all();
    }

    /**
     * 获取当前队列中积压的元素总个数（线程安全）
     * @return 当前队列元素个数
     */
    size_t BoundedPayloadQueue::Size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

    /**
     * 获取当前队列中积压的所有 JSON 数据所占用的内存总字节数（线程安全）
     * @return 当前内存占用量（字节）
     */
    size_t BoundedPayloadQueue::Bytes() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return bytes_;
    }

} // namespace Engine

