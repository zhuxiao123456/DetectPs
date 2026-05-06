#pragma once

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

// Fixed-size diagnostic log ring buffer.
//
// This is only the data structure seam. It intentionally owns no locks, wake
// events, worker threads, platform handles, transports, or policy decisions.
// Entries are stored as null-terminated diagnostic text, not binary payloads.
class DiagRingBuffer {
public:
    static constexpr size_t kCapacity = 256;
    static constexpr size_t kSlotSize = 1024;

    size_t Capacity() const noexcept { return kCapacity; }
    size_t SlotSize() const noexcept { return kSlotSize; }
    size_t Count() const noexcept { return count_; }
    bool Empty() const noexcept { return count_ == 0; }

    void Push(std::string_view text)
    {
        if (count_ >= kCapacity) {
            tail_ = (tail_ + 1) % kCapacity;
        } else {
            ++count_;
        }

        CopyToSlot(entries_[head_], text);
        head_ = (head_ + 1) % kCapacity;
    }

    bool Pop(std::string& out)
    {
        if (count_ == 0)
            return false;

        out.assign(entries_[tail_].text.data());
        tail_ = (tail_ + 1) % kCapacity;
        --count_;
        return true;
    }

    std::vector<std::string> Drain()
    {
        std::vector<std::string> out;
        out.reserve(count_);
        std::string item;
        while (Pop(item))
            out.push_back(item);
        return out;
    }

    void Clear() noexcept
    {
        head_ = 0;
        tail_ = 0;
        count_ = 0;
        for (auto& entry : entries_)
            entry.text[0] = '\0';
    }

private:
    struct Entry {
        std::array<char, kSlotSize> text{};
    };

    static void CopyToSlot(Entry& entry, std::string_view text)
    {
        const size_t copyLen = std::min(text.size(), kSlotSize - 1);
        if (copyLen > 0)
            std::memcpy(entry.text.data(), text.data(), copyLen);
        entry.text[copyLen] = '\0';
    }

    std::array<Entry, kCapacity> entries_{};
    size_t head_ = 0;
    size_t tail_ = 0;
    size_t count_ = 0;
};
