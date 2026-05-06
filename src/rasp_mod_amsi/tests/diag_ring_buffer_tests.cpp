#include "diag_ring_buffer.h"

#include <iostream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

std::string Repeat(char ch, size_t count)
{
    return std::string(count, ch);
}

} // namespace

int main()
{
    {
        DiagRingBuffer buffer;
        if (!Expect(buffer.Capacity() == 256, "capacity matches legacy kLogQueueCap"))
            return 1;
        if (!Expect(buffer.SlotSize() == 1024, "slot size matches legacy LogEntry::text"))
            return 1;
        if (!Expect(buffer.Count() == 0, "new buffer is empty"))
            return 1;
    }

    {
        DiagRingBuffer buffer;
        buffer.Push("one");
        buffer.Push("two");
        if (!Expect(buffer.Count() == 2, "count increases before full"))
            return 1;

        std::string value;
        if (!Expect(buffer.Pop(value) && value == "one", "pop returns first item"))
            return 1;
        if (!Expect(buffer.Pop(value) && value == "two", "pop returns second item"))
            return 1;
        if (!Expect(!buffer.Pop(value), "pop on empty returns false"))
            return 1;
    }

    {
        DiagRingBuffer buffer;
        for (size_t i = 0; i < buffer.Capacity(); ++i)
            buffer.Push("old");
        buffer.Push("new");
        if (!Expect(buffer.Count() == buffer.Capacity(), "count never exceeds capacity"))
            return 1;

        std::string value;
        if (!Expect(buffer.Pop(value) && value == "old", "overflow evicts exactly one oldest item"))
            return 1;
        size_t remainingOld = 0;
        while (buffer.Pop(value)) {
            if (value == "old")
                ++remainingOld;
            if (value == "new")
                break;
        }
        if (!Expect(remainingOld == buffer.Capacity() - 2, "head/tail preserve order after overwrite"))
            return 1;
        if (!Expect(value == "new", "newest item is still present after overwrite"))
            return 1;
    }

    {
        DiagRingBuffer buffer;
        for (size_t i = 0; i < buffer.Capacity(); ++i)
            buffer.Push("item-" + std::to_string(i));
        buffer.Push("new");

        std::string value;
        if (!Expect(buffer.Pop(value) && value == "item-1",
                    "overflow evicts item-0 and first remaining item is item-1"))
            return 1;

        std::string last;
        do {
            last = value;
        } while (buffer.Pop(value));
        if (!Expect(last == "new", "last drained item after overflow is newest item"))
            return 1;
    }

    {
        DiagRingBuffer buffer;
        const std::string longText = Repeat('A', buffer.SlotSize() + 32);
        buffer.Push(longText);
        std::string value;
        if (!Expect(buffer.Pop(value), "long item can be popped"))
            return 1;
        if (!Expect(value.size() == buffer.SlotSize() - 1, "long item is truncated to slot minus nul"))
            return 1;
        if (!Expect(value == Repeat('A', buffer.SlotSize() - 1), "truncated content preserves prefix"))
            return 1;
    }

    {
        DiagRingBuffer buffer;
        buffer.Push("a");
        buffer.Push("b");
        buffer.Push("c");
        auto drained = buffer.Drain();
        if (!Expect(drained.size() == 3, "drain returns all entries"))
            return 1;
        if (!Expect(drained[0] == "a" && drained[1] == "b" && drained[2] == "c",
                    "drain preserves FIFO order"))
            return 1;
        if (!Expect(buffer.Count() == 0, "drain clears buffer"))
            return 1;
    }

    return 0;
}
