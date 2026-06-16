#include "../include/script_input_normalizer.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

std::string Utf16LeBytes(const std::wstring& text, bool bom)
{
    std::string out;
    if (bom) {
        out.push_back(static_cast<char>(0xFF));
        out.push_back(static_cast<char>(0xFE));
    }
    for (wchar_t ch : text) {
        unsigned v = static_cast<unsigned>(ch);
        out.push_back(static_cast<char>(v & 0xFF));
        out.push_back(static_cast<char>((v >> 8) & 0xFF));
    }
    return out;
}

std::string Repeat(char ch, size_t count)
{
    return std::string(count, ch);
}

bool IsValidUtf8(const std::string& value)
{
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    size_t i = 0;
    while (i < value.size()) {
        unsigned char c = bytes[i];
        if (c <= 0x7F) {
            ++i;
            continue;
        }

        size_t extra = 0;
        unsigned char minSecond = 0x80;
        unsigned char maxSecond = 0xBF;
        if (c >= 0xC2 && c <= 0xDF) {
            extra = 1;
        } else if (c == 0xE0) {
            extra = 2;
            minSecond = 0xA0;
        } else if (c >= 0xE1 && c <= 0xEC) {
            extra = 2;
        } else if (c == 0xED) {
            extra = 2;
            maxSecond = 0x9F;
        } else if (c >= 0xEE && c <= 0xEF) {
            extra = 2;
        } else if (c == 0xF0) {
            extra = 3;
            minSecond = 0x90;
        } else if (c >= 0xF1 && c <= 0xF3) {
            extra = 3;
        } else if (c == 0xF4) {
            extra = 3;
            maxSecond = 0x8F;
        } else {
            return false;
        }

        if (i + extra >= value.size())
            return false;
        if (bytes[i + 1] < minSecond || bytes[i + 1] > maxSecond)
            return false;
        for (size_t j = 2; j <= extra; ++j) {
            if ((bytes[i + j] & 0xC0) != 0x80)
                return false;
        }
        i += extra + 1;
    }
    return true;
}

} // namespace

int main()
{
    ScriptInputNormalizer normalizer;

    {
        std::string sample = "Write-Host hello";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(out.normalized == sample, "plain UTF-8 is preserved"))
            return 1;
        if (!Expect(out.sampleHash.size() == 64, "SHA-256 hash is hex encoded"))
            return 1;
    }

    {
        std::string sample = Utf16LeBytes(L"Write-Host utf16", true);
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(out.decodedUtf16Le, "UTF-16LE BOM is detected"))
            return 1;
        if (!Expect(out.normalized.find("Write-Host utf16") != std::string::npos,
                    "UTF-16LE BOM text is converted to UTF-8"))
            return 1;
    }

    {
        std::string sample = Utf16LeBytes(L"powershell -nop IEX", false);
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(out.decodedUtf16Le, "UTF-16LE without BOM is detected by heuristic"))
            return 1;
        if (!Expect(out.normalized.find("powershell -nop IEX") != std::string::npos,
                    "UTF-16LE without BOM is converted"))
            return 1;
    }

    {
        const char raw[] = {'I', 'E', 'X', '\0', 'D', 'o', 'w', 'n'};
        auto out = normalizer.Normalize(raw, static_cast<ULONG>(sizeof(raw)));
        if (!Expect(out.hadNullBytes, "NUL byte is recorded"))
            return 1;
        if (!Expect(out.normalized.find("IEX Down") != std::string::npos,
                    "non-UTF16 NUL is replaced with space"))
            return 1;
    }

    {
        std::string sample = "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGQAZQBjAG8AZABlAGQA";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(out.decodedBase64, "EncodedCommand token is decoded"))
            return 1;
        if (!Expect(out.normalized.find("Write-Host decoded") != std::string::npos,
                    "decoded UTF-16LE payload is visible in normalized body"))
            return 1;
        if (!Expect(out.normalized.find("VwByAGkA") != std::string::npos,
                    "original EncodedCommand text remains visible"))
            return 1;
    }

    {
        std::string sample = "powershell -EnC 'VwByAGkAdABlAC0ASABvAHMAdAAgAHEAdQBvAHQAZQBkAA=='";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(out.decodedBase64, "mixed-case -enc quoted token is decoded"))
            return 1;
        if (!Expect(out.normalized.find("Write-Host quoted") != std::string::npos,
                    "quoted EncodedCommand payload is visible"))
            return 1;
    }

    {
        std::string sample = "powershell -enc !!!!";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(!out.decodedBase64, "invalid base64 does not decode"))
            return 1;
    }

    {
        std::string sample = "powershell -enc " + Repeat('A', 8193);
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(!out.decodedBase64, "oversized EncodedCommand token is skipped"))
            return 1;
    }

    {
        std::string sample = Repeat('A', 5000) + "TAIL_IEX";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(out.truncated, "long raw sample is truncated"))
            return 1;
        if (!Expect(out.normalized.find("/*<rasp_truncated>*/") != std::string::npos,
                    "truncation marker is inserted"))
            return 1;
        if (!Expect(out.normalized.find("TAIL_IEX") != std::string::npos,
                    "suffix is preserved after truncation"))
            return 1;
        if (!Expect(out.normalized.size() <= 4096,
                    "normalized body stays within 4KB including marker"))
            return 1;
    }

    {
        std::string sample = Repeat('A', 7000) + "TAIL_DYNAMIC_LIMIT";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()), 8192);
        if (!Expect(!out.truncated, "custom 8KB limit keeps 7KB sample intact"))
            return 1;
        if (!Expect(out.normalized.find("TAIL_DYNAMIC_LIMIT") != std::string::npos,
                    "custom limit preserves tail without truncation"))
            return 1;
    }

    {
        std::string sample = Repeat('B', 9000) + "TAIL_DYNAMIC_LIMIT";
        auto out = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()), 8192);
        if (!Expect(out.truncated, "custom 8KB limit truncates larger sample"))
            return 1;
        if (!Expect(out.normalized.find("TAIL_DYNAMIC_LIMIT") != std::string::npos,
                    "custom limit still preserves suffix"))
            return 1;
        if (!Expect(out.normalized.size() <= 8192,
                    "custom limit bounds normalized body including marker"))
            return 1;
    }

    {
        std::string marker = ScriptInputNormalizer::TruncatedMarker();
        if (!Expect(marker.find("invoke") == std::string::npos &&
                    marker.find("iex") == std::string::npos &&
                    marker.find("encoded") == std::string::npos &&
                    marker.find("command") == std::string::npos &&
                    marker.find("powershell") == std::string::npos,
                    "truncation marker avoids high-risk keywords"))
            return 1;
    }

    {
        std::string sample = "stable hash";
        auto a = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        auto b = normalizer.Normalize(sample.data(), static_cast<ULONG>(sample.size()));
        if (!Expect(a.sampleHash == b.sampleHash, "sampleHash is stable for same raw input"))
            return 1;
    }

    {
        const char raw[] = {
            'A', static_cast<char>(0xC0), static_cast<char>(0xAF), ' ',
            't', 'e', 's', 't', ' ',
            'a', 'm', 's', 'i', 'u', 't', 'i', 'l', 's', 'z', 'x', 'c',
            ' ', static_cast<char>(0xE4), static_cast<char>(0xB8)
        };
        auto out = normalizer.Normalize(raw, static_cast<ULONG>(sizeof(raw)));
        if (!Expect(IsValidUtf8(out.normalized), "invalid raw bytes are repaired to valid UTF-8"))
            return 1;
        if (!Expect(out.normalized.find("test amsiutilszxc") != std::string::npos,
                    "ASCII detection text remains visible after UTF-8 repair"))
            return 1;
    }

    {
        const char raw[] = {
            static_cast<char>(0xE6), static_cast<char>(0xB5), static_cast<char>(0x8B),
            static_cast<char>(0xE8), static_cast<char>(0xAF), static_cast<char>(0x95),
            ' ', 'I', 'E', 'X'
        };
        auto out = normalizer.Normalize(raw, static_cast<ULONG>(sizeof(raw)));
        if (!Expect(IsValidUtf8(out.normalized), "valid UTF-8 input remains valid"))
            return 1;
        if (!Expect(out.normalized == std::string(raw, sizeof(raw)),
                    "valid UTF-8 non-ASCII bytes are preserved"))
            return 1;
    }

    {
        auto empty = normalizer.Normalize("", 0);
        if (!Expect(empty.normalized.empty(), "empty input is safe"))
            return 1;
        auto nullInput = normalizer.Normalize(nullptr, 10);
        if (!Expect(nullInput.normalized.empty(), "nullptr with length is safe"))
            return 1;
    }

    return 0;
}
