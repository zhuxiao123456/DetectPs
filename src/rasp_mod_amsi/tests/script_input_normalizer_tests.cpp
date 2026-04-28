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
        if (!Expect(out.normalized.size() <= 4096 + std::string("\n/*<rasp_truncated>*/\n").size(),
                    "normalized body stays within 4KB plus marker"))
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
        auto empty = normalizer.Normalize("", 0);
        if (!Expect(empty.normalized.empty(), "empty input is safe"))
            return 1;
        auto nullInput = normalizer.Normalize(nullptr, 10);
        if (!Expect(nullInput.normalized.empty(), "nullptr with length is safe"))
            return 1;
    }

    return 0;
}
