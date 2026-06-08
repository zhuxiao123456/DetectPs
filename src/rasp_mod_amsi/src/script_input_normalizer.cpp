#include "../include/script_input_normalizer.h"

#include <algorithm>
#include <bcrypt.h>
#include <cctype>
#include <cstring>
#include <vector>

namespace {

constexpr const char* kTruncatedMarker = "\n/*<rasp_truncated>*/\n";
constexpr const char* kDecodedMarker = "\n/*<decoded>*/\n";

std::string Hex(const unsigned char* data, size_t len)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = kHex[data[i] & 0x0F];
    }
    return out;
}

std::string Sha256Hex(const char* data, size_t len)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD cbData = 0;
    DWORD hashLen = 0;
    std::string result(64, '0');

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return result;
    if (BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen),
                          sizeof(hashLen), &cbData, 0) != 0 || hashLen == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return result;
    }

    std::vector<unsigned char> hashBytes(hashLen);
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0 &&
        BCryptHashData(hash,
                       reinterpret_cast<PUCHAR>(const_cast<char*>(data)),
                       static_cast<ULONG>(len), 0) == 0 &&
        BCryptFinishHash(hash, hashBytes.data(), hashLen, 0) == 0) {
        result = Hex(hashBytes.data(), hashBytes.size());
    }

    if (hash)
        BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return result;
}

bool IsPrintableAscii(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return uc == '\r' || uc == '\n' || uc == '\t' || (uc >= 0x20 && uc < 0x7F);
}

std::string WideToUtf8(const wchar_t* data, int chars)
{
    if (!data || chars <= 0)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, data, chars, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, data, chars, &out[0], len, nullptr, nullptr);
    return out;
}

bool LooksLikeUtf16Le(const char* data, size_t len)
{
    if (!data || len < 4 || (len % 2) != 0)
        return false;
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(data);
    if (len >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
        return true;

    size_t pairs = (std::min)(len / 2, static_cast<size_t>(128));
    size_t zeroHigh = 0;
    size_t printableLow = 0;
    for (size_t i = 0; i < pairs; ++i) {
        unsigned char low = bytes[i * 2];
        unsigned char high = bytes[i * 2 + 1];
        if (high == 0)
            ++zeroHigh;
        if (low == 0 || low == '\r' || low == '\n' || low == '\t' || (low >= 0x20 && low < 0x7F))
            ++printableLow;
    }
    return zeroHigh * 100 / pairs >= 60 && printableLow * 100 / pairs >= 70;
}

bool DecodeUtf16Le(const char* data, size_t len, std::string& out)
{
    if (!LooksLikeUtf16Le(data, len))
        return false;
    const unsigned char* bytes = reinterpret_cast<const unsigned char*>(data);
    size_t offset = (len >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) ? 2 : 0;
    if (((len - offset) % 2) != 0)
        return false;
    int chars = static_cast<int>((len - offset) / 2);
    out = WideToUtf8(reinterpret_cast<const wchar_t*>(data + offset), chars);
    return !out.empty();
}

std::string NormalizeControls(const char* data, size_t len, bool& hadNullBytes)
{
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        char c = data[i];
        if (c == '\0') {
            hadNullBytes = true;
            out.push_back(' ');
        } else if (IsPrintableAscii(c) || static_cast<unsigned char>(c) >= 0x80) {
            out.push_back(c);
        } else {
            out.push_back(' ');
        }
    }
    return out;
}

std::string ToLowerAscii(const std::string& input)
{
    std::string out = input;
    for (char& c : out)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

bool IsTokenChar(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    return std::isalnum(uc) || c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
}

bool ExtractEncodedCommandToken(const std::string& text, std::string& token)
{
    std::string lower = ToLowerAscii(text);
    size_t pos = lower.find("-encodedcommand");
    size_t keyLen = 15;
    if (pos == std::string::npos) {
        pos = lower.find("-enc");
        keyLen = 4;
    }
    if (pos == std::string::npos)
        return false;

    size_t i = pos + keyLen;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i])))
        ++i;
    if (i >= text.size())
        return false;

    char quote = 0;
    if (text[i] == '\'' || text[i] == '"')
        quote = text[i++];

    size_t start = i;
    if (quote) {
        while (i < text.size() && text[i] != quote)
            ++i;
    } else {
        while (i < text.size() && IsTokenChar(text[i]))
            ++i;
    }

    if (i <= start)
        return false;
    token = text.substr(start, i - start);
    return true;
}

int Base64Value(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool Base64Decode(const std::string& input, std::string& out)
{
    out.clear();
    int val = 0;
    int valb = -8;
    for (char c : input) {
        if (c == '=') break;
        int d = Base64Value(c);
        if (d < 0)
            return false;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return !out.empty();
}

std::string ApplyViewLimit(const std::string& input, size_t maxBytes, bool& truncated)
{
    if (maxBytes == 0) {
        truncated = !input.empty();
        return {};
    }
    if (input.size() <= maxBytes)
        return input;
    truncated = true;
    const size_t markerLen = strlen(kTruncatedMarker);
    if (maxBytes <= markerLen)
        return input.substr(0, maxBytes);

    const size_t payloadBudget = maxBytes - markerLen;
    const size_t prefixBytes = (payloadBudget * 3) / 4;
    const size_t suffixBytes = payloadBudget - prefixBytes;

    std::string out;
    out.reserve(maxBytes);
    out.append(input.data(), prefixBytes);
    out.append(kTruncatedMarker);
    out.append(input.data() + input.size() - suffixBytes, suffixBytes);
    return out;
}

} // namespace

const char* ScriptInputNormalizer::TruncatedMarker()
{
    return kTruncatedMarker;
}

NormalizedScriptInput ScriptInputNormalizer::Normalize(const char* sample, ULONG sampleLen) const
{
    return Normalize(sample, sampleLen, kMaxNormalizedBodyBytes);
}

NormalizedScriptInput ScriptInputNormalizer::Normalize(const char* sample,
                                                       ULONG sampleLen,
                                                       size_t maxNormalizedBodyBytes) const
{
    NormalizedScriptInput result;
    result.rawLen = sampleLen;

    if (!sample || sampleLen == 0) {
        result.normalizationReason = "empty";
        result.normalizedLen = 0;
        return result;
    }

    result.sampleHash = Sha256Hex(sample, sampleLen);

    std::string primary;
    if (DecodeUtf16Le(sample, sampleLen, primary)) {
        result.decodedUtf16Le = true;
        result.normalizationReason = "utf16le";
    } else {
        primary = NormalizeControls(sample, sampleLen, result.hadNullBytes);
        result.normalizationReason = result.hadNullBytes ? "raw_nulls_replaced" : "raw";
    }

    std::string token;
    if (ExtractEncodedCommandToken(primary, token)) {
        if (token.size() <= kMaxEncodedCommandTokenBytes) {
            std::string decodedBytes;
            if (Base64Decode(token, decodedBytes)) {
                std::string decodedText;
                bool decodedUtf16 = DecodeUtf16Le(decodedBytes.data(), decodedBytes.size(), decodedText);
                if (!decodedUtf16) {
                    bool ignoredNulls = false;
                    decodedText = NormalizeControls(decodedBytes.data(), decodedBytes.size(), ignoredNulls);
                }
                if (!decodedText.empty()) {
                    result.decodedBase64 = true;
                    result.decodedUtf16Le = result.decodedUtf16Le || decodedUtf16;
                    primary.append(kDecodedMarker);
                    primary.append(decodedText);
                    result.normalizationReason += "+encoded_command";
                }
            }
        } else {
            result.normalizationReason += "+encoded_command_too_large";
        }
    }

    result.normalized = ApplyViewLimit(primary, maxNormalizedBodyBytes, result.truncated);
    result.normalizedLen = result.normalized.size();
    return result;
}