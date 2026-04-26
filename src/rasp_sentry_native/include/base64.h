#pragma once
// base64.h — header-only base64 encode/decode, no external dependencies.
// Matches C# Convert.ToBase64String / Convert.FromBase64String semantics:
//   - Encoder produces standard alphabet with '=' padding.
//   - Decoder skips whitespace, stops at padding, returns empty vector on
//     any invalid character (mirrors the try/catch-empty pattern in C#).

#include <cstdint>
#include <string>
#include <vector>

inline std::string base64_encode(const uint8_t* data, size_t len)
{
    static const char kAlpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3)
    {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
        out += kAlpha[(n >> 18) & 0x3F];
        out += kAlpha[(n >> 12) & 0x3F];
        out += (i + 1 < len) ? kAlpha[(n >> 6) & 0x3F] : '=';
        out += (i + 2 < len) ? kAlpha[(n >> 0) & 0x3F] : '=';
    }
    return out;
}

inline std::string base64_encode(const std::vector<uint8_t>& v)
{
    return base64_encode(v.data(), v.size());
}

inline std::string base64_encode(const std::string& s)
{
    return base64_encode(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

inline std::vector<uint8_t> base64_decode(const std::string& input)
{
    // -1 = invalid, -2 = whitespace (skip), -3 = padding ('=')
    static const signed char kTbl[256] = {
        /* 0x00 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-2,-2,-1,-1,-2,-1,-1,
        /* 0x10 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0x20 */ -2,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        /* 0x30 */ 52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-3,-1,-1,
        /* 0x40 */ -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        /* 0x50 */ 15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        /* 0x60 */ -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        /* 0x70 */ 41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        /* 0x80 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0x90 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xA0 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xB0 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xC0 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xD0 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xE0 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        /* 0xF0 */ -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    std::vector<uint8_t> out;
    out.reserve((input.size() / 4) * 3 + 3);
    int val  = 0;
    int bits = -8;
    for (unsigned char c : input)
    {
        signed char d = kTbl[c];
        if (d == -2) continue;       // whitespace — skip
        if (d == -3) break;          // padding — stop
        if (d <   0) return {};      // invalid character
        val   = (val << 6) | d;
        bits += 6;
        if (bits >= 0)
        {
            out.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return out;
}

inline std::string base64_decode_str(const std::string& input)
{
    auto v = base64_decode(input);
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}
