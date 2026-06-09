#include "../include/event_submit_client.h"

#include <cstdio>
#include <sstream>

namespace {

constexpr size_t kMaxEventPayloadFieldBytes = 8 * 1024;
constexpr const char* kTruncatedSuffix = "...[Truncated]";

std::string JsonEscape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char ch : value) {
        switch (ch) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (ch < 0x20) {
                char escaped[8];
                std::snprintf(escaped, sizeof(escaped), "\\u%04x", ch);
                out += escaped;
            } else {
                out.push_back(static_cast<char>(ch));
            }
            break;
        }
    }
    return out;
}

size_t Utf8SafePrefixLength(const std::string& value, size_t maxBytes)
{
    size_t i = 0;
    size_t last = 0;
    while (i < value.size() && i < maxBytes) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        size_t width = 1;
        if (ch < 0x80) {
            width = 1;
        } else if ((ch & 0xE0) == 0xC0) {
            width = 2;
        } else if ((ch & 0xF0) == 0xE0) {
            width = 3;
        } else if ((ch & 0xF8) == 0xF0) {
            width = 4;
        } else {
            ++i;
            last = i;
            continue;
        }

        if (i + width > value.size() || i + width > maxBytes)
            break;

        bool valid = true;
        for (size_t j = 1; j < width; ++j) {
            unsigned char next = static_cast<unsigned char>(value[i + j]);
            if ((next & 0xC0) != 0x80) {
                valid = false;
                break;
            }
        }

        if (!valid) {
            ++i;
            last = i;
            continue;
        }

        i += width;
        last = i;
    }
    return last;
}

std::string TruncateUtf8Field(const std::string& value, size_t maxBytes)
{
    const size_t suffixLen = std::char_traits<char>::length(kTruncatedSuffix);
    if (value.size() <= maxBytes)
        return value;
    if (maxBytes <= suffixLen)
        return std::string(kTruncatedSuffix, maxBytes);

    const size_t prefixLimit = maxBytes - suffixLen;
    const size_t prefixLen = Utf8SafePrefixLength(value, prefixLimit);
    std::string out = value.substr(0, prefixLen);
    out += kTruncatedSuffix;
    return out;
}

int NormalizeSeverity(int severity)
{
    if (severity < 0 || severity > 4)
        return 2;
    return severity;
}

} // namespace

EventJsonBuildResult EventJsonBuilder::BuildDetection(const EventJsonBuildInput& input) const
{
    EventJsonBuildResult result;
    result.decision = input.block ? "block" : "audit";
    result.payload = TruncateUtf8Field(input.payload, kMaxEventPayloadFieldBytes);
    const std::string scriptContent = TruncateUtf8Field(input.scriptContent, kMaxEventPayloadFieldBytes);
    result.eventTruncated = result.payload.size() != input.payload.size() || scriptContent.size() != input.scriptContent.size();

    const std::string confidence = input.confidence ? std::to_string(input.confidence) : "70";

    std::ostringstream oss;
    oss << "{\"act\":\"" << JsonEscape(result.decision) << "\","
        << "\"cat\":\"Detection\","
        << "\"rule\":\"" << JsonEscape(input.ruleId) << "\","
        << "\"desc\":\"" << JsonEscape(input.description) << "\","
        << "\"severity\":" << NormalizeSeverity(input.severity) << ","
        << "\"confidence\":\"" << JsonEscape(confidence) << "\","
        << "\"processPid\":\"" << input.processPid << "\","
        << "\"processName\":\"" << JsonEscape(input.processName) << "\","
        << "\"processPath\":\"" << JsonEscape(input.processPath) << "\","
        << "\"script_content\":\"" << JsonEscape(scriptContent) << "\","
        << "\"parentPid\":\"" << input.parentPid << "\","
        << "\"parentProcessName\":\"" << JsonEscape(input.parentProcessName) << "\","
        << "\"parentProcessPath\":\"" << JsonEscape(input.parentProcessPath) << "\"}";
    result.compactJson = oss.str();
    return result;
}
