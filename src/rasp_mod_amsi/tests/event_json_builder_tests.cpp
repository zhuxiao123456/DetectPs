#include "event_submit_client.h"

#include <iostream>
#include <map>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

EventJsonBuildInput BaseInput()
{
    EventJsonBuildInput input;
    input.eventId = "evt-fixed";
    input.timestamp = "2026-04-30T01:02:03.004Z";
    input.moduleName = "rasp_mod_amsi";
    input.ruleId = "rule-1";
    input.sensor = "AmsiProvider";
    input.block = true;
    input.severity = "Critical";
    input.description = "quote \" slash \\ newline\n tab\t";
    input.appName = "powershell.exe";
    input.contentName = "C:\\scripts\\demo.ps1";
    input.confidence = 91;
    input.ip = "127.0.0.1";
    input.ua = "unit-test";
    input.payload = "IEX \"payload\"\n中文";
    return input;
}

bool ParseFlatJsonObject(const std::string& json, std::map<std::string, std::string>& out)
{
    out.clear();
    size_t i = 0;
    auto skipWs = [&]() {
        while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n'))
            ++i;
    };
    auto readString = [&](std::string& s) {
        skipWs();
        if (i >= json.size() || json[i] != '"')
            return false;
        ++i;
        s.clear();
        while (i < json.size() && json[i] != '"') {
            if (json[i] == '\\') {
                ++i;
                if (i >= json.size())
                    return false;
                switch (json[i]) {
                case '"': s.push_back('"'); break;
                case '\\': s.push_back('\\'); break;
                case 'n': s.push_back('\n'); break;
                case 'r': s.push_back('\r'); break;
                case 't': s.push_back('\t'); break;
                default: s.push_back(json[i]); break;
                }
                ++i;
            } else {
                s.push_back(json[i++]);
            }
        }
        if (i >= json.size() || json[i] != '"')
            return false;
        ++i;
        return true;
    };

    skipWs();
    if (i >= json.size() || json[i++] != '{')
        return false;
    skipWs();
    while (i < json.size() && json[i] != '}') {
        std::string key;
        std::string value;
        if (!readString(key))
            return false;
        skipWs();
        if (i >= json.size() || json[i++] != ':')
            return false;
        if (!readString(value))
            return false;
        out[key] = value;
        skipWs();
        if (i < json.size() && json[i] == ',') {
            ++i;
            skipWs();
        }
    }
    return i < json.size() && json[i] == '}';
}

} // namespace

int main()
{
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        EventJsonBuildResult result = builder.BuildDetection(input);

        const std::string expected =
            "{\"id\":\"evt-fixed\","
            "\"ts\":\"2026-04-30T01:02:03.004Z\","
            "\"sev\":\"Critical\","
            "\"act\":\"block\","
            "\"cat\":\"Detection\","
            "\"mod\":\"rasp_mod_amsi\","
            "\"sensor\":\"AmsiProvider\","
            "\"rule\":\"rule-1\","
            "\"desc\":\"quote \\\" slash \\\\ newline\\n tab\\t\","
            "\"appName\":\"powershell.exe\","
            "\"contentName\":\"C:\\\\scripts\\\\demo.ps1\","
            "\"confidence\":\"91\","
            "\"ip\":\"127.0.0.1\","
            "\"ua\":\"unit-test\","
            "\"pattern\":\"IEX \\\"payload\\\"\\n中文\"}";

        if (!Expect(result.compactJson == expected, "raw JSON matches legacy field order and escaping"))
            return 1;
        if (!Expect(result.decision == "block", "block decision maps to legacy act"))
            return 1;
        if (!Expect(!result.eventTruncated, "short payload is not marked truncated"))
            return 1;

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "canonical JSON parses"))
            return 1;
        if (!Expect(fields["id"] == input.eventId, "canonical id matches"))
            return 1;
        if (!Expect(fields["sev"] == input.severity, "canonical severity matches"))
            return 1;
        if (!Expect(fields["pattern"] == input.payload, "canonical payload matches"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.block = false;
        input.severity.clear();
        input.confidence = 0;
        input.payload.clear();
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "default JSON parses"))
            return 1;
        if (!Expect(fields["act"] == "audit", "non-block decision maps to audit"))
            return 1;
        if (!Expect(fields["sev"] == "High", "empty severity preserves legacy High fallback"))
            return 1;
        if (!Expect(fields["confidence"] == "70", "zero confidence preserves legacy fallback"))
            return 1;
        if (!Expect(fields["pattern"].empty(), "empty payload preserves legacy empty pattern"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.description.assign(10 * 1024, 'D');
        input.payload = std::string("control-") + static_cast<char>(0x01);
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "control character JSON parses"))
            return 1;
        if (!Expect(fields["desc"].size() == 10 * 1024, "description is not truncated by legacy builder"))
            return 1;
        if (!Expect(result.compactJson.find("\\u0001") != std::string::npos,
                    "control characters preserve legacy unicode escape"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.payload.assign(9 * 1024, 'A');
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "truncated JSON parses"))
            return 1;
        if (!Expect(result.eventTruncated, "oversized payload is marked truncated"))
            return 1;
        if (!Expect(fields["pattern"].size() == 8 * 1024, "payload field is capped at legacy 8KB"))
            return 1;
        if (!Expect(fields["pattern"].find("...[Truncated]") != std::string::npos,
                    "payload truncation suffix is present"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        std::string prefix(8 * 1024 - std::string("...[Truncated]").size() - 1, 'A');
        input.payload = prefix + "\xF0\x9F\x98\x80" + std::string(128, 'Z');
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "emoji boundary JSON parses"))
            return 1;
        if (!Expect(fields["pattern"].size() == 8 * 1024 - 1,
                    "emoji crossing boundary is removed before truncation suffix"))
            return 1;
        if (!Expect(fields["pattern"].find("\xF0\x9F\x98\x80") == std::string::npos,
                    "truncated payload does not contain partial emoji"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        std::string prefix(8 * 1024 - std::string("...[Truncated]").size() - 2, 'A');
        input.payload = prefix + "\xE4\xB8\xAD" + std::string(128, 'Z');
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "Chinese boundary JSON parses"))
            return 1;
        if (!Expect(fields["pattern"].size() == 8 * 1024 - 2,
                    "Chinese character crossing boundary is removed before truncation suffix"))
            return 1;
        if (!Expect(fields["pattern"].find("\xE4\xB8\xAD") == std::string::npos,
                    "truncated payload does not contain partial Chinese character"))
            return 1;
    }

    return 0;
}
