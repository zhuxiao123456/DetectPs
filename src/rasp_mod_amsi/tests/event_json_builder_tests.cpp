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
    input.ruleId = "rule-1";
    input.sensor = "AmsiProvider";
    input.block = true;
    input.severity = 3;
    input.description = "quote \" slash \\ newline\n tab\t";
    input.confidence = 91;
    input.payload = "IEX \"payload\"\ntext";
    input.processPid = 4321;
    input.processName = "powershell.exe";
    input.processPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    input.scriptContent = "Get-Process";
    input.parentPid = 1234;
    input.parentProcessName = "cmd.exe";
    input.parentProcessPath = "C:\\Windows\\System32\\cmd.exe";
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
    auto readValue = [&](std::string& s) {
        skipWs();
        if (i < json.size() && json[i] == '"')
            return readString(s);
        s.clear();
        while (i < json.size() && json[i] != ',' && json[i] != '}')
            s.push_back(json[i++]);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
            s.pop_back();
        return !s.empty();
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
        if (!readValue(value))
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

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "detection JSON parses"))
            return 1;
        if (!Expect(fields.find("sev") == fields.end(), "detection event no longer emits string sev"))
            return 1;
        if (!Expect(fields["severity"] == "3", "severity is emitted as integer value"))
            return 1;
        if (!Expect(fields["act"] == "block", "block decision maps to act"))
            return 1;
        if (!Expect(fields["cat"] == "Detection", "category is Detection"))
            return 1;
        if (!Expect(fields["rule"] == input.ruleId, "rule id matches"))
            return 1;
        if (!Expect(fields["desc"] == input.description, "description round trips"))
            return 1;
        if (!Expect(fields["confidence"] == "91", "confidence matches"))
            return 1;
        if (!Expect(fields["processPid"] == "4321", "process pid matches"))
            return 1;
        if (!Expect(fields["processPath"] == input.processPath, "process path matches"))
            return 1;
        if (!Expect(fields["script_content"] == input.scriptContent, "script content matches"))
            return 1;
        if (!Expect(fields["parentPid"] == "1234", "parent pid matches"))
            return 1;
        if (!Expect(!result.eventTruncated, "short event is not truncated"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.block = false;
        input.severity = 0;
        input.confidence = 0;
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "zero severity JSON parses"))
            return 1;
        if (!Expect(fields["act"] == "audit", "non-block decision maps to audit"))
            return 1;
        if (!Expect(fields["severity"] == "0", "severity 0 is preserved"))
            return 1;
        if (!Expect(fields["confidence"] == "70", "zero confidence preserves fallback"))
            return 1;
    }

    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.payload.assign(9 * 1024, 'A');
        input.scriptContent.assign(9 * 1024, 'B');
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "truncated JSON parses"))
            return 1;
        if (!Expect(result.eventTruncated, "oversized fields are marked truncated"))
            return 1;
        if (!Expect(fields["script_content"].size() == 8 * 1024, "script content is capped at 8KB"))
            return 1;
        if (!Expect(fields["script_content"].find("...[Truncated]") != std::string::npos,
                    "script content truncation suffix is present"))
            return 1;
    }

    return 0;
}
