# Parent Process Path Gate Design

## 1. Current Stage

This document defines the design for adding parent-process-path based gate fields to AMSI rules.

Current request scope:

- Design only.
- Do not change production code in this step.
- Do not expose full parent process path to Lua or event JSON by default.
- Do not make parent path blocklist a standalone detection condition.

The intended behavior is:

```text
parent path gate passes
AND
existing regex / Lua detection matches
=>
rule reports audit/block according to rule mode
```

## 2. Goal

Add rule-level parent process path gating for AMSI rules.

The new fields constrain when an existing rule is applicable. They are not independent alert conditions.

Example use case:

```text
parentProcessPath = C:\a\b\asp businesee one\a.exe
parentPathBlockContains contains "asp businesee one"
body contains "amsiinitfailed"

=> gate passes and regex matches, so the rule may alert/block.
```

If the body does not match the rule regex/Lua logic, no alert is produced even when the parent path matches.

## 3. Proposed Rule Fields

Add two optional arrays at rule top level, next to fields such as `confidence`.
They must not be placed under `config`.

```json
{
  "confidence": 90,
  "parentPathAllowContains": [
    "trusted launcher.exe"
  ],
  "parentPathBlockContains": [
    "asp businesee one\\a.exe",
    "\\asp businesee one\\"
  ],
  "config": {
    "regexField": "body",
    "regexPatterns": [
      "(?i)(amsiinitfailed|amsicontext)",
      "(?i)(invoke-expression|\\biex\\b)\\s*[({\"']"
    ]
  }
}
```

### Field Semantics

| Field | Type | Match Type | Case Sensitivity | Meaning |
|---|---|---|---|---|
| `parentPathAllowContains` | string array | substring contains | case-insensitive | Exclusion list. If matched, skip the current rule. |
| `parentPathBlockContains` | string array | substring contains | case-insensitive | Gate list. If configured, at least one item must match before regex/Lua can run. |

Important:

- These fields are plain substring lists, not PCRE2 regex lists.
- Empty string entries must be ignored.
- Entries are not trimmed automatically. Rule authors must avoid leading/trailing spaces unless those spaces are intended to be part of the match string.
- Matching uses full `parentProcessPath`, not only basename.
- Matching is ASCII case-insensitive. Non-ASCII path characters are compared byte-for-byte after UTF-8 conversion.
- Before matching, normalize both `\` and `/` to `\` in the parent path and list entries.
- Full parent path should not be written to event JSON by default.

## 4. Final Decision Order

Gate skip is rule-local. Skipping a rule because of parent path allow/block logic must not stop the entire rule set evaluation; later rules must continue to be evaluated.

Trade-off: when any parent path gate field is configured and `parentProcessPath` is unavailable, this design skips the current rule. This intentionally favors lower false positives over detection coverage for that gated rule. The team must accept this behavior before implementation.

The final decision order is:

```text
1. No parentPathAllowContains and no parentPathBlockContains configured
   -> parent path gate is disabled
   -> keep existing regex / Lua detection behavior

2. At least one parent path condition configured, but parentProcessPath unavailable
   -> current rule is skipped
   -> do not run regex / Lua
   -> do not alert/block

3. parentProcessPath matches parentPathAllowContains
   -> current rule is skipped
   -> do not run regex / Lua
   -> do not alert/block

4. parentPathBlockContains is configured but does not match parentProcessPath
   -> current rule is skipped
   -> do not run regex / Lua
   -> do not alert/block

5. parentPathBlockContains is configured and matches parentProcessPath
   -> gate passes
   -> continue to existing regexPatterns / regexChecks / Lua evaluation

6. Existing regex / Lua detection matches
   -> rule reports according to rule mode: block / audit

7. Existing regex / Lua detection does not match
   -> no alert/block
```

This means:

- `parentPathAllowContains` is an exclusion list.
- `parentPathBlockContains` is an applicability gate.
- Actual detection still requires regex/Lua match.

## 5. Pseudocode

```cpp
bool ContainsAnyIgnoreCase(std::string_view haystack,
                           const std::vector<std::string>& needles)
{
    for (const std::string& needle : needles) {
        if (needle.empty())
            continue;
        if (ContainsIgnoreCase(haystack, needle))
            return true;
    }
    return false;
}

std::string NormalizePathForContains(std::string_view value)
{
    std::string normalized(value);
    std::replace(normalized.begin(), normalized.end(), '/', '\\');
    return normalized;
}

std::vector<std::string> NormalizeListForContains(const std::vector<std::string>& values)
{
    std::vector<std::string> normalized;
    normalized.reserve(values.size());
    for (const std::string& value : values) {
        if (!value.empty())
            normalized.push_back(NormalizePathForContains(value));
    }
    return normalized;
}

bool ParentPathGatePasses(const AmsiRaspRuleConfig& rule,
                          const ScanContext& scanContext)
{
    const bool hasAllow = !rule.parentPathAllowContains.empty();
    const bool hasBlock = !rule.parentPathBlockContains.empty();

    if (!hasAllow && !hasBlock)
        return true;

    const ProcessContextSnapshot* process = scanContext.process;
    if (!process || process->parentProcessPath.empty())
        return false;

    const std::string parentPath = NormalizePathForContains(process->parentProcessPath);

    if (ContainsAnyIgnoreCase(parentPath, NormalizeListForContains(rule.parentPathAllowContains)))
        return false;

    if (hasBlock)
        return ContainsAnyIgnoreCase(parentPath, NormalizeListForContains(rule.parentPathBlockContains));

    // Only allowlist configured: allowlist acts as exclusion; all other paths
    // continue with normal detection.
    return true;
}
```

## 6. Current Code Facts

Parent path is already captured but not exposed to rule context by default.

Current fields exist in:

- `src/rasp_mod_amsi/include/process_context_provider.h`
  - `ProcessContextSnapshot::parentProcessPath`
  - `ProcessContextSnapshot::parentProcessName`
  - `ProcessContextSnapshot::parentPid`

Current scan context setup:

- `src/rasp_mod_amsi/src/amsi_provider.cpp`
  - obtains `GetProcessContextProvider().GetSnapshot()`
  - sets `scanContext.process = &process`
  - currently sets `scanContext.emitProcessPathFields = false`

Current rule context injection:

- `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`
  - injects `parentPid`
  - injects `parentProcessName`
  - injects `processCaptureStatus`
  - does not inject `parentProcessPath`

This design intentionally uses `scanContext.process->parentProcessPath` inside C++ rule evaluation and does not require exposing the full path to Lua.

## 7. Code Change Plan

### 7.1 `src/rasp_mod_amsi/include/amsi_rule_engine.h`

Add fields to `AmsiRaspRuleConfig`:

```cpp
std::vector<std::string> parentPathAllowContains;
std::vector<std::string> parentPathBlockContains;
```

These fields are rule configuration only. They are not output fields.

### 7.2 `src/rasp_mod_amsi/src/amsi_rule_engine.cpp`

Update the target branch's real extension parser: `AmsiRuleEngine::ParseRuleExtension(...)`.

```cpp
else if (ckey == "parentPathAllowContains")
    p->read_string_array(rule.parentPathAllowContains);
else if (ckey == "parentPathBlockContains")
    p->read_string_array(rule.parentPathBlockContains);
```

Here `ckey` means the top-level rule key passed to `ParseRuleExtension(...)`, not a key inside `config`.
Inside `config`, these fields are ignored as unknown configuration.

Add helper functions near other AMSI rule evaluation helpers:

```cpp
bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle);
bool ContainsAnyIgnoreCase(std::string_view haystack,
                           const std::vector<std::string>& needles);
bool ParentPathGatePasses(const AmsiRaspRuleConfig& rule,
                          const ScanContext& scanContext);
```

Call the gate at the start of per-rule evaluation, before:

- `regexChecks`
- `regexPatterns`
- Lua `Run()`

Expected placement:

```cpp
if (!ParentPathGatePasses(rule, scanContext)) {
    continue;
}
```

The gate must not change:

- rule snapshot lifetime
- Lua engine behavior
- PCRE2 budget/limit behavior
- event JSON schema
- `RaspEvalResult` fields

## 8. Rule Examples

### 8.1 Gate + Regex Match Required

```json
{
  "id": "AMSI-PARENT-GATED-01",
  "sensor": "AmsiProvider",
  "enabled": true,
  "mode": "block",
  "description": "AMSI bypass only under selected parent paths",
  "confidence": 90,
  "parentPathAllowContains": [
    "trusted launcher.exe"
  ],
  "parentPathBlockContains": [
    "asp businesee one\\a.exe",
    "\\asp businesee one\\"
  ],
  "config": {
    "regexField": "body",
    "regexPatterns": [
      "(?i)(amsiinitfailed|amsicontext)",
      "(?i)(invoke-expression|\\biex\\b)\\s*[({\"']",
      "(?i)\\[ref\\]\\.assembly\\.gettype\\(",
      "(?i)amsi\\.dll.*virtualprotect"
    ]
  }
}
```

### 8.2 Allowlist-Only Exclusion

```json
{
  "id": "AMSI-ALLOWLIST-EXCLUDE-01",
  "sensor": "AmsiProvider",
  "enabled": true,
  "mode": "block",
  "description": "Existing regex rule with parent path exclusion",
  "confidence": 80,
  "parentPathAllowContains": [
    "trusted launcher.exe"
  ],
  "config": {
    "regexField": "body",
    "regexPatterns": [
      "(?i)amsiinitfailed"
    ]
  }
}
```

In this case:

- `trusted launcher.exe` skips the rule.
- Other parent paths continue normal regex detection.

## 9. Test Matrix

| Case | parentProcessPath | allow list | block list | body | Expected |
|---|---|---|---|---|---|
| No parent fields configured | any / empty | empty | empty | `amsiinitfailed` | Existing regex behavior, match |
| Parent path unavailable | empty | empty | `\asp businesee one\` | `amsiinitfailed` | Skip current rule; continue later rules |
| Allowlist match | `C:\trusted launcher.exe` | `trusted launcher.exe` | `\asp businesee one\` | `amsiinitfailed` | Skip current rule; continue later rules |
| Blocklist missing | `C:\Windows\System32\cmd.exe` | empty | `\asp businesee one\` | `amsiinitfailed` | Skip current rule; continue later rules |
| Blocklist match, regex miss | `C:\a\b\asp businesee one\a.exe` | empty | `\asp businesee one\` | `Write-Host ok` | No match |
| Blocklist match, regex match | `C:\a\b\asp businesee one\a.exe` | empty | `\asp businesee one\` | `amsiinitfailed` | Match, apply rule mode |
| Case-insensitive contains | `C:\A\B\ASP BUSINESEE ONE\A.EXE` | empty | `\asp businesee one\` | `amsiinitfailed` | Match, apply rule mode |
| Empty list entry | `C:\Windows\System32\cmd.exe` | empty | `""` | `amsiinitfailed` | Empty item ignored; skip if no non-empty block match |
| Allowlist-only exclusion miss | `C:\Windows\System32\cmd.exe` | `trusted launcher.exe` | empty | `amsiinitfailed` | Existing regex behavior, match |

## 10. Verification Plan

Minimum tests to add:

- Parser test: `parentPathAllowContains` and `parentPathBlockContains` arrays populate `AmsiRaspRuleConfig`.
- Gate test: allowlist match skips rule even when regex body matches.
- Gate test: blocklist miss skips rule even when regex body matches.
- Gate test: blocklist match plus regex match triggers result.
- Gate test: blocklist match plus regex miss does not trigger result.
- Gate test: parent path unavailable plus configured gate skips rule.
- Gate test: parent path skip is current-rule only; later rules still evaluate.
- Gate test: no parent path fields configured preserves existing rule behavior.
- Case-insensitive substring test.
- Slash normalization test: `/asp businesee one/` matches `\asp businesee one\`.

Suggested test file:

- `src/rasp_mod_amsi/tests/engine_runtime_tests.cpp`

## 11. Boundaries

This feature must not:

- Treat parent path blocklist as a standalone block condition.
- Emit full `parentProcessPath` to event JSON by default.
- Add parent path to Lua context by default.
- Convert contains lists into PCRE2 regex lists.
- Change global allow/block policy semantics.
- Change `ScanBudget`, Lua hook, or PCRE2 limit behavior.
- Add IPC or EDR dependency.

## 12. Open Questions

These are intentionally deferred:

- Whether full parent path should be emitted under an explicit debug flag.
- Whether Lua should later receive `parentProcessPath`.
- Whether future rules need regex-based parent path matching.
