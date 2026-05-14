# v4 sentry-side Lua bytecode migration

## Scope

This document records the current migration of the v4 sentry-side Lua source-to-bytecode path into the current `codex` branch.

The migration is limited to `rasp_sentry_native`:

- `rasp_sentry.exe` reads Lua source files referenced by rule JSON.
- `rasp_sentry.exe` prepends `globalLibraries` source when a Lua script is present.
- `rasp_sentry.exe` compiles the combined Lua source with Lua 5.4.
- The assembled rule sent to the AMSI DLL carries:
  - `scriptBodyBase64`: base64 encoded Lua 5.4 bytecode.
  - `scriptEncoding`: `bytecode`.

This change does not implement:

- PCRE2 Layer B TLS resource reuse.
- thread-local Lua state cache.
- HostGuard prepared bundle format.
- EDR SDK integration.
- DLL-side rule execution semantics changes.

## Code Changes

### `src/rasp_sentry_native/CMakeLists.txt`

The sentry executable now builds and links a local static Lua 5.4 library:

- Enables C language in the project.
- Reuses vendored Lua source from `src/rasp_rule_engine/third_party/lua/src`.
- Builds `lua54_static_sentry`.
- Links `lua54_static_sentry` into `rasp_sentry`.

### `src/rasp_sentry_native/src/rule_server.cpp`

New sentry-side bytecode flow:

1. `InlineGlobalLibraries()` reads `globalLibraries` and emits `globalLibrariesBase64`.
2. `InlineScriptFiles()` reads each `script` file and emits source `scriptBodyBase64`.
3. `CompileAllRulesToBytecode()` compiles all source-backed Lua rules.
4. `PrependLibToRuleScript()` combines global lib source plus rule source before compilation.
5. `CompileToBytecode()` uses `luaL_loadbuffer()` and `lua_dump()`.
6. On successful compile, the rule is rewritten to `scriptEncoding = "bytecode"`.
7. On compile failure, the rule falls back to source payload and removes `scriptEncoding`.

`FilterAmsiProviderRules()` skips library prepending for rules that are already marked as bytecode.

## Rule Authoring

### Recommended source rule

Use `script` and do not set `scriptEncoding`.

```json
{
  "id": "AMSI-LUA-SOURCE-01",
  "sensor": "AmsiProvider",
  "enabled": true,
  "mode": "block",
  "description": "Lua source rule compiled by rasp_sentry.exe",
  "confidence": 90,
  "script": "rules/amsi_p01.lua"
}
```

Expected sentry log:

```text
Compiled =AMSI-LUA-SOURCE-01 to bytecode (...)
CompileAllRulesToBytecode: compiled=1 skipped=0
```

Expected DLL diagnostic log:

```text
PrecompileAll: rule=AMSI-LUA-SOURCE-01 scriptEncoding=bytecode accepted
```

### Direct bytecode rule

Use `scriptEncoding = "bytecode"` only when `scriptBodyBase64` already contains Lua 5.4 bytecode.

```json
{
  "id": "AMSI-LUA-BYTECODE-01",
  "sensor": "AmsiProvider",
  "enabled": true,
  "mode": "block",
  "description": "Precompiled bytecode rule",
  "confidence": 90,
  "scriptEncoding": "bytecode",
  "scriptBodyBase64": "<base64-of-lua54-bytecode>"
}
```

The bytecode must already include any helper/library semantics required by the rule. The DLL does not prepend `globalLibraries` to bytecode.

Do not combine `script` with `scriptEncoding = "bytecode"`.

## Validation

Build command:

```powershell
cmake --build src\rasp_sentry_native\build-codex --config Release --target rasp_sentry
```

Validated output:

```text
src\rasp_sentry_native\build-codex\Release\rasp_sentry.exe
```

Runtime checks:

```powershell
Select-String -Path C:\RaspSentry\rasp_logs\rasp-events-*.jsonl -Pattern "Compiled =|scriptEncoding=bytecode|PrecompileAll"
Select-String -Path C:\RaspSentry\rasp_logs\rasp-control-status-*.jsonl -Pattern "RULE_LOAD_RESULT|success|error"
```
