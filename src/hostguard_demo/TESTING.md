# HostGuard Demo Testing Guide

This document records how to build and validate `hostguard_demo.exe`, including production pipe testing and real DLL integration.

## Build Outputs

Build directory:

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\build-hostguard-demo\Release
```

Main binaries:

```text
hostguard_demo.exe
hostguard_demo_pipe_client.exe
hostguard_demo_smoke_tests.exe
hostguard_demo_options_tests.exe
```

Roles:

- `hostguard_demo.exe`: standalone HostGuard-style IPC host.
- `hostguard_demo_pipe_client.exe`: minimal DLL substitute for rules/event/status pipe testing.
- `hostguard_demo_smoke_tests.exe`: automated `_demo` pipe smoke test.
- `hostguard_demo_options_tests.exe`: command-line parsing, explicit pipe mode, status ordering, and pipe client wire semantics test.

## Build

Run from:

```powershell
cd D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo
```

Configure:

```powershell
cmake -S . -B build-hostguard-demo -G "Visual Studio 17 2022" -A x64
```

Build:

```powershell
cmake --build build-hostguard-demo --config Release --target hostguard_demo
cmake --build build-hostguard-demo --config Release --target hostguard_demo_pipe_client
cmake --build build-hostguard-demo --config Release --target hostguard_demo_smoke_tests
cmake --build build-hostguard-demo --config Release --target hostguard_demo_options_tests
```

## Automated Tests

Run:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_options_tests.exe
.\build-hostguard-demo\Release\hostguard_demo_smoke_tests.exe
```

Expected result:

- Both commands exit with code `0`.
- `hostguard_demo_smoke_tests.exe` may print IPC startup logs.

## Production Pipe Manual Loop

Use this before real DLL testing. Do not run `rasp_sentry.exe` at the same time.

Start the demo:

```powershell
.\build-hostguard-demo\Release\hostguard_demo.exe .\config\rasp_rules.json .\logs\production-loop --production-pipes
```

In another PowerShell window, verify rules:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes rules GET_ALL_RULES
```

Write event and control status payloads:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes event '{"loopEvent":1}'
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes status '{"msgType":"RULE_LOAD_RESULT","loopStatus":1}'
```

Check logs:

```powershell
Get-Content .\logs\production-loop\rasp-events-YYYY-MM-DD.jsonl
Get-Content .\logs\production-loop\rasp-control-status-YYYY-MM-DD.jsonl
```

Expected payloads:

```json
{"loopEvent":1}
{"msgType":"RULE_LOAD_RESULT","loopStatus":1}
```

In the `hostguard_demo.exe` console, run:

```text
status
reload
unload
quit
```

`status` must show:

```text
strictHostGuardMode: yes
pipeMode: production
rulesPipeName: \\.\pipe\amsi_detect_rules
eventsPipeName: \\.\pipe\amsi_detect_events
controlStatusPipeName: \\.\pipe\amsi_detect_control_status
configPipeName: \\.\pipe\amsi_detect_config
```

No pipe name line should contain `_demo` in production mode.

## Real DLL Integration

### Preconditions

Before connecting the real DLL:

1. `rasp_sentry.exe` is not running.
2. `hostguard_demo.exe --production-pipes` starts successfully.
3. Production pipe manual loop passes:
   - `GET_RULES`
   - `GET_ALL_RULES`
   - event payload
   - control status payload
4. `reload` and `unload` can be executed repeatedly without hang or crash.
5. Log files are generated under the selected log directory:
   - `rasp-events-YYYY-MM-DD.jsonl`
   - `rasp-control-status-YYYY-MM-DD.jsonl`

### Start HostGuard Demo

```powershell
.\build-hostguard-demo\Release\hostguard_demo.exe .\config\rasp_rules.json .\logs\dll-loop --production-pipes
```

Run `status` and confirm:

```text
strictHostGuardMode: yes
pipeMode: production
```

Formal pipe names:

```text
\\.\pipe\amsi_detect_rules
\\.\pipe\amsi_detect_events
\\.\pipe\amsi_detect_control_status
\\.\pipe\amsi_detect_config
```

### Verify DLL Rule Pull

Load or start the DLL path that connects to the formal rules pipe.

The DLL should send:

```text
GET_RULES\n
```

to:

```text
\\.\pipe\amsi_detect_rules
```

`hostguard_demo.exe` returns AMSI rules from:

```text
.\config\rasp_rules.json
```

Only rules with:

```json
"sensor": "AmsiProvider"
```

are returned for `GET_RULES`.

Optional DLL substitute check:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES
```

Expected example:

```json
[{"action":"log","id":"hostguard-demo-amsi","sensor":"AmsiProvider"}]
```

### Verify Rule Update

Edit:

```powershell
.\config\rasp_rules.json
```

Example:

```json
{
  "rules": [
    {
      "id": "hostguard-demo-amsi-v2",
      "sensor": "AmsiProvider",
      "action": "log"
    }
  ]
}
```

In the demo console, run:

```text
reload
```

Expected behavior:

1. `hostguard_demo.exe` invalidates the provider cache.
2. `hostguard_demo.exe` broadcasts reload on the formal config pipe.
3. DLL receives reload.
4. DLL pulls rules again from the formal rules pipe.
5. New `GET_RULES` response contains `hostguard-demo-amsi-v2`.

Optional check:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES
```

### Verify Event Upload

Trigger DLL behavior that produces an AMSI detection event.

The DLL should write raw event payload to:

```text
\\.\pipe\amsi_detect_events
```

`hostguard_demo.exe` writes the payload unchanged to:

```text
.\logs\dll-loop\rasp-events-YYYY-MM-DD.jsonl
```

Check:

```powershell
Get-Content .\logs\dll-loop\rasp-events-YYYY-MM-DD.jsonl
```

The JSON should match the DLL payload exactly.

Optional DLL substitute:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes event '{"dllEventTest":1}'
```

Expected log line:

```json
{"dllEventTest":1}
```

### Verify Control Status Upload

The DLL should write control status payload to:

```text
\\.\pipe\amsi_detect_control_status
```

`hostguard_demo.exe` writes the payload unchanged to:

```text
.\logs\dll-loop\rasp-control-status-YYYY-MM-DD.jsonl
```

Check:

```powershell
Get-Content .\logs\dll-loop\rasp-control-status-YYYY-MM-DD.jsonl
```

Optional DLL substitute:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes status '{"msgType":"RULE_LOAD_RESULT","ok":true}'
```

Expected log line:

```json
{"msgType":"RULE_LOAD_RESULT","ok":true}
```

### Verify Unload

In the demo console, run:

```text
unload
```

Expected behavior:

- DLL receives unload through:

```text
\\.\pipe\amsi_detect_config
```

- DLL unloads or disables current rules/module logic.
- DLL may write a control status payload.
- `rasp-control-status-YYYY-MM-DD.jsonl` records the payload if DLL reports status.

### Exit

In the demo console:

```text
quit
```

Confirm no `hostguard_demo.exe` process remains:

```powershell
Get-Process hostguard_demo -ErrorAction SilentlyContinue
```

## Pass Criteria

DLL integration is considered passing when all of the following are true:

- DLL pulls rules from `\\.\pipe\amsi_detect_rules`.
- After editing `rasp_rules.json`, `reload` causes DLL to pull and load the updated rules.
- DLL event payload appears in `rasp-events-YYYY-MM-DD.jsonl`.
- DLL control status payload appears in `rasp-control-status-YYYY-MM-DD.jsonl`.
- `unload` is received by the DLL.
- `rasp_sentry.exe` is not running during the test.
- `status` shows `pipeMode: production` and `strictHostGuardMode: yes`.
- No production pipe name contains `_demo`.

## PowerShell JSON Quoting

When passing JSON to `hostguard_demo_pipe_client.exe` from PowerShell, prefer single quotes around JSON:

```powershell
.\build-hostguard-demo\Release\hostguard_demo_pipe_client.exe --production-pipes event '{"loopEvent":1}'
```

If double quotes are stripped by the shell, the log may show invalid JSON such as:

```text
{loopEvent:1}
```

That means the shell command was quoted incorrectly, not that the pipe modified the payload.
