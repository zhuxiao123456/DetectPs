# Policy Detection Toggle Test Steps

This document records the manual verification steps for the Phase A policy
toggle implementation. The toggle uses the existing config pipe:

- `0x03` / `policy-off` / `pause`: pause detection in already loaded DLLs.
- `0x04` / `policy-on` / `resume`: resume detection in already loaded DLLs.

This phase does not include heartbeat, DLL instance counting, or per-DLL state
query. `status` only prints the host-side command record last requested by
`rasp_sentry.exe`; it is not per-DLL actual state.

## Build Artifacts

`rasp_sentry.exe`:

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\rasp_sentry.exe
```

`rasp_mod_amsi.dll`:

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\rasp_mod_amsi.dll
```

## 1. Start rasp_sentry

```powershell
cd D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release

.\rasp_sentry.exe `
  --log D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs `
  --rules D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\config\rasp_rules.json `
  --staging D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\staging
```

Expected console output:

```text
rasp_sentry_native running. Commands: status, reload, unload, policy-off, policy-on, quit
rasp_sentry>
```

## 2. Verify Detection Works Before Policy-Off

Start or use a target process that loads `rasp_mod_amsi.dll`, then trigger an
AMSI scan that should match the current rules.

Check recent event logs:

```powershell
Get-Content D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs\rasp-events-$(Get-Date -Format yyyy-MM-dd).jsonl -Tail 20
```

Expected result:

- Detection events are generated when rules match.
- This confirms the DLL and rules channel are working before the policy toggle.

## 3. Send Policy-Off

In the `rasp_sentry>` console:

```text
policy-off
```

Alias:

```text
pause
```

Expected output:

```text
policy-off: reached=1 lastError=0
```

`reached >= 1` means at least one loaded DLL instance received `0x03`.
`reached=0` usually means no DLL config pipe listener is currently available.

Check host-side status:

```text
status
```

Expected output:

```text
lastRequestedPolicyPaused: yes
note: host-side command record only; not per-DLL actual state
```

## 4. Verify Detection Is Paused

Using the same already-loaded target process, trigger the same AMSI scan again.

Check recent event logs:

```powershell
Get-Content D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs\rasp-events-$(Get-Date -Format yyyy-MM-dd).jsonl -Tail 20
```

Expected result:

- No new detection event is generated for the paused scan.
- The caller is not blocked.
- The DLL scan path returns the existing no-match result shape
  (`AMSI_RESULT_NOT_DETECTED`).

## 5. Send Policy-On

In the `rasp_sentry>` console:

```text
policy-on
```

Alias:

```text
resume
```

Expected output:

```text
policy-on: reached=1 lastError=0
```

Check host-side status:

```text
status
```

Expected output:

```text
lastRequestedPolicyPaused: no
note: host-side command record only; not per-DLL actual state
```

## 6. Verify Detection Resumes

Trigger the same AMSI scan again.

Check recent event logs:

```powershell
Get-Content D:\Code\rasp\DetectPsByAmsiCodex\src\hostguard_demo\logs\rasp-events-$(Get-Date -Format yyyy-MM-dd).jsonl -Tail 20
```

Expected result:

- Detection events are generated again when rules match.

## 7. Verify Reload Does Not Clear Pause State

In the `rasp_sentry>` console:

```text
policy-off
reload
```

Trigger the same AMSI scan again.

Expected result:

- `reload` still works.
- Detection remains paused after reload.
- No detection event is generated until `policy-on` is sent.

Resume detection:

```text
policy-on
```

## 8. Exit

In the `rasp_sentry>` console:

```text
quit
```

Ctrl+C can also stop `rasp_sentry.exe`.

## Troubleshooting

If `policy-off` or `policy-on` prints:

```text
reached=0
```

then no already-loaded DLL instance received the broadcast. Start or reuse a
target process that has loaded `rasp_mod_amsi.dll`, then send the command again.

In test environments where DLL unregister is not performed, manually send
`policy-off` after the target DLL has loaded. In the real EDR deployment,
policy disable is expected to unregister the DLL so newly started processes do
not enter the AMSI path.

## Automated Test Scope

Run the policy-toggle related unit checks:

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\amsi_config_broadcaster_tests.exe
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
```

Expected result:

- `amsi_config_broadcaster_tests` verifies the fixed signal byte values and
  no-listener behavior for reload, pause, and resume broadcasts.
- `engine_runtime_tests` verifies pause/resume scan gating, in-flight scan
  behavior, idempotency, and reload preserving pause state.

`amsi_ipc_host_adapter_tests.exe` is not a blocking policy-toggle acceptance
test in this phase. It currently fails earlier in the adapter suite when writing
to the event pipe:

```text
CreateFileW failed for pipe (GLE=5)
FAIL: event payload write succeeds
```

That failure occurs before any pause/resume broadcast assertion and should be
handled as a separate named-pipe ACL/token investigation.

## Manual Acceptance Record

Date: 2026-05-19

Scope:

- Real integration with `rasp_sentry.exe`.
- Loaded AMSI DLL receives `0x03` / `0x04` over the existing config pipe.
- No heartbeat, DLL counting, online view, or `GET_POLICY` mechanism included.

Observed acceptance:

- Detection works before `policy-off`.
- `policy-off` pauses detection for already loaded DLL instances.
- Paused scans return the existing no-match result path and do not emit
  detection events.
- `policy-on` resumes detection.
- `policy-off` followed by `reload` keeps detection paused.

Build artifacts used:

```text
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_sentry_native\build-codex\Release\rasp_sentry.exe
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\rasp_mod_amsi.dll
```
