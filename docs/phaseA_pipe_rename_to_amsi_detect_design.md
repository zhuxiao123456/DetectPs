# Phase A Pipe Rename to amsi_detect Design

Date: 2026-05-13

## Goal

Replace the production named pipe surface with `amsi_detect_*` names and remove
runtime dependency on the old `rasp_sentry_*` pipe names.

Final production pipes:

| Pipe | Direction | Purpose |
|---|---|---|
| `\\.\pipe\amsi_detect_rules` | DLL -> EXE | Fetch current rule response |
| `\\.\pipe\amsi_detect_config` | EXE -> DLL | Broadcast reload `0x01` and unload `0x02` |
| `\\.\pipe\amsi_detect_events` | DLL -> EXE | DetectionEvent, DiagLog, drain-ack |
| `\\.\pipe\amsi_detect_control_status` | DLL -> EXE | RULE_LOAD_RESULT |

## Non-goals

1. No dual-stack fallback to `rasp_sentry_*`.
2. No payload schema change.
3. No prepared bundle implementation.
4. No HostGuard / EDR SDK integration.
5. No reload/unload protocol change; config remains one-byte control.
6. No AsyncEventQueue behavior change.

## File-level changes

| Area | Old pipe | New pipe | Files |
|---|---|---|---|
| Rules | `rasp_sentry_rules` | `amsi_detect_rules` | `RaspSentryBase::ConnectSentry`, `RuleServer` |
| Config | `rasp_sentry_config` | `amsi_detect_config` | `ConfigPipeThreadProc`, `ConfigWatcher`, `AmsiStagingWatcher` |
| Events | `rasp_sentry_events` | `amsi_detect_events` | `LegacyPipeEventTransport`, `LegacyDiagPipeWriter`, `EventCollector`, drain-ack |
| Status | N/A | `amsi_detect_control_status` | unchanged |

## Compatibility decision

This batch intentionally removes old pipe names from production source. Existing
PowerShell instances that loaded an older DLL must be restarted to receive
reload/unload on `amsi_detect_config`. Test machines must deploy the matching
DLL and EXE together.

## Static gate

`scripts/check_amsi_detect_pipe_names.ps1` fails if production source contains:

- `rasp_sentry_rules`
- `rasp_sentry_config`
- `rasp_sentry_events`
- `\\.\pipe\rasp_sentry_rules`
- `\\.\pipe\rasp_sentry_config`
- `\\.\pipe\rasp_sentry_events`

Build directories are excluded from the scan.

## Acceptance

1. Production source contains no old `rasp_sentry_rules/config/events` pipe names.
2. `rasp_mod_amsi.dll` Release build succeeds.
3. `rasp_sentry.exe` Release build succeeds.
4. Pipe rename static gate passes.
5. Existing parser/event transport/runtime tests pass.
