# Policy detection toggle design

Date: 2026-05-19

## 1. Goal

Implement a minimal policy switch that lets the host process pause or resume
detection in DLL instances that are already loaded.

This design intentionally does not modify `rasp_rules.json` and does not read
policy state from the rules file.

## 2. Important deployment assumption

In the real EDR program, when the policy is disabled, the EDR side also
unregisters the AMSI DLL, for example:

```text
regsvr32 /u **.dll
```

Therefore, newly started processes should no longer load or enter the AMSI DLL
path after policy disable.

Because of this deployment behavior, this phase only needs to notify DLL
instances that are already loaded. It does not need to solve initial policy
state for newly loaded DLL instances.

## 3. Explicit non-goals

This phase does not implement:

- reading policy from `rasp_rules.json`
- modifying rules schema
- `GET_POLICY`
- heartbeat
- DLL instance count
- online/stale/unloaded view
- paused/running statistics
- status reporting
- quota/admission/lease/slot control
- real-time process scanning

## 4. Control signals

Extend the existing config pipe signal bytes:

```text
0x01 = Reload
0x02 = Unload
0x03 = PauseDetection
0x04 = ResumeDetection
```

Semantics:

- `0x03 PauseDetection`: loaded DLL instances stop executing detection logic.
- `0x04 ResumeDetection`: loaded DLL instances resume executing detection
  logic.
- Pause is not unload.
- A paused DLL must keep the config pipe listener alive so it can receive
  `0x04`.

## 5. Host / sentry responsibilities

The host process owns the policy switch operation.

When policy is disabled:

```text
1. Host/EDR unregisters the DLL so new processes will not enter the AMSI path.
2. Host broadcasts 0x03 to already loaded DLL instances.
```

When policy is enabled:

```text
1. Host/EDR registers the DLL again if needed.
2. Host broadcasts 0x04 to already loaded DLL instances.
```

Suggested API additions:

```cpp
AmsiBroadcastResult BroadcastPauseDetection(int maxListeners, uint32_t timeoutMs);
AmsiBroadcastResult BroadcastResumeDetection(int maxListeners, uint32_t timeoutMs);
```

API contract follows the existing reload/unload broadcast behavior:

- `maxListeners` limits how many listener connections the broadcaster attempts
  to reach.
- `timeoutMs` follows the current `AmsiConfigBroadcaster` timeout semantics.
- A timeout may still produce a partial result.
- Callers must inspect `AmsiBroadcastResult`, especially reached count and error
  details, instead of treating the call as all-or-nothing success.
- This phase does not redefine the existing `AmsiBroadcastResult` structure.

If a CLI or command loop is present, recommended command names are:

```text
policy-off
policy-on
```

For `rasp_sentry.exe`, the console command loop should support:

```text
policy-off          -> BroadcastPauseDetection() / 0x03
policy-on           -> BroadcastResumeDetection() / 0x04
pause               -> alias for policy-off
resume              -> alias for policy-on
status              -> print host-side lastRequestedPolicyPaused state
reload              -> existing reload flow
unload              -> existing unload flow
quit / exit         -> stop rasp_sentry
```

`status` is a host-side command record only. It confirms what this
`rasp_sentry.exe` process last requested; it is not a DLL instance heartbeat and
does not prove every loaded DLL received the latest signal.

## 6. DLL responsibilities

Add runtime state:

```cpp
std::atomic<bool> m_detectionPaused{false};
```

Handle config pipe bytes:

```text
0x03 -> m_detectionPaused = true
0x04 -> m_detectionPaused = false
```

Scan hot path:

```cpp
if (m_detectionPaused.load(std::memory_order_relaxed)) {
    return NoMatch;
}
```

Return semantics:

- A paused scan returns the same result shape as "no rule matched".
- It must not return an explicit allow/block decision.
- It must not emit detection events.
- It must not execute Lua rules.

`NoMatch` is preferred over `Allow` because pause means "detection was skipped",
not "the content was evaluated and allowed".

If a future caller needs to distinguish paused scans from normal no-match, add a
dedicated internal status later. That is out of scope for this phase.

When paused:

- Do not execute Lua rules.
- Do not emit detection events.
- Do not block the caller.
- Keep reload working.
- Keep unload working.
- Keep the config pipe listener alive.

Concurrency boundary:

- Pause/resume is checked at the next `Scan()` entry.
- A scan that has already passed the pause check is allowed to finish.
- `0x03` does not interrupt an in-flight scan.
- With concurrent scan threads, each thread observes pause/resume independently
  at its next entry check.
- `memory_order_relaxed` is sufficient because this flag only controls a
  best-effort runtime gate and does not protect shared rule memory or object
  lifetime.

## 7. Reload behavior

Reload must not implicitly change the pause state.

Rules:

```text
0x01 Reload          -> reload rules only
0x03 PauseDetection  -> pause detection
0x04 ResumeDetection -> resume detection
```

This prevents a rule reload from accidentally re-enabling detection while the
policy is supposed to be disabled.

## 8. New process behavior

This phase does not synchronize policy state to newly loaded DLL instances.

Reason:

- In the real EDR deployment, policy disable also unregisters the DLL.
- New processes should not load the DLL or enter the AMSI path after unregister.

Known limitation if the unregister step is not performed:

- A newly loaded DLL that missed the previous `0x03` broadcast will default to
  detection enabled until it receives a later `0x03`.

This limitation is acceptable only because the real EDR program unregisters the
DLL on policy disable.

Testing note:

- In test environments where unregister is not performed, operators must
  manually broadcast `0x03` after target DLL instances are loaded to simulate the
  real deployment state.
- This phase can print the host-side requested pause state, but it does not
  query each loaded DLL instance for its current state.
- If a deployment cannot rely on unregister, the future `GET_POLICY` mechanism
  below should be implemented before treating pause as a global guarantee.

## 9. Failure behavior

Broadcast result is best effort, as with existing reload/unload behavior.

If some listeners are not reached:

- The host can report the `reached` count and error details using existing
  broadcast result handling.
- No heartbeat or online-instance accounting is introduced in this phase.
- The host should log signal type, listener limit, reached count, timeout, and
  last error.
- A small bounded retry is acceptable at the caller/policy layer if operationally
  needed, for example up to 3 attempts with a short delay.
- Retry must remain bounded and must not block the protected application path.
- Without heartbeat or online accounting, operators cannot prove every loaded
  DLL instance paused successfully; the operational guarantee comes from
  unregistering the DLL plus best-effort broadcast to already loaded instances.

Unknown config bytes should be ignored or logged at low frequency. They must
not change detection state.

## 10. Existing event and metrics impact

Pause period behavior:

- No detection event is emitted for skipped scans.
- Lua/rule execution metrics should not increment because rules are not
  executed.
- If a generic "scan entered" counter already exists above the pause check, it
  may still increment. This design does not require adding such a metric.
- Pause/resume control operations should be logged by the host as audit/control
  actions if the existing logging layer has such a channel.
- This phase does not add DLL status reports or paused/running dashboard
  counters.

## 11. Acceptance criteria

Hard acceptance:

- `PauseDetection` is encoded as `0x03`.
- `ResumeDetection` is encoded as `0x04`.
- Host can broadcast `0x03`.
- Host can broadcast `0x04`.
- DLL receiving `0x03` stops executing detection logic.
- DLL receiving `0x04` resumes detection logic.
- Reload does not clear or override paused state.
- Unload keeps existing behavior.
- Unknown config byte does not change pause state.
- Pause takes effect at the next scan entry and does not interrupt an in-flight
  scan.
- A paused scan returns `NoMatch` and does not emit detection events.

Out-of-scope acceptance:

- No validation of DLL count.
- No heartbeat validation.
- No online/stale/unloaded status validation.
- No new DLL initial-state synchronization.
- No rules-file policy validation.

## 12. Suggested implementation order

1. Extend `AmsiControlSignal`:

```cpp
Reload = 0x01
Unload = 0x02
PauseDetection = 0x03
ResumeDetection = 0x04
```

2. Add broadcaster helpers for `0x03 / 0x04`.
3. Add DLL config pipe handling for `0x03 / 0x04`.
4. Add `m_detectionPaused`.
5. Add `Scan()` short-circuit at the earliest safe point.
6. Add tests:
   - broadcaster sends `0x03`
   - broadcaster sends `0x04`
   - pause makes scan skip rule execution
   - resume restores scan execution
   - reload preserves pause state
   - unknown byte does not change pause state
   - pause received during an in-flight scan does not interrupt that scan
   - repeated pause-pause-resume is idempotent
   - pause followed by unload keeps unload behavior
   - reload while paused preserves pause state
   - broadcast timeout reports partial result through `AmsiBroadcastResult`

## 13. Future option, not in this phase

If a future deployment cannot rely on unregistering the DLL, then a separate
initial-state mechanism will be needed. One possible extension is:

```text
GET_POLICY -> {"detectionEnabled": false}
```

That future mechanism is explicitly out of scope for the current phase.
