# AMSI Block/Alert Rule Group Optimization Plan

## Goal

After rules are parsed, build two execution index groups inside the active snapshot:

- `blockRuleIndexes`
- `alertRuleIndexes`

The rule JSON remains unchanged. The optimization changes evaluation order only.

## Fixed Semantics

1. Use rule indexes, not rule pointers.

```cpp
std::vector<size_t> blockRuleIndexes;
std::vector<size_t> alertRuleIndexes;
```

Indexes avoid pointer lifetime issues when snapshots are copied or rule vectors are moved.

2. Grouping is based on the rule's own effective mode.

```text
rule mode == block
    => blockRuleIndexes

other modes such as alert / monitor / audit / detect
    => alertRuleIndexes
```

`globalMode=audit` does not rebuild or change the groups. It only changes the action taken after a match.

3. In `globalMode=block`:

```text
Evaluate blockRuleIndexes first.

If a block rule matches and stopAfterFirstBlock=true:
    stop evaluation and do not evaluate alertRuleIndexes.

If no block rule matches:
    evaluate alertRuleIndexes.

Alert group results can only produce audit/alert events.
Alert group must never return block.
```

4. In `globalMode=audit`:

```text
Evaluate blockRuleIndexes as audit.
Then evaluate alertRuleIndexes as audit.

No rule can block.
auditMaxEventsPerScan applies across both groups.
```

## Perf Log

The perf log keeps the original aggregate fields and adds group-level counters:

```text
blockRulesVisited=xx
alertRulesVisited=xx
blockRegexCalls=xx
alertRegexCalls=xx
blockMatched=0/1
alertMatched=0/1
```

This makes it possible to verify whether the optimization reduces rule visits and regex calls in the block phase.

