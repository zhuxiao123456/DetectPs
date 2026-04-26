/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#ifndef RASP_RULE_BASE_H
#define RASP_RULE_BASE_H

#pragma once
// =========================================================================
// rasp_rule_base.h — Shared base rule struct for all RASP native modules.
//
// All per-module rule types (Iis7RaspRuleConfig, AmsiRaspRuleConfig, …)
// derive from RaspRuleBase.  Common fields live here so rasp_sentry_base
// can parse them once without knowing module-specific extensions.
// =========================================================================

#include <string>
#include <vector>

// ── RaspRuleMode ──────────────────────────────────────────────────────────
// Replaces the three mutually-exclusive bool flags in the old RaspRuleConfig
// (blockMode / auditMode / offMode) and the AmsiRuleMode enum — one enum
// for both modules.
enum class RaspRuleMode {
    Off = 0, Audit = 1, Block = 2
};

// ── RegexCondition ────────────────────────────────────────────────────────
// Controls how multiple regexChecks are combined:
//   Any — gate passes when at least one check matches (OR semantics, default).
//   All — gate passes only when every check matches (AND semantics).
enum class RegexCondition {
    Any = 0, All = 1
};

// ── RegexCheck ────────────────────────────────────────────────────────────
// One named check inside a regexChecks array.
//   id       — 检查项标识符，暴露给 Lua 作为 context.regex_matches[i]
//   field    — 要匹配的字段，空字符串 → 使用传感器默认字段
//   patterns — PCRE2 正则表达式模式数组，OR 语义（首个匹配即触发检查）
struct RegexCheck {
    std::string id;
    std::string field;
    std::vector <std::string> patterns;
};

// ── RaspRuleBase ──────────────────────────────────────────────────────────
// Fields common to every rule in every module.
// Module-specific fields live in derived structs: <Module>RaspRuleConfig.
struct RaspRuleBase {
    std::string id;
    std::string sensor;                          // e.g. "AmsiProvider", "RequestFilter"
    bool enabled = true;
    RaspRuleMode mode = RaspRuleMode::Audit;
    std::string description;
    std::string severity;                        // "Low" / "Medium" / "High" / "Critical"
    std::string scriptBodyBase64;                // cleared after Precompile
    std::string scriptEval;                      // "exclusive" | "additional"
    int confidence;  // 设置置信度
    int scriptTimeoutInstructions = 500000; // scriptTimeoutMs * 50000; min 500000

    // ── Legacy single-field regex (config.regexField + config.regexPatterns) ──
    // Fires the rule immediately on first pattern match; Lua is not invoked.
    // regexField: field to match ("body", "url", "ua", …); empty → sensor default.
    // regexPatterns: PCRE2 patterns tested in order (OR semantics).
    std::string regexField;
    std::vector <std::string> regexPatterns;

    // ── Multi-check regex gate (config.regexChecks + config.regexCondition) ──
    // Acts as a named pre-filter: gate must pass before Lua runs (or fires directly
    // if no script is configured).  Matched check IDs are exposed to Lua as
    // context.regex_matches so scripts can branch on which checks fired.
    // regexChecks:    array of {id, field, patterns} checks.
    // regexCondition: Any (OR, default) or All (AND).
    std::vector <RegexCheck> regexChecks;  // 正则表达式
    RegexCondition regexCondition = RegexCondition::Any;

    bool IsOff() const { return mode == RaspRuleMode::Off; }

    bool IsAudit() const { return mode == RaspRuleMode::Audit; }

    bool IsBlock() const { return mode == RaspRuleMode::Block; }
};

#endif
