#pragma once

namespace amsi_ipc {

inline constexpr const wchar_t* kRulesPipeName = LR"(\\.\pipe\amsi_detect_rules)";
inline constexpr const wchar_t* kEventsPipeName = LR"(\\.\pipe\amsi_detect_events)";
inline constexpr const wchar_t* kLogsPipeName = LR"(\\.\pipe\amsi_detect_logs)";
inline constexpr const wchar_t* kControlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status)";
inline constexpr const wchar_t* kConfigPipeName = LR"(\\.\pipe\amsi_detect_config)";

} // namespace amsi_ipc
