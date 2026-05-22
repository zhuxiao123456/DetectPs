/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 定义了 4 根管道的全局静态路径
 */
#ifndef AMSI_PIPE_NAMES_H
#define AMSI_PIPE_NAMES_H

#pragma once

namespace amsi_ipc {

inline constexpr const wchar_t* kRulesPipeName = LR"(\\.\pipe\amsi_detect_rules)";
inline constexpr const wchar_t* kEventsPipeName = LR"(\\.\pipe\amsi_detect_events)";
inline constexpr const wchar_t* kControlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status)";
inline constexpr const wchar_t* kConfigPipeName = LR"(\\.\pipe\amsi_detect_config)";

} // namespace amsi_ipc

#endif
