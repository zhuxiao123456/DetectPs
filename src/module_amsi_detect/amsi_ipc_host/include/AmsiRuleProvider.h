/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 目的: 解耦, AmsiRuleChannel 不负责从硬盘读文件或连数据库，它只向 IAmsiRuleProvider 要数据
 */
#ifndef AMSI_RULE_PROVIDER_H
#define AMSI_RULE_PROVIDER_H

#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiRuleResponse {
    std::string json;
};

class IAmsiRuleProvider {
public:
    virtual ~IAmsiRuleProvider() = default;
    // 输入：command（如获取哪种类型的规则）。
    // 输出：AmsiRuleResponse out（里面包着序列化好的 JSON 字符串），std::string error（错误信息）
    virtual bool BuildRulesResponse(const std::string& command,
                                    AmsiRuleResponse& out,
                                    std::string& error) = 0;

    virtual void InvalidateRuleCache() = 0;  // 用于清空内存中缓存的规则，以便下一次请求时重新从磁盘或云端加载
};

} // namespace amsi_ipc

#endif
