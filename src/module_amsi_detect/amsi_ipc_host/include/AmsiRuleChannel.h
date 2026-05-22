/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#ifndef AMSI_RULE_CHANNEL_H
#define AMSI_RULE_CHANNEL_H

#pragma once

#include "AmsiRuleProvider.h"
#include "NamedPipeServerPool.h"

namespace amsi_ipc {

class AmsiRuleChannel : public INamedPipeClientHandler {
public:
    explicit AmsiRuleChannel(IAmsiRuleProvider& provider);

    void HandleClient(HANDLE pipe) override;

private:
    IAmsiRuleProvider& provider_;
};

} // namespace amsi_ipc

#endif
