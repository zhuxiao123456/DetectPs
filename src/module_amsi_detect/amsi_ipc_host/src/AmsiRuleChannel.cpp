/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 功能: 听取探针的请求 -> 找仓库（Provider）拿规则 -> 把规则打包发给探针
 */
#include "../include/AmsiRuleChannel.h"

#include <string>

namespace amsi_ipc {

    namespace {

        void TrimCommand(std::string &command) {
            while (!command.empty() &&
                   (command.back() == '\n' || command.back() == '\r' || command.back() == ' ')) {
                command.pop_back();
            }
        }

    } // namespace

    AmsiRuleChannel::AmsiRuleChannel(IAmsiRuleProvider &provider)
            : provider_(provider) {
    }

    void AmsiRuleChannel::HandleClient(HANDLE pipe) {
        char requestBuffer[64] = {};
        DWORD bytesRead = 0;
        if (!ReadFile(pipe,
                      requestBuffer,
                      static_cast<DWORD>(sizeof(requestBuffer) - 1),
                      &bytesRead,
                      nullptr)) {
            return;
        }

        requestBuffer[bytesRead] = '\0';
        std::string command(requestBuffer, bytesRead);
        TrimCommand(command);

        AmsiRuleResponse response;
        std::string error;
        if (!provider_.BuildRulesResponse(command, response, error) || response.json.empty()) {
            return;
        }

        std::string wire = response.json + "\n";
        DWORD written = 0;
        const DWORD expected = static_cast<DWORD>(wire.size());
        const BOOL ok = WriteFile(pipe, wire.c_str(), expected, &written, nullptr);
        if (!ok || written != expected) {
            return;
        }

        if (!FlushFileBuffers(pipe)) {
            return;
        }
    }

} // namespace amsi_ipc
