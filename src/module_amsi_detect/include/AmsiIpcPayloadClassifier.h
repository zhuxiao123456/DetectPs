//
// Created by z00840245 on 2026/5/22.
// 功能: 识别dll传过来的payload信息(轻量级别json字段提取算法)
//

#ifndef CSA_ENGINE_AMSI_IPC_PAYLOAD_CLASSIFIER_H
#define CSA_ENGINE_AMSI_IPC_PAYLOAD_CLASSIFIER_H

#include <string>

namespace Engine {

    enum class AmsiIpcPayloadKind {
        UnknownEvent,  // 未知或畸形事件。无法识别的数据包，作为兜底保护
        Detection,  //  威胁检测告警事件
        DllDiagnosticLog,  // 来自注入动态链接库（hss_amsi.dll）内部的本地运行诊断日志、错误上报
        DrainAck,  // 排空确认响应。用于引擎关闭或重置时，同步确认管道内的残留事件是否已被完全“抽干清除”
        Status  // 探针健康状态、心跳包或性能指标
    };

    AmsiIpcPayloadKind ClassifyAmsiEventPayload(const std::string &payload);

} // namespace Engine

#endif //CSA_ENGINE_AMSI_IPC_PAYLOAD_CLASSIFIER_H
