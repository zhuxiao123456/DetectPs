project(engine-test)

set(ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../)
setup_common_path(${PROJECT_NAME} ${ROOT_PATH})

# 添加驱动数据采集模块测试用例.
set(DRIVER_DATA_COLLECT_MODULE_TEST module_driver_data_collect/EdrDriverCtrlTest.cpp module_driver_data_collect/DriverDataCollectModuleTest.cpp
		module_driver_data_collect/DriverDataCollectUtilsTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../native_module/module_driver_data_collect/include)

# 添加文件保护模块测试用例.
set(FILE_PROTECT_MODULE_TEST module_file_protect/FileProtectPolicyTest.cpp module_file_protect/FileProtectModuleTest.cpp
		module_file_protect/FileProtectKeyDirectoryMonitorTaskTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_file_protect/include)

# 添加特征库升级模块测试用例
set(FEATURE_UPGRADE_MODULE
		module_feature_upgrade/FeatureUpgradeModuleTest.cpp
		module_feature_upgrade/FeatureUpgradeTaskTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../native_module/module_feature_upgrade/include)

# 添加病毒扫描任务测试用例
file(GLOB_RECURSE SCANNER_TEST scanner/*.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../scanner/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../scanner/include/utils)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../scanner/include/task)

# 添加基础响应模块测试用例
set(BASE_RESPONSE_MODULE_TEST
		module_basic_response/BaseResponseModuleTest.cpp
		module_basic_response/BaseResponsePolicyTest.cpp
		module_basic_response/UploadFileTaskTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_basic_response/include)

# 添加勒索签名检测模块测试用例
set(BLOCKEXEC_MODULE_TEST
		module_blockexec/BlockExecModuleTest.cpp
		module_blockexec/BlockExecPolicyTest.cpp
		module_blockexec/IntelligenceMatchTaskTest.cpp
		module_blockexec/FileHashFeatureDatabaseTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_blockexec/include)

# 添加图引擎检测模块测试用例
set(GRAPH_MODULE_TEST
		module_graph_detect/GraphDetectModuleTest.cpp
		module_graph_detect/GraphDetectTaskTest.cpp
		module_graph_detect/GraphDetectPolicyTest.cpp
		module_graph_detect/GraphDisposerTest.cpp
		module_graph_detect/RiskScoreAnalyzerTest.cpp
		module_graph_detect/StatisticsAnalyzerTest.cpp
		module_graph_detect/RuleMatcherTest.cpp
		module_graph_detect/GraphEventBuilderTest.cpp
		module_graph_detect/GraphMemoryStoreTest.cpp
		module_graph_detect/GraphDetectMessageTest.cpp
)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_graph_detect/include)

# 添加基线检查模块测试用例
set(BENCHMARK_MODULE_TEST
		module_benchmark/BenchmarkCheckTaskTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_benchmark/include)

# 添加登陆检测模块测试用例
set(LOGIN_MODULE_TEST
		module_login/WeakPwdTaskTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_login/include)

set(ASSET_MANAGE_MODULE_TEST
		module_assetmanage/T6PortalAppScanTest.cpp
		module_assetmanage/JavaAppScanTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_assetmanage/include)

# 添加AV检测模块测试用例
set(AV_MODULE_TEST
		module_avdet/AvDetectModuleTest.cpp
		module_avdet/AvDetectPolicyTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_avdet/include)

# 添加AMSI检测模块测试用例
set(AMSI_MODULE_TEST
		module_amsi_detect/AmsiEventChannelTest.cpp
		module_amsi_detect/AmsiControlStatusChannelTest.cpp
		module_amsi_detect/AmsiRuleChannelTest.cpp
		module_amsi_detect/AmsiConfigBroadcasterTest.cpp
		module_amsi_detect/NamedPipeServerPoolTest.cpp
		module_amsi_detect/AmsiGlobalConfTest.cpp
		module_amsi_detect/AmsiIpcRuntimeQueueTest.cpp
		module_amsi_detect/AmsiIpcPayloadClassifierTest.cpp
		module_amsi_detect/AmsiEventProcessorTest.cpp
		module_amsi_detect/AmsiDetectPolicyTest.cpp
		module_amsi_detect/AmsiIpcRuntimeTest.cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_amsi_detect/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../module/module_amsi_detect/amsi_ipc_host/include)

add_executable(${TARGET}
		main.cpp
		${DRIVER_DATA_COLLECT_MODULE_TEST}
		${FILE_PROTECT_MODULE_TEST}
		${FEATURE_UPGRADE_MODULE}
		${SCANNER_TEST}
		${BASE_RESPONSE_MODULE_TEST}
		${BLOCKEXEC_MODULE_TEST}
		${ASSET_MANAGE_MODULE_TEST}
		${GRAPH_MODULE_TEST}
		${AV_MODULE_TEST}
		${AMSI_MODULE_TEST}
		${BENCHMARK_MODULE_TEST}
		${LOGIN_MODULE_TEST}
)

# 连接必要的库
TARGET_LINK_LIBRARIES(
		${TARGET}
		gtest
		HostVirusScanner
		driver_data_collect_module
		file_protect_module
		feature_upgrade_module
		basic_response_module
		blockexec_module
		assetmanage_module
		graph_detect_module
		av_det_module
		amsi_detect_module
		benchmark_module
		login_module
)