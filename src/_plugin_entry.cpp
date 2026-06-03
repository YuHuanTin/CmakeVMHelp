//
// Created by YuHuanTin on 2026/5/18.
//

#include "_plugin_entry.h"

#include "CommandHandlers.h"
#include "Engine.h"
#include "GUI.h"

#ifdef OUTPUT_FILE
void plugin_log_to_file(const char *fmt, ...) {
    FILE *fp = nullptr;
    if (fopen_s(&fp, OUTPUT_FILE, "ab") != 0 || fp == nullptr) {
        return;
    }

    va_list args;
    va_start(args, fmt);
    std::vfprintf(fp, fmt, args);
    va_end(args);

    std::fclose(fp);
}
#endif

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion    = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, sizeof(PLUGIN_NAME));
    gPluginHandle = initStruct->pluginHandle;
    return init_engine();
}

void init_command_reg() {
    bool bRet = false;

    constexpr auto vm_run_until_page_switch = "vmrun_until_page_switch"; // 运行直到页切换（跳出当前页）
    constexpr auto vm_run_until_breakpoint  = "vmrun_until_breakpoint";  // 运行直到断点处
    constexpr auto vm_run_until_instruction = "vmrun_until_instruction"; // 运行直到遇到某指令
    constexpr auto vm_run_until_call_return = "vmrun_until_call_return"; // 运行直到当前 call 返回（跳出）

    bRet = _plugin_registercommand(gPluginHandle, vm_run_until_page_switch, cb_run_until_page_switch, true);
    if (!bRet) {
        LOG("register command failed for %s", vm_run_until_page_switch);
    }

    bRet = _plugin_registercommand(gPluginHandle, vm_run_until_breakpoint, cb_run_until_breakpoint, true);
    if (!bRet) {
        LOG("register command failed for %s", vm_run_until_breakpoint);
    }

    bRet = _plugin_registercommand(gPluginHandle, vm_run_until_instruction, cb_run_until_instruction, true);
    if (!bRet) {
        LOG("register command failed for %s", vm_run_until_instruction);
    }

    bRet = _plugin_registercommand(gPluginHandle, vm_run_until_call_return, cb_run_until_call_return, true);
    if (!bRet) {
        LOG("register command failed for %s", vm_run_until_call_return);
    }

    // for test
    bRet = _plugin_registercommand(gPluginHandle, "_test_DbgGetBpxTypeAt", cb_test_DbgGetBpxTypeAt, true);
    if (!bRet) {
        LOG("register command failed for %s", "_test_DbgGetBpxTypeAt");
    }
    bRet = _plugin_registercommand(gPluginHandle, "_test_PageQuery", cb_test_PageQuery, true);
    if (!bRet) {
        LOG("register command failed for %s", "_test_PageQuery");
    }
    bRet = _plugin_registercommand(gPluginHandle, "_test_StepInAndQueryPage", cb_test_StepInAndQueryPage, true);
    if (!bRet) {
        LOG("register command failed for %s", "_test_StepInAndQueryPage");
    }
}

// 插件初始化成功，可以注册菜单和其他GUI相关的东西
PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct) {
    init_gui(setupStruct);
    init_command_reg();
}

// 插件即将被卸载，删除此处所有已注册的命令和回调。还要清理插件数据
PLUG_EXPORT bool plugstop() {
    return true;
}


// 初始化导出
// extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct);
// extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct);
// extern "C" __declspec(dllexport) bool plugstop();

// 回调导出。确保仅导出您实际使用的回调！
// extern "C" __declspec(dllexport) void CBINITDEBUG(CBTYPE cbType, PLUG_CB_INITDEBUG* info);
// extern "C" __declspec(dllexport) void CBSTOPDEBUG(CBTYPE cbType, PLUG_CB_STOPDEBUG* info);
// extern "C" __declspec(dllexport) void CBEXCEPTION(CBTYPE cbType, PLUG_CB_EXCEPTION* info);
// extern "C" __declspec(dllexport) void CBDEBUGEVENT(CBTYPE cbType, PLUG_CB_DEBUGEVENT* info);
// extern "C" __declspec(dllexport) void CBMENUENTRY(CBTYPE cbType, PLUG_CB_MENUENTRY* info);
