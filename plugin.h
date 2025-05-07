#pragma once

#define Cmd(x) DbgCmdExecDirect(x)
#define Eval(x) DbgValFromString(x)
#define PLUG_EXPORT extern "C" __declspec(dllexport)

// plugin data
#define PLUGIN_NAME_utf16 L"VMHelp"
#define PLUGIN_NAME "VMHelp"
#define PLUGIN_VERSION 1

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT *initStruct);

PLUG_EXPORT bool plugstop();

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT *setupStruct);

// --------------------------------------------------------------------
using CBCONDFUNC = void(*)(CBTYPE cbType, void *Info);

struct dbg_cond_cmd {
    DWORD       thread_id;  //只有在此线程断下才可执行,如果ID为0 则任意线程可执行
    bool        no_cmd;     //ture 不执行cmd 只执行回调函数
    uint64_t    valid_time; //有效截至时间
    CBTYPE      type;       //CB_STEPPED  触发时机:如单步后
    std::string cond;       //条件表达式  当表达式成立才可执行
    std::string cmd;        //命令         执行的命令
    CBCONDFUNC  callback;   //回调函数 为NULL时不调用
};

// GUI 回调
void plugin_GuiEvent(CBTYPE bType, void *pInfo);

// Debug 回调
void plugin_DebugEvent(CBTYPE bType, void *pInfo);

// 格式化字符串 执行Dbg命令
bool DbgCmdExecV(const char *_FormatCmd, ...);

// 设置命令条件 valid_time == -1 永久有效
bool DbgCmdSetCondV(dbg_cond_cmd *pCond, uint64_t valid_time, CBTYPE nCondType, CBCONDFUNC callback, const char *_FormatCond, ...);

// 推送命令到队列
bool DbgCmdExecCondV(dbg_cond_cmd *pCond, const char *_FormatCmd, ...);

// 执行条件命令 实现函数
bool DbgCmdExecCondCome(CBTYPE nCondType, void *pInfo);

// 启动跟踪执行到一个退出点
void Track_Execute_Until_Ret(int flags);

// 启动跟踪执行,直到遇见设置的断点,或不可控退出
void Track_Execute();
