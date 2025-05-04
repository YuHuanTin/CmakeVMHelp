#include "pch.h"
#include "Track.h"
#include "plugin.h"

#include "main.hpp"

#define MAX_SCAN_SIZE 0x1000

typedef void (*CBCONDFUNC)(CBTYPE cbType, void *Info);

struct _dbg_cond_cmd {
    DWORD       thread_id;  //只有在此线程断下才可执行,如果ID为0 则任意线程可执行
    bool        no_cmd;     //ture 不执行cmd 只执行回调函数
    uint64_t    valid_time; //有效截至时间
    CBTYPE      type;       //CB_STEPPED  触发时机:如单步后
    std::string cond;       //条件表达式  当表达式成立才可执行
    std::string cmd;        //命令         执行的命令
    CBCONDFUNC  callback;   //回调函数 为NULL时不调用
};

RTL_CRITICAL_SECTION       m_dbg_cmd_cond_lock;
std::vector<_dbg_cond_cmd> m_dbg_cmd_cond;
Track                      m_Track;

//GUI回调
void plugin_GuiEvent(CBTYPE bType, void *pInfo);

//Debug回调
void plugin_DebugEvent(CBTYPE bType, void *pInfo);

//格式化字符串 执行Dbg命令
bool DbgCmdExecV(const char *_FormatCmd, ...);

//设置命令条件 valid_time == -1 永久有效
bool DbgCmdSetCondV(_dbg_cond_cmd *pCond, uint64_t valid_time, CBTYPE nCondType, CBCONDFUNC callback, const char *_FormatCond, ...);

//推送命令到队列
bool DbgCmdExecCondV(_dbg_cond_cmd *pCond, const char *_FormatCmd, ...);

//执行条件命令 实现函数
bool DbgCmdExecCondCome(CBTYPE nCondType, void *pInfo);


//启动跟踪执行,直到遇见设置的断点,或不可控退出
void track_execute();

//当遇到仿真器不能处理的异常时,设置那时的断点,命中时执行此回调
void track_execute_continue(CBTYPE cbType, void *pInfo) {
    if (cbType == CB_BREAKPOINT) {
        //跟踪断点
        while (DbgIsRunning() == true) {
            Sleep(10);
        }
        PLUG_CB_BREAKPOINT *pBreakpoint = (PLUG_CB_BREAKPOINT *) pInfo;

        BPXTYPE bptype = DbgGetBpxTypeAt(pBreakpoint->breakpoint->addr);
        if (bptype != bp_none) {
            DbgCmdExecV("bpc %llx", pBreakpoint->breakpoint->addr);
        }

        track_execute();
    } else
        if (cbType == CB_STEPPED) {}
}

//在这里初始化插件数据.
bool pluginInit(PLUG_INITSTRUCT *initStruct) {
    InitializeCriticalSection(&m_dbg_cmd_cond_lock);

    if (!m_Track.engine_init()) {
        _plugin_logprintf("[" PLUGIN_NAME "] 插件引擎初始化失败.");
        return false;
    }
    return true;
}

//在这里取消初始化插件数据(清除菜单可选)
bool pluginStop() {
    return true;
}

//这里有GUI/Menu相关的东西吗.
void pluginSetup() {
    _plugin_menuaddentry(hMenu, 1001, "关于\"" PLUGIN_NAME "\"");

    _plugin_menuaddentry(hMenuDisasm, 2001, "执行到跳出内存区域");
    _plugin_menuaddentry(hMenuDisasm, 2002, "跟踪执行");

    _plugin_registercallback(pluginHandle, CB_MENUENTRY, (CBPLUGIN) &plugin_GuiEvent);


    _plugin_registercallback(pluginHandle, CB_BREAKPOINT, (CBPLUGIN) &plugin_DebugEvent);
    _plugin_registercallback(pluginHandle, CB_STEPPED, (CBPLUGIN) &plugin_DebugEvent);
}

//获取地址到内存的范围
bool get_addr_mem_range(HANDLE hProcess, uint64_t address, _track_mem_range *mem_rage) {
    bool bSuccess = false;
    if (hProcess != NULL) {
        MEMORY_BASIC_INFORMATION mem_info;
        MEMORY_BASIC_INFORMATION mem_info_1;
        //先获取AllocationBase
        if (VirtualQueryEx(hProcess, (LPCVOID) address, &mem_info_1, sizeof(mem_info_1)) != NULL) {
            if (VirtualQueryEx(hProcess, (LPCVOID) mem_info_1.AllocationBase, &mem_info_1, sizeof(mem_info_1)) != NULL) {
                bSuccess       = true;
                mem_info       = mem_info_1;
                mem_rage->base = (uintptr_t) mem_info.AllocationBase;
                mem_rage->end  = mem_rage->base;
                do {
                    mem_rage->end += mem_info.RegionSize;

                    mem_info.BaseAddress = (PVOID) ((uint64_t) mem_info.BaseAddress + mem_info.RegionSize);
                    if (VirtualQueryEx(hProcess, (LPCVOID) mem_info.BaseAddress, &mem_info, sizeof(mem_info)) == NULL)
                        break;
                    if (mem_info_1.AllocationBase != mem_info.AllocationBase)
                        break;
                } while ((uint64_t) mem_info.BaseAddress <= address);
            }
        }
    }
    return bSuccess;
}

//启动跟踪执行到一个退出点
void track_execute_exit(int flags) {
    if (DbgIsRunning() == true) {
        MessageBoxW(hwndDlg, L"调试器需要在停止状态下执行.", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);
        return;
    }
    REGDUMP lpRegDump;
    if (DbgGetRegDumpEx(&lpRegDump, sizeof(lpRegDump)) == false) {
        MessageBoxW(hwndDlg, L"获取寄存器环境失败.", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);
        return;
    }
    //如果EIP位置有设置断点并且启用
    BPXTYPE bptype = DbgGetBpxTypeAt(lpRegDump.regcontext.cip);
    if (bptype == BPXTYPE::bp_normal && DbgIsBpDisabled(lpRegDump.regcontext.cip) == false) {
        MessageBoxW(hwndDlg, L"当前地址设置了断点,请取消断点或单步后在执行操作.", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);
        return;
    }

    DWORD process_id = DbgGetProcessId();
    DWORD thread_id  = DbgGetThreadId();

    m_Track.set_mem_context(process_id, thread_id);
    m_Track.set_reg_context(lpRegDump, true, thread_id);
    m_Track.mem_map_range(lpRegDump.regcontext.cip);
    
    MessageBoxW(hwndDlg, L"1", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);

    m_Track.mem_map_range(lpRegDump.regcontext.csp);

    MessageBoxW(hwndDlg, L"2", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);


    _track_mem_range pmem_range = { 0 };
    if (!get_addr_mem_range(m_Track.m_process_info.Process, lpRegDump.regcontext.cip, &pmem_range)) {
        MessageBoxW(hwndDlg, L"获取内存区域失败.", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);
        return;
    }
    m_Track.set_mem_track_range(true, pmem_range.base, pmem_range.end);


    _track_exit_msg exit_msg;
    m_Track.start_track(&exit_msg);

    MessageBoxW(hwndDlg, L"safe", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);

    if (exit_msg.exit_base != NULL) {
        bool         is_dbg_bp  = false;
        uint64_t     bp_base    = exit_msg.exit_base;
        _track_insn *track_insn = m_Track.get_execute_last_insn();
        if (track_insn->insn.id == X86_INS_INT3) {
            BPXTYPE bptype = DbgGetBpxTypeAt(track_insn->insn.address);
            if (bptype == BPXTYPE::bp_normal && DbgIsBpDisabled(track_insn->insn.address) == false) {
                //执行到dbg设置的断点上
                is_dbg_bp = true;
            }
        }
        if (is_dbg_bp == false) {
            if (flags == 1 || exit_msg.exit_insn_flags == 1) {
                if (exit_msg.next_base != NULL && DbgMemIsValidReadPtr(exit_msg.next_base))
                    bp_base = exit_msg.next_base;
            }

            MessageBoxW(hwndDlg, L"safe2", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);

            _dbg_cond_cmd pDbgCondCmd;
            pDbgCondCmd.thread_id = thread_id;
            pDbgCondCmd.no_cmd    = false;
            DbgCmdSetCondV(&pDbgCondCmd, 1000 * 30, CB_STEPPED, nullptr, "1");
            DbgCmdExecCondV(&pDbgCondCmd, "bp 0x%llx, \"%s\", ssshort", bp_base, PLUGIN_NAME);
            DbgCmdExecCondV(&pDbgCondCmd, "bpcond %llx, \"tid()==0x%x\"", bp_base, thread_id);
            DbgCmdExecCondV(&pDbgCondCmd, "go");
            MessageBoxW(hwndDlg, L"safe3", PLUGIN_NAME_utf16, MB_OK | MB_ICONERROR);

            if (flags == 1) {
                pDbgCondCmd.no_cmd = true;
                DbgCmdSetCondV(&pDbgCondCmd, 1000 * 30, CB_BREAKPOINT, track_execute_continue, "cip==0x%llx", bp_base);
                DbgCmdExecCondV(&pDbgCondCmd, "");
            } else if (flags == 0) {
                pDbgCondCmd.no_cmd = false;
                DbgCmdSetCondV(&pDbgCondCmd, 1000 * 30, CB_BREAKPOINT, nullptr, "cip==0x%llx", bp_base);
                DbgCmdExecCondV(&pDbgCondCmd, "dis 0x%llx", bp_base); //添加回溯地址
                DbgCmdExecCondV(&pDbgCondCmd, "StepInto 1");
            }

            DbgCmdExecV("StepInto 1");
        } else {
            DbgCmdExecV("go");
        }
        _plugin_logprintf("[%s] 结束地址:%llx  本次跟踪数量:%d 总跟踪数量:%d \n", PLUGIN_NAME, exit_msg.exit_base, exit_msg.track_num, m_Track.m_track_insn.size());
    }
}

//启动跟踪执行,直到遇见设置的断点,或不可控退出
void track_execute() {
    track_execute_exit(1);
}

//GUI回调
void plugin_GuiEvent(CBTYPE bType, void *pInfo) {
    if (bType == CB_MENUENTRY) {
        PLUG_CB_MENUENTRY *pEntry = (PLUG_CB_MENUENTRY *) pInfo;
        switch (pEntry->hEntry) {
            case 1001: //注册时填的菜单ID
            {
                MessageBoxW(hwndDlg, L"TLD.XiaoYao", PLUGIN_NAME_utf16, MB_OK | MB_ICONINFORMATION);
                break;
            }
            case 2001: {
                m_Track.m_track_insn.clear();
                track_execute_exit(0);
                m_Track.m_track_insn.clear();
                break;
            }
            case 2002: {
                m_Track.m_track_insn.clear();
                track_execute();
            }
            default:
                break;
        }
    }
}

//Debug回调
void plugin_DebugEvent(CBTYPE bType, void *pInfo) {
    if (bType == CB_BREAKPOINT) {
        PLUG_CB_BREAKPOINT *pBreakpoint = (PLUG_CB_BREAKPOINT *) pInfo;
        DbgCmdExecCondCome(bType, pInfo);
    } else if (bType == CB_STEPPED) {
        PLUG_CB_STEPPED *pStepped = (PLUG_CB_STEPPED *) pInfo;

        DbgCmdExecCondCome(bType, pInfo);
    }
}


//格式化字符串 执行Dbg命令
bool DbgCmdExecV(const char *_FormatCmd, ...) {
    bool    bret   = false;
    va_list vlArgs = NULL;
    va_start(vlArgs, _FormatCmd);
    size_t nLen      = _vscprintf(_FormatCmd, vlArgs) + 1;
    char * strBuffer = new char[nLen];
    _vsnprintf_s(strBuffer, nLen, nLen, _FormatCmd, vlArgs);
    va_end(vlArgs);


    bret = DbgCmdExecDirect(strBuffer);

    delete[] strBuffer;

    return bret;
}

//设置命令条件
bool DbgCmdSetCondV(_dbg_cond_cmd *pCond, uint64_t valid_time, CBTYPE nCondType, CBCONDFUNC callback, const char *_FormatCond, ...) {
    bool    bret   = true;
    va_list vlArgs = NULL;
    va_start(vlArgs, _FormatCond);
    size_t nLen      = _vscprintf(_FormatCond, vlArgs) + 1;
    char * strBuffer = new char[nLen];
    _vsnprintf_s(strBuffer, nLen, nLen, _FormatCond, vlArgs);
    va_end(vlArgs);

    if (valid_time == -1)
        pCond->valid_time = valid_time;
    else
        pCond->valid_time = GetTickCount64() + valid_time;

    pCond->type     = nCondType;
    pCond->cond     = strBuffer;
    pCond->callback = callback;

    delete[] strBuffer;


    return bret;
}

//推送命令到队列
bool DbgCmdExecCondV(_dbg_cond_cmd *pCond, const char *_FormatCmd, ...) {
    bool    bret   = true;
    va_list vlArgs = NULL;
    va_start(vlArgs, _FormatCmd);
    size_t nLen      = _vscprintf(_FormatCmd, vlArgs) + 1;
    char * strBuffer = new char[nLen];
    _vsnprintf_s(strBuffer, nLen, nLen, _FormatCmd, vlArgs);
    va_end(vlArgs);


    pCond->cmd = strBuffer;
    EnterCriticalSection(&m_dbg_cmd_cond_lock);
    m_dbg_cmd_cond.push_back(*pCond);
    LeaveCriticalSection(&m_dbg_cmd_cond_lock);

    delete[] strBuffer;

    return bret;
}

//执行条件命令 实现函数
bool DbgCmdExecCondCome(CBTYPE nCondType, void *pInfo) {
    bool     bRet  = false;
    size_t   nSize = m_dbg_cmd_cond.size();
    uint64_t nTime = GetTickCount64();
    bool     is_thread;
    DWORD    thread_id = DbgGetThreadId();
    EnterCriticalSection(&m_dbg_cmd_cond_lock);
    for (size_t i = 0; i < nSize; i++) {
        if (nTime > m_dbg_cmd_cond[i].valid_time) {
            m_dbg_cmd_cond.erase(m_dbg_cmd_cond.begin() + i);
            i--;
            nSize--;
            continue;
        }
        if (m_dbg_cmd_cond[i].type == nCondType) {
            is_thread = true;
            if (m_dbg_cmd_cond[i].thread_id != NULL && thread_id != m_dbg_cmd_cond[i].thread_id) {
                thread_id = false;
            }

            if (is_thread && DbgValFromString(m_dbg_cmd_cond[i].cond.c_str())) {
                if (m_dbg_cmd_cond[i].no_cmd == false) {
                    bRet = DbgCmdExecDirect(m_dbg_cmd_cond[i].cmd.c_str());
                } else {
                    bRet = true;
                }
                if (m_dbg_cmd_cond[i].callback != nullptr)
                    m_dbg_cmd_cond[i].callback(nCondType, pInfo);
                m_dbg_cmd_cond.erase(m_dbg_cmd_cond.begin() + i);
                i--;
                nSize--;

                if (bRet == false)
                    break;
            }
        }
    }
    LeaveCriticalSection(&m_dbg_cmd_cond_lock);
    return bRet;
}
