#pragma once


#define ALIGN_TO_4KB(value) (((value) + 0xFFF) & ~0xFFF)
#define DebugFileOutputPath "log.txt"
#include "gdt.h"
#include "VMExecute.h"

struct ProcessInfo {
    DWORD  ProcessId;
    DWORD  ThreadId;
    HANDLE Process;
    HANDLE Thread;
};

struct TrackInsn {
    cs_insn insn {};
};

struct TrackExitMsg {
    int      exit_code;       //0:虚拟机退出 1:不在跟踪范围退出
    int      exit_insn_flags; //0.无特殊指令 1.特殊指令 ljmp
    uint64_t exit_base;       //导致退出的base
    uint64_t next_base;       //解析选择的base
    size_t   track_num;       //跟踪数量
};

struct TrackMemRange {
    uint64_t base;
    uint64_t end;
};

class Track {
public:
    //初始化引擎
    bool engine_init();

    //设置内存环境  先设置内存环境
    bool set_mem_context(DWORD process_id, DWORD thread_id);

    //设置寄存器环境  process_id == 0 将不设置段寄存器 eflags_zero_tf == true 设置tf位为0
    bool set_reg_context(REGDUMP regdump, bool eflags_zero_tf = false, DWORD thread_id = 0);

    //设置内存跟踪范围
    void set_mem_track_range(bool only, uint64_t addr, uint64_t end);

    TrackMemRange *find_mem_track_range(uint64_t addr);

    //开始仿真跟踪
    uc_err start_track(TrackExitMsg *exit_msg);

    //获取最后一条执行指令
    TrackInsn *get_execute_last_insn();

    //寻找下一条指令地址
    uint64_t find_next_base(int *insn_flags = 0);


    VMExecute              m_VME;
    ProcessInfo            m_process_info;
    TrackExitMsg           m_exit_msg;
    std::vector<TrackInsn> m_track_insn;

    bool                       m_enable_track_mem_range; //是否启用跟踪范围
    std::vector<TrackMemRange> m_track_mem_range;        //跟踪的内存范围
    TrackMemRange              m_only_range;             //当存在这个时其他范围限定都将不起作用

    //映射给定进程的地址范围到虚拟机
    bool mem_map_range(uint64_t address);

    void print_mem_region();

private:
    SegmentSelector m_back_ss; //初始化时需要ss段为0环权限,执行代码时恢复为3环权限
    uc_hook         m_handle_hook_mem_unmapped;
    uc_hook         m_handle_hook_code_execute;
    bool            debugFileOutput_ = true;
    std::fstream    debugFile_;

    static bool callback_event_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);

    static void callback_evnet_code(uc_engine *uc, uint64_t addr, uint32_t size, void *user_data);
};
