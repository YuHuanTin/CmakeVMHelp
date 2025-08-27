#include "Track.h"
#include "plugin.h"

#define _NO_NTDLL_ACT_
#define _NO_NTDLL_CRT_
#include "ntdll/ntstatus.h"
#include "ntdll/ntdll.h"

#include "Config.h"

__forceinline uint32_t mem_win_protect_to_uc_protect(DWORD win_protect_c) {
    DWORD win_protect = win_protect_c & (~(PAGE_TARGETS_INVALID | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE));
    if (win_protect == PAGE_EXECUTE)
        return UC_PROT_EXEC;
    else if (win_protect == PAGE_EXECUTE_READ)
        return UC_PROT_EXEC | UC_PROT_READ;
    else if (win_protect == PAGE_EXECUTE_READWRITE)
        return UC_PROT_EXEC | UC_PROT_READ | UC_PROT_WRITE;
    else if (win_protect == PAGE_EXECUTE_WRITECOPY)
        return UC_PROT_EXEC | UC_PROT_READ | UC_PROT_WRITE;
    else if (win_protect == PAGE_NOACCESS)
        return UC_PROT_NONE;
    else if (win_protect == PAGE_READONLY)
        return UC_PROT_READ;
    else if (win_protect == PAGE_READWRITE)
        return UC_PROT_READ | UC_PROT_WRITE;
    else if (win_protect == PAGE_WRITECOPY)
        return UC_PROT_READ | UC_PROT_WRITE;
    else if (win_protect == PAGE_WRITECOPY)
        return UC_PROT_READ | UC_PROT_WRITE;
    return UC_PROT_NONE;
}

bool Track::engine_init() {
    bool bsuccess = false;
#ifdef _WIN64
    bsuccess = m_VME.Init(UC_ARCH_X86, UC_MODE_64, CS_ARCH_X86, CS_MODE_64);
#else
    bsuccess = m_VME.Init(UC_ARCH_X86, UC_MODE_32, CS_ARCH_X86, CS_MODE_32);
#endif

    _plugin_logprintf("log: the vm engine init result = %d\n", bsuccess);

    if (bsuccess) {
        //汇编引擎将解析更多细节
        m_VME.disa_cs_option(CS_OPT_DETAIL, CS_OPT_ON);
    }
    return bsuccess;
}

bool Track::set_reg_context(REGDUMP regdump, bool eflags_zero_tf, DWORD thread_id) {
    uc_err err;
    bool   bSuccess = true;

    //设置eflags tf 位 禁止单步
    _reg_eflags reg_eflags;
    reg_eflags.all = regdump.regcontext.eflags;
    if (eflags_zero_tf)
        reg_eflags.tf = 0;

#ifdef _WIN64
    m_VME.sim_uc_reg_write(UC_X86_REG_RSP, &regdump.regcontext.csp);
    m_VME.sim_uc_reg_write(UC_X86_REG_RAX, &regdump.regcontext.cax);
    m_VME.sim_uc_reg_write(UC_X86_REG_RBX, &regdump.regcontext.cbx);
    m_VME.sim_uc_reg_write(UC_X86_REG_RCX, &regdump.regcontext.ccx);
    m_VME.sim_uc_reg_write(UC_X86_REG_RDX, &regdump.regcontext.cdx);
    m_VME.sim_uc_reg_write(UC_X86_REG_RBP, &regdump.regcontext.cbp);
    m_VME.sim_uc_reg_write(UC_X86_REG_RSI, &regdump.regcontext.csi);
    m_VME.sim_uc_reg_write(UC_X86_REG_RDI, &regdump.regcontext.cdi);

    m_VME.sim_uc_reg_write(UC_X86_REG_R8, &regdump.regcontext.r8);
    m_VME.sim_uc_reg_write(UC_X86_REG_R9, &regdump.regcontext.r9);
    m_VME.sim_uc_reg_write(UC_X86_REG_R10, &regdump.regcontext.r10);
    m_VME.sim_uc_reg_write(UC_X86_REG_R11, &regdump.regcontext.r11);
    m_VME.sim_uc_reg_write(UC_X86_REG_R12, &regdump.regcontext.r12);
    m_VME.sim_uc_reg_write(UC_X86_REG_R13, &regdump.regcontext.r13);
    m_VME.sim_uc_reg_write(UC_X86_REG_R14, &regdump.regcontext.r14);
    m_VME.sim_uc_reg_write(UC_X86_REG_R15, &regdump.regcontext.r15);

    m_VME.sim_uc_reg_write(UC_X86_REG_RIP, &regdump.regcontext.cip);

    err = m_VME.sim_uc_reg_write(UC_X86_REG_RFLAGS, &reg_eflags.all);

#else
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ESP, &regdump.regcontext.csp);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_EAX, &regdump.regcontext.cax);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_EBX, &regdump.regcontext.cbx);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ECX, &regdump.regcontext.ccx);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_EDX, &regdump.regcontext.cdx);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_EBP, &regdump.regcontext.cbp);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ESI, &regdump.regcontext.csi);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_EDI, &regdump.regcontext.cdi);

    err = m_VME.sim_uc_reg_write(UC_X86_REG_EIP, &regdump.regcontext.cip);

    err = m_VME.sim_uc_reg_write(UC_X86_REG_EFLAGS, &reg_eflags.all);
#endif


    err = m_VME.sim_uc_reg_write(UC_X86_REG_DR0, &regdump.regcontext.dr0);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_DR1, &regdump.regcontext.dr1);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_DR2, &regdump.regcontext.dr2);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_DR3, &regdump.regcontext.dr3);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_DR6, &regdump.regcontext.dr6);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_DR7, &regdump.regcontext.dr7);

    //浮点控制寄存器
    err = m_VME.sim_uc_reg_write(UC_X86_REG_FPSW, &regdump.regcontext.x87fpu.StatusWord);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_FPCW, &regdump.regcontext.x87fpu.ControlWord); //精度控制
    err = m_VME.sim_uc_reg_write(UC_X86_REG_FPTAG, &regdump.regcontext.x87fpu.TagWord);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_MXCSR, &regdump.regcontext.MxCsr); //SIMD浮点控制寄存器


    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST0, &regdump.regcontext.RegisterArea[0 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST1, &regdump.regcontext.RegisterArea[1 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST2, &regdump.regcontext.RegisterArea[2 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST3, &regdump.regcontext.RegisterArea[3 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST4, &regdump.regcontext.RegisterArea[4 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST5, &regdump.regcontext.RegisterArea[5 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST6, &regdump.regcontext.RegisterArea[6 * 10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_ST7, &regdump.regcontext.RegisterArea[7 * 10]);


    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM0, &regdump.regcontext.YmmRegisters[0]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM1, &regdump.regcontext.YmmRegisters[1]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM2, &regdump.regcontext.YmmRegisters[2]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM3, &regdump.regcontext.YmmRegisters[3]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM4, &regdump.regcontext.YmmRegisters[4]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM5, &regdump.regcontext.YmmRegisters[5]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM6, &regdump.regcontext.YmmRegisters[6]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM7, &regdump.regcontext.YmmRegisters[7]);
#ifdef _WIN64
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM8, &regdump.regcontext.YmmRegisters[8]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM9, &regdump.regcontext.YmmRegisters[9]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM10, &regdump.regcontext.YmmRegisters[10]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM11, &regdump.regcontext.YmmRegisters[11]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM12, &regdump.regcontext.YmmRegisters[12]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM13, &regdump.regcontext.YmmRegisters[13]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM14, &regdump.regcontext.YmmRegisters[14]);
    err = m_VME.sim_uc_reg_write(UC_X86_REG_YMM15, &regdump.regcontext.YmmRegisters[15]);
#else
#endif
    if (thread_id != 0) {
        typedef NTSTATUS (WINAPI*pfnNtQueryInformationThread)(
            HANDLE          ThreadHandle,
            THREADINFOCLASS ThreadInformationClass,
            PVOID           ThreadInformation,
            ULONG           ThreadInformationLength,
            PULONG          ReturnLength
        );
        PVOID  pTeb    = 0;
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread_id);
        if (hThread != NULL) {
            THREAD_BASIC_INFORMATION thread_basic_info = { 0 };
            ULONG                    returnLength;
            NTSTATUS                 status = NtQueryInformationThread(hThread, ThreadBasicInformation, &thread_basic_info, sizeof(thread_basic_info), &returnLength);
            if (status != STATUS_SUCCESS) {
                bSuccess = false;
            } else {
                pTeb = thread_basic_info.TebBaseAddress;
            }
            CloseHandle(hThread);
        }
        if (pTeb != NULL) {
            uc_x86_mmr gdtr;


#ifdef _WIN64
            const uint64_t m_gdt_address = 0xFFFFC00000000000;
#else
            const uint64_t m_gdt_address = 0xc0000000;
#endif
            struct SegmentDescriptor *gdt = (struct SegmentDescriptor *) malloc(31 * sizeof(struct SegmentDescriptor));

            SegmentSelector r_cs_32 = {}; //代码段  33 64位运行模式  23 32位运行模式
            SegmentSelector r_cs    = {}; //代码段  33 64位运行模式  23 32位运行模式
            SegmentSelector r_ss    = {}; //堆栈段 0环
            SegmentSelector r_ss_3  = {}; //堆栈段 3环
            SegmentSelector r_ds    = {}; //数据段
            SegmentSelector r_es    = {};
            SegmentSelector r_fs    = {};
            SegmentSelector r_gs    = {};
            r_cs_32.desc            = 0x23;
            r_cs.desc               = 0x33;
            r_ss.desc               = 0x88; //0环
            r_ss_3.desc             = 0x2B;
            r_ds.desc               = 0x2B;
            r_es.desc               = 0x2B;
            r_fs.desc               = 0x53;
            r_gs.desc               = 0x2B;

            r_ss.rpl = 0;

            //r_cs_32.rpl = 0;
            //r_cs.rpl = 0;
            //r_ds.rpl = 0;
            //r_es.rpl = 0;
            //r_fs.rpl = 0;
            //r_gs.rpl = 0;

            m_back_ss = r_ss_3;

            gdtr.base  = m_gdt_address;
            gdtr.limit = 31 * sizeof(struct SegmentDescriptor) - 1;

            init_descriptor(&gdt[r_cs_32.index], 0, 0xfffff000, 1, 3, 0);
            init_descriptor(&gdt[r_cs.index], 0, 0xfffff000, 1, 3, 1);


            init_descriptor(&gdt[r_ss.index], 0, 0xfffff000, 0, 0);
            init_descriptor(&gdt[r_ss_3.index], 0, 0xfffff000, 0, 3);

            init_descriptor(&gdt[r_ds.index], 0, 0xfffff000, 0, 3);
            init_descriptor(&gdt[r_es.index], 0, 0xfffff000, 0, 3);

            init_descriptor(&gdt[r_gs.index], 0, 0xfffff000, 0, 3); //实际上gs段没有用
            init_descriptor(&gdt[r_fs.index], (uint64_t) pTeb, 0xfffff000, 0, 3);

            err = m_VME.sim_uc_mem_map(m_gdt_address, 0x10000, UC_PROT_WRITE | UC_PROT_READ);

            err = m_VME.sim_uc_mem_write(m_gdt_address, gdt, gdtr.limit * sizeof(struct SegmentDescriptor)); //写入GDT段描述表

            err = m_VME.sim_uc_reg_write(UC_X86_REG_GDTR, &gdtr); //写入GDTR寄存器

            // 设置 SS 时，需要 rpl == cpl && dpl == cpl
            // 仿真器从 cpl == 0 开始，因此我们需要 dpl 0 描述符和 rpl 0 选择符
#ifdef _WIN64
            err = m_VME.sim_uc_reg_write(UC_X86_REG_CS, &r_cs);
#else
            err = m_VME.sim_uc_reg_write(UC_X86_REG_CS, &r_cs_32);
#endif
            err = m_VME.sim_uc_reg_write(UC_X86_REG_SS, &r_ss); //0环
            err = m_VME.sim_uc_reg_write(UC_X86_REG_DS, &r_ds);
            err = m_VME.sim_uc_reg_write(UC_X86_REG_ES, &r_es);
            err = m_VME.sim_uc_reg_write(UC_X86_REG_GS, &r_gs);
            err = m_VME.sim_uc_reg_write(UC_X86_REG_FS, &r_fs);

            err = m_VME.sim_uc_reg_write(UC_X86_REG_FS_BASE, &pTeb);
            err = m_VME.sim_uc_reg_write(UC_X86_REG_GS_BASE, &pTeb);

            free(gdt);
        }
    }
    return bSuccess;
}

bool Track::set_mem_context(DWORD process_id, DWORD thread_id) {
    m_process_info.ProcessId = process_id;
    m_process_info.ThreadId  = thread_id;

    if (m_process_info.Process != NULL)
        CloseHandle(m_process_info.Process);
    if (m_process_info.Thread != NULL)
        CloseHandle(m_process_info.Thread);

    HANDLE hProcess        = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    HANDLE hThread         = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
    m_process_info.Process = hProcess;
    m_process_info.Thread  = hThread;

    if (hProcess != NULL && hThread != NULL) {
        uc_mem_region *mem_region       = 0;
        uint32_t       mem_region_count = 0;
        if (m_VME.sim_uc_mem_regions(&mem_region, &mem_region_count) == UC_ERR_OK) {
            for (size_t i = 0; i < mem_region_count; i++) {
                //if (m_gdt_address != mem_region[i].begin)
                {
                    m_VME.sim_uc_mem_unmap(mem_region[i].begin, ALIGN_TO_4KB(mem_region[i].end - mem_region[i].begin));
                }
            }
            m_VME.sim_uc_free(mem_region);
        }

        if (m_handle_hook_mem_unmapped == NULL) {
            m_VME.sim_uc_hook_add(&m_handle_hook_mem_unmapped, UC_HOOK_MEM_UNMAPPED, callback_event_mem_unmapped, this, 1, 0);
        }
        return true;
    }
    if (hProcess != NULL) {
        CloseHandle(hProcess);
        m_process_info.Process = 0;
    }
    if (hThread != NULL) {
        CloseHandle(hThread);
        m_process_info.Thread = 0;
    }

    return false;
}

void Track::set_mem_track_range(bool only, uint64_t addr, uint64_t end) {
    m_enable_track_mem_range = true;
    if (only == true) {
        m_only_range.base = addr;
        m_only_range.end  = end;
    } else {
        TrackMemRange mem_range;
        mem_range.base = addr;
        mem_range.end  = end;

        TrackMemRange *find_mem_range = find_mem_track_range(addr);
        if (find_mem_range == nullptr) {
            m_track_mem_range.push_back(mem_range);
        } else {
            find_mem_range->base = addr;
            find_mem_range->end  = end;
        }
    }
}

TrackMemRange *Track::find_mem_track_range(uint64_t addr) {
    size_t nSize = m_track_mem_range.size();
    for (size_t i = 0; i < nSize; i++) {
        if (m_track_mem_range[i].base <= addr && m_track_mem_range[i].end > addr) {
            return &m_track_mem_range[i];
        }
    }
    return nullptr;
}

uc_err Track::start_track(TrackExitMsg *exit_msg) {
    if (Config::getInstance().getConfig().isDebug) {
        debugFile_.open(Config::getInstance().getConfig().trace_log_path, std::ios::out | std::ios::app);
    }
    uc_err err;
#ifdef _WIN64
    uint64_t lpCip = 0;
    m_VME.sim_uc_reg_read(UC_X86_REG_RIP, &lpCip);
#else
    uint32_t lpCip = 0;
    m_VME.sim_uc_reg_read(UC_X86_REG_EIP, &lpCip);
#endif
    if (m_handle_hook_code_execute == NULL)
        err = m_VME.sim_uc_hook_add(&m_handle_hook_code_execute, UC_HOOK_CODE, callback_evnet_code, this, 1, 0);

    m_exit_msg.exit_code = 0;

    size_t track_num = m_track_insn.size();

    err = m_VME.sim_uc_emu_start(lpCip, NULL, NULL, NULL);

    // write track data to file
    if (Config::getInstance().getConfig().isDebug) {
        if (!debugFile_.is_open()) {
            debugFile_.open(Config::getInstance().getConfig().trace_log_path, std::ios::out | std::ios::app);
        }

        for (const auto &[insn]: m_track_insn) {
            const std::string dis_str = std::format("[0x{:016X}] {:} {:}\n", insn.address, insn.mnemonic, insn.op_str);
            debugFile_.write(dis_str.c_str(), dis_str.size());
        }
        debugFile_.flush();
        debugFile_.close();
    }

    track_num = m_track_insn.size() - track_num;
    _plugin_logprintf("[" PLUGIN_NAME "]: end track");

    m_exit_msg.exit_insn_flags = 0;
    m_exit_msg.track_num       = track_num;
    TrackInsn *track_insn      = get_execute_last_insn();
    if (track_insn != nullptr) {
        m_exit_msg.exit_base = track_insn->insn.address;
        m_exit_msg.next_base = find_next_base(&m_exit_msg.exit_insn_flags);
        m_exit_msg.track_num = track_num;
    } else {
        memset(exit_msg, 0, sizeof(*exit_msg));
    }
    *exit_msg = m_exit_msg;
    return err;
}

TrackInsn *Track::get_execute_last_insn() {
    return m_track_insn.empty() ? nullptr : &(*m_track_insn.rbegin());
}

uint64_t Track::find_next_base(int *insn_flags) {
    uint64_t   nRet       = 0;
    TrackInsn *track_insn = get_execute_last_insn();

    uintptr_t reg_rsp = 0;
    uintptr_t retbase = 0;
    int       flags   = 0;
    if (track_insn != nullptr) {
        switch (track_insn->insn.id) {
            case X86_INS_LJMP: //长跳 x64系统中执行32位程序跳转到wow64的系统调用
            {
                flags = 1;
            }
            case X86_INS_JMP: {
#ifdef _WIN64
                m_VME.sim_uc_reg_read(X86_REG_RSP, &reg_rsp);
#else
                m_VME.sim_uc_reg_read(X86_REG_ESP, &reg_rsp);
#endif
                m_VME.sim_uc_mem_read(reg_rsp, &retbase, sizeof(char *));
                nRet = retbase;
                break;
            }
            case X86_INS_SYSCALL:
            case X86_INS_INT:
            default: {
                nRet = track_insn->insn.address + track_insn->insn.size;
                break;
            }
        }
    }

    if (insn_flags != nullptr)
        insn_flags[0] = flags;
    return nRet;
}

void Track::callback_evnet_code(uc_engine *uc, uint64_t addr, uint32_t size_n, void *user_data) {
    Track *info = (Track *) user_data;

    /*
    * 传入的 size 遇到未识别指令时会错误给予大小 如:monitorx 0F 01 FA
    */
    uc_err   err;
    cs_insn *insn;
    BYTE     code[32];
    uint32_t size = size_n;
    //if (size > sizeof(code))
    size = sizeof(code);

    //下面三个变量会指向下一指令地址,不可使用,
    const uint8_t *Temp_codebase = code;
    size_t         Temp_codesize = size;
    uint64_t       Temp_address  = addr;

    //跟踪范围限定
    if (info->m_enable_track_mem_range) {
        if (info->m_only_range.base != 0) {
            if (!(info->m_only_range.base <= addr && info->m_only_range.end > addr)) {
                info->m_exit_msg.exit_code = 1;
                info->m_VME.sim_uc_emu_stop();
                return;
            }
        } else {
            if (info->find_mem_track_range(addr) == nullptr) {
                info->m_exit_msg.exit_code = 1;
                info->m_VME.sim_uc_emu_stop();
                return;
            }
        }
    }


    //向虚拟机写入3环SS段
    if (info->m_back_ss.desc != 0) {
        info->m_VME.sim_uc_reg_write(UC_X86_REG_SS, &info->m_back_ss);
        info->m_back_ss.desc = 0;
    }

    err = info->m_VME.sim_uc_mem_read(addr, code, size);
    if (err != UC_ERR_OK) {
        info->print_mem_region();
    }
    if (!info->m_VME.disa_cs_disasm_iter(&Temp_codebase, &Temp_codesize, &Temp_address, &insn)) {
        //反汇编出错,停止继续
        MessageBox(NULL, "反汇编出现解析致命错误,停止继续执行.\n", NULL, NULL);
        info->m_VME.sim_uc_emu_stop();
    } else {
        TrackInsn tr_insn;
        tr_insn.insn        = *insn;
        tr_insn.insn.detail = nullptr; //指针为null

        if (info->m_track_insn.size() > Config::getInstance().getConfig().max_trace_num_once) {
            // write track data to file
            if (Config::getInstance().getConfig().isDebug) {
                if (!info->debugFile_.is_open()) {
                    info->debugFile_.open(Config::getInstance().getConfig().trace_log_path, std::ios::out | std::ios::app);
                }

                for (const auto &[insn]: info->m_track_insn) {
                    const std::string dis_str = std::format("[0x{:016X}] {:} {:}\n", insn.address, insn.mnemonic, insn.op_str);
                    info->debugFile_.write(dis_str.c_str(), dis_str.size());
                }
                info->debugFile_.flush();
            }
            info->m_track_insn.clear();
            _plugin_logprintf("track_insn too big, clear :)\n");
        }
        info->m_track_insn.push_back(tr_insn);
    }
}

//映射给定进程的地址范围到虚拟机
bool Track::mem_map_range(uint64_t address) {
    bool   bSuccess = false;
    HANDLE hProcess = m_process_info.Process;
    if (hProcess == nullptr) {
        _plugin_logprintf("Get hProcess failed, GetLastError: %llX\n", GetLastError());
        return bSuccess;
    }
    MEMORY_BASIC_INFORMATION mem_info;
    MEMORY_BASIC_INFORMATION mem_info_1;

    // 先获取 AllocationBase
    if (VirtualQueryEx(hProcess, (LPCVOID) address, &mem_info_1, sizeof(mem_info_1)) == NULL) {
        _plugin_logprintf("VirtualQueryEx failed, GetLastError: %llX\n", GetLastError());
        return bSuccess;
    }

    if (VirtualQueryEx(hProcess, mem_info_1.AllocationBase, &mem_info_1, sizeof(mem_info_1)) == NULL) {
        _plugin_logprintf("VirtualQueryEx failed, GetLastError: %llX\n", GetLastError());
        return bSuccess;
    }
    mem_info = mem_info_1;

    // FIX 映射 gs,fs 段寄存器的时候跳过 ( readprocessmemory 会失败 )
    if (mem_info.BaseAddress == 0) {
        // FIX CRASH WHEN unicorn FETCH EXCEPTION
        // MUST RETURN TRUE TO AVOID THE EXCEPTION
        if (uc_err err;
            err = m_VME.sim_uc_mem_map((uint64_t) mem_info.BaseAddress, 0x1000, UC_PROT_ALL),
            err != UC_ERR_OK) {
            bSuccess = false;
            MessageBox(hwndDlg, std::format("gs/fs uc_mem_map err: {:02x}\n", static_cast<int>(err)).c_str(), PLUGIN_NAME, MB_OK | MB_ICONERROR);
        } else {
            bSuccess = true;
        }
        return bSuccess;
    }
    do {
        // FIX too big!
        if (mem_info.RegionSize > 0x7ffe0000 - 1) {
            bSuccess = false;
            break;
        }
        auto   mem_buffer = std::make_unique<uint8_t[]>(mem_info.RegionSize);
        SIZE_T read_size  = 0;
        if (ReadProcessMemory(hProcess, mem_info.BaseAddress, mem_buffer.get(), mem_info.RegionSize, &read_size)) {
            // _plugin_logprintf("uc_mem_map %llX [%llX]\n", (uintptr_t) mem_info.BaseAddress, mem_info.RegionSize);

            if (uc_err mapRet;
                mapRet = m_VME.sim_uc_mem_map((uintptr_t) mem_info.BaseAddress, mem_info.RegionSize, mem_win_protect_to_uc_protect(mem_info.Protect)),
                mapRet == UC_ERR_OK) {
                if (uc_err writeRet;
                    writeRet = m_VME.sim_uc_mem_write((uintptr_t) mem_info.BaseAddress, mem_buffer.get(), mem_info.RegionSize),
                    writeRet == UC_ERR_OK) {
                    bSuccess = true;
                } else {
                    _plugin_logprintf("uc_mem_map_write err: %d\n", writeRet);
                }
            } else {
                // MessageBox(hwndDlg, std::format("uc_mem_map err: {:02x}\n", (int) mapRet).c_str(), PLUGIN_NAME, MB_OK | MB_ICONERROR);
                _plugin_logprintf("uc_mem_map err: %d\n", mapRet);
            }
        }

        mem_info.BaseAddress = (PVOID) ((uint64_t) mem_info.BaseAddress + mem_info.RegionSize);
        if (VirtualQueryEx(hProcess, mem_info.BaseAddress, &mem_info, sizeof(mem_info)) == NULL)
            break;
        if (mem_info_1.AllocationBase != mem_info.AllocationBase)
            break;
    } while ((uint64_t) mem_info.BaseAddress <= address);

    return bSuccess;
}

bool Track::callback_event_mem_unmapped(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data) {
    bool   bSuccess = false;
    Track *info     = (Track *) user_data;
    switch (type) {
        case UC_MEM_READ:
            break;
        case UC_MEM_WRITE:
            break;
        case UC_MEM_FETCH:
            break;
        case UC_MEM_READ_UNMAPPED:
        case UC_MEM_WRITE_UNMAPPED:
        case UC_MEM_FETCH_UNMAPPED: {
            bSuccess = info->mem_map_range(address);
            break;
        }
        case UC_MEM_WRITE_PROT:
            break;
        case UC_MEM_READ_PROT:
            break;
        case UC_MEM_FETCH_PROT:
            break;
        case UC_MEM_READ_AFTER:
            break;
        default:
            break;
    }
    return bSuccess;
}

void Track::print_mem_region() {
    uc_mem_region *mem_region       = 0;
    uint32_t       mem_region_count = 0;
    if (m_VME.sim_uc_mem_regions(&mem_region, &mem_region_count) == UC_ERR_OK) {
        for (size_t i = 0; i < mem_region_count; i++) {
            _plugin_logprintf("mem_region: %llx %llx %d \r\n", mem_region[i].begin, mem_region[i].end, mem_region[i].perms);
        }
        m_VME.sim_uc_free(mem_region);
    }
}
