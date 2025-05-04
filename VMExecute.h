#pragma once
#define READ_QWORD(x) ((uint64_t)x)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_WORD(x) (x & 0xffff)
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)
#define WRITE_DWORD(x, w) (x = (x & ~0xffffffffLL) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | ((b & 0xff) << 8))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))

struct _reg_eflags {
    union {
        struct {
            uintptr_t cf       : 1; //!< [0] [进位标志] 当其被设置时表示运算结果的最高有效位发生进位或借位的情况,并在无符号整数的运算中表示运算的溢出状态.
            uintptr_t reserved1: 1;
            uintptr_t pf       : 1; //!< [2] [奇偶校验标志] 当其被设置表示结果中包含偶数个值为1的位，否则表示结果中包含奇数个值为1的位.
            uintptr_t reserved2: 1;
            uintptr_t af       : 1; //!< [4] [辅助进位标志] 当其被设置表示在算术运算中低三位发生进位或借位（例如AL向AH进位或借位）或BCD码算术运算中发生进位或借位的情况.
            uintptr_t reserved3: 1;
            uintptr_t zf       : 1; //!< [6] [零标志] 当其被设置时运算的结果是否等于0,否则不等于0.
            uintptr_t sf       : 1; //!< [7] [符号标志] 当其被设置时表示结果为负数,否则为正数.
            uintptr_t tf       : 1; //!< [8] [陷阱标志] 将该位设置为1以允许单步调试模式,清零则禁用该模式.
            uintptr_t b_if     : 1; //!< [9] [中断标志] 当其被设置时表示CPU可响应可屏蔽中断
            uintptr_t df       : 1; //!< [10] [方向标志] 这个方向标志(位于EFLAGS寄存器的第10位)控制串指令
            uintptr_t of       : 1; //!< [11] [溢出标志] 当其被设置时代表运算结果溢出,即结果超出了能表达的最大范围.
            uintptr_t iopl     : 2; //!< [12:13] [I/O特权级别标志] 表示当其程序或任务的I/O权限级别.I/O权限级别为0～3范围之间的值,通常一般用户程序I/O特权级别为0.当前运行程序的CPL（current privilege level）必须小于等于IOPL,否则将发生异常.
            uintptr_t nt       : 1; //!< [14] [嵌套任务] 用于控制中断返回指令IRET的执行方式.若被设置则将通过中断的方式执行返回,否则通过常规的堆栈的方式执行.在执行CALL指令,中断或异常处理时,处理器将会设置该标志.
            uintptr_t reserved4: 1;
            uintptr_t rf       : 1; //!< [16] [恢复标志] 用于控制处理器对调试异常的响应.若其被设置则会暂时禁止断点指令产生的调试异常,其复位后断点指令将会产生异常.
            uintptr_t vm       : 1; //!< [17] [虚拟8086模式标志] 当其被设置表示启用虚拟8086模式（在保护模式下模拟实模式）,否则退回到保护模式工作.
            uintptr_t ac       : 1; //!< [18] [对齐检查标志] 当该标志位被设置且CR0寄存器中的AM位被设置时,将对用户态下对内存引用进行对齐检查,在存在未对齐的操作数时产生异常.
            uintptr_t vif      : 1; //!< [19] [虚拟中断标志] 为IF标志的虚拟映象.该标志与VIP标志一起,且在CR4寄存器中VME或PVI位被设置且IOPL小于3时,处理器才将识别该标志.
            uintptr_t vip      : 1; //!< [20] [虚拟中断挂起标志] 其被设置表示有一个中断被挂起(等待处理),否则表示没有等待处理的中断.该标志通常与VIF标志搭配一起使用.
            uintptr_t id       : 1; //!< [21] [ID标志] 通过修改该位的值可以测试是否支持CPUID指令.
#ifdef _WIN64
            uintptr_t reserved5: 42;
#else
#endif
        };

        uintptr_t all;
    };
};

struct REGS {
    struct {
        uint64_t    pax;
        uint64_t    pcx;
        uint64_t    pdx;
        uint64_t    pbx;
        uint64_t    psp;
        uint64_t    pbp;
        uint64_t    psi;
        uint64_t    pdi;
        uint64_t    r8;
        uint64_t    r9;
        uint64_t    r10;
        uint64_t    r11;
        uint64_t    r12;
        uint64_t    r13;
        uint64_t    r14;
        uint64_t    r15;
        uint64_t    pip;
        _reg_eflags uEflags;
    } regs;
};

class VMExecute {
public:
    VMExecute() {
        m_uc        = 0;
        m_cs_handle = 0;
        m_cs_insn   = 0;
    }

    ~VMExecute() {
        if (m_uc != NULL) {
            uc_close(m_uc);
        }
        if (m_cs_insn != NULL) {
            cs_free(m_cs_insn, 1);
        }
        if (m_cs_handle != NULL) {
            cs_close(&m_cs_handle);
        }
    }

    /*
        初始化模拟器引擎与反汇编解析引擎
        arch:CPU 架构
        mode:CPU 解码模式
    */
    bool Init(uc_arch nUc_arch, uc_mode nUc_mode, cs_arch nCs_arch, cs_mode nCS_mode) {
        bool   bRet = false;
        uc_err err  = uc_open(nUc_arch, nUc_mode, &m_uc);
        _plugin_logprintf("log: uc_open result = %d\n", err);
        if (err == UC_ERR_OK) {
            cs_err nCs_err = cs_open(nCs_arch, nCS_mode, &m_cs_handle);
            _plugin_logprintf("log: cs_open result = %d\n", nCs_err);
            if (nCs_err == CS_ERR_OK) {
                //提前申请一条指令信息储存空间
                m_cs_insn = disa_cs_malloc();

                bRet = true;
            }
        }
        return bRet;
    }

    /**************************************************************************
    ***************************************************************************
                                模拟器函数										
    ***************************************************************************
    ***************************************************************************/

    /*
        开始模拟执行
        @begin: 开始模拟的地址
        @until: 模拟停止的地址 (当到达该地址时)
        @timeout: 模拟代码的持续时间(以微秒计)。当这个值为0时，将无时间限制模拟代码，直到模拟完成。
        @count: 要模拟的指令数。当这个值为0时，将模拟所有可执行的代码，直到模拟完成
    */
    uc_err sim_uc_emu_start(uint64_t begin, uint64_t until, uint64_t timeout, size_t count) {
        return uc_emu_start(m_uc, begin, until, timeout, count);
    }

    /*
        停止模拟执行
    */
    uc_err sim_uc_emu_stop() {
        return uc_emu_stop(m_uc);
    }

    /*
        映射创建一段内存到模拟器环境,只进行映射不对其写入内容
        @address:要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回UC_ERR_ARG错误。
        @size:要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回UC_ERR_ARG错误。
        @perms:新映射区域的权限。参数必须是UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC或这些的
组合，否则返回UC_ERR_ARG错误。

    */
    uc_err sim_uc_mem_map(uint64_t address, size_t size, uint32_t perms) {
        return uc_mem_map(m_uc, address, size, perms);
    }

    /*
        映射创建一段内存到模拟器环境,并且将ptr主机内存区域的数据进行拷贝
        @ptr: 指向支持新映射内存的主机内存的指针。映射的主机内存的大小应该与size的大小相同或更大，并且
        至少使用PROT_READ | PROT_WRITE进行映射，否则不定义映射。

    */
    uc_err sim_uc_mem_map_ptr(uint64_t address, size_t size, uint32_t perms, void *ptr) {
        return uc_mem_map_ptr(m_uc, address, size, perms, ptr);
    }

    /*
        取消映射内存
        @address: 要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回UC_ERR_ARG错误。
        @size: 要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回UC_ERR_ARG错误。

    */
    uc_err sim_uc_mem_unmap(uint64_t address, size_t size) {
        return uc_mem_unmap(m_uc, address, size);
    }

    /*
        修改已经映射的内存的保护属性
        @address: 要映射到的新内存区域的起始地址。这个地址必须与4KB对齐，否则将返回UC_ERR_ARG错误。
        @size: 要映射到的新内存区域的大小。这个大小必须是4KB的倍数，否则将返回UC_ERR_ARG错误。
        @perms: 映射区域的新权限。参数必须是UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC或这些的
        组合，否则返回UC_ERR_ARG错误。
    */
    uc_err sim_uc_mem_protect(uint64_t address, size_t size, uint32_t perms) {
        return uc_mem_protect(m_uc, address, size, perms);
    }

    /*
        检索由 uc_mem_map() 和 uc_mem_map_ptr() 映射的内存的信息。
        这个API为@regions分配内存，用户之后必须通过free()释放这些内存来避免内存泄漏。
        @regions: 指向 uc_mem_region 结构体的数组的指针. 由Unicorn申请，必须通过uc_free()释放这些内存
        @count: 指向@regions中包含的uc_mem_region结构体的数量的指针
    */
    uc_err sim_uc_mem_regions(uc_mem_region **regions, uint32_t *count) {
        return uc_mem_regions(m_uc, regions, count);
    }

    /*
        释放由模拟器申请的内存
        @mem: 由 uc_mem_regions (返回 *regions)申请的内存
    */
    uc_err sim_uc_free(void *mem) {
        return uc_free(mem);
    }

    /*
        从模拟器中读取内存
    */
    uc_err sim_uc_mem_read(uint64_t address, void *bytes, size_t size) {
        return uc_mem_read(m_uc, address, bytes, size);
    }

    /*
        从模拟器中写入内存
    */
    uc_err sim_uc_mem_write(uint64_t address, void *bytes, size_t size) {
        return uc_mem_write(m_uc, address, bytes, size);
    }

    /*
        对寄存器写入值
        @regid:如 UC_X86_REG_ECX
        @value: 指向保存寄存器值的指针
    */
    uc_err sim_uc_reg_write(int regid, const void *value) {
        return uc_reg_write(m_uc, regid, value);
    }

    /*
        读入寄存器值
        @regid:如 UC_X86_REG_ECX
        @value: 指向保存寄存器值的指针

    */
    uc_err sim_uc_reg_read(int regid, void *value) {
        return uc_reg_read(m_uc, regid, value);
    }

    /*
        添加HOOK回调
        @hh: 注册hook得到的句柄. uc_hook_del() 中使用
        @type: hook 类型   UC_HOOK_CODE
        @callback: 当指令被命中时要运行的回调
        @user_data: 用户自定义数据. 将被传递给回调函数的最后一个参数 @user_data
        @begin: 回调生效区域的起始地址(包括)
        @end: 回调生效区域的结束地址(包括)
        注意 1: 只有回调的地址在[@begin, @end]中才会调用回调
        注意 2: 如果 @begin > @end, 每当触发此hook类型时都会调用回调
        @...: 变量参数 (取决于 @type)
        注意: 如果 @type = UC_HOOK_INSN, 这里是指令ID (如: UC_X86_INS_OUT)
    */
    template<typename... Args>
    uc_err sim_uc_hook_add(uc_hook *hh, int type, void *callback, void *user_data, uint64_t begin, uint64_t end, Args &&... args) {
        return uc_hook_add(m_uc, hh, type, callback, user_data, begin, end, std::forward<Args>(args)...);
    }

    /*
        删除HOOK回调
        @hh: uc_hook_add() 返回的句柄
    */
    uc_err sim_uc_hook_del(uc_engine *uc, uc_hook hh) {
        return uc_hook_del(m_uc, hh);
    }

    /*
        控制发动机内部状态。
        请参见uc_ctl_ * 宏帮助程序以方便使用。
        uc_open()返回句柄
        @control:控件类型。
        @args : 参见uc_control_type了解可变参数的详细信息。 uc_ctl_flush_tlb() 使TB缓存无效
        @return: uc_err枚举类型的错误代码(UC_ERR_ * ，见上文)
    */
    template<typename... Args>
    uc_err sim_uc_ctl(uc_control_type control, Args &&... args) {
        return uc_ctl(m_uc, control, std::forward<Args>(args)...);
    }

    /*
        动态查询硬件模式
    */
    uc_err sim_uc_query(uc_query_type type, size_t *result) {
        return uc_query(m_uc, type, result);
    }

    /*
        查询上一个模拟器API的错误号
    */
    uc_err sim_uc_errno() {
        return uc_errno(m_uc);
    }

    /*
        根据错误号获得字符串解释
    */
    const char *sim_uc_strerror(uc_err code) {
        return uc_strerror(code);
    }


    /**************************************************************************
    ***************************************************************************
                            反汇编函数
    ***************************************************************************
    ***************************************************************************/
    /*
        cs_option
        设置反汇编引擎解析选项

    */
    cs_err disa_cs_option(cs_opt_type type, size_t value) {
        cs_err err = cs_option(m_cs_handle, type, value);
        if (err == CS_ERR_OK && m_cs_insn != NULL) {
            //重新申请一份,防止设置选项后,导致空间不足的问题
            disa_cs_free(m_cs_insn, 1);
            m_cs_insn = disa_cs_malloc();
        }
        return err;
    }

    /*
        反汇编
        @code: 包含要反汇编的机器码的缓冲区。
        @code_size:上面代码缓冲区的大小。
        @address:给定原始代码缓冲区中的第一条指令的地址。
        @insn: 由这个API填写的指令数组。注意: insn将由这个函数分配，应该用cs_free () API释放
        @count: 需要分解的指令数量，或输入0分解所有指令
        @return:成功反汇编指令的数量，如果该函数未能反汇编给定的代码，则为0，失败时，调用cs_errno()获取错误代码。
    */
    size_t disa_cs_disasm(const uint8_t *code, size_t code_size, uint64_t address, size_t count, cs_insn **insn) {
        return cs_disasm(m_cs_handle, code, code_size, address, count, insn);
    }

    /*
        反汇编单条指令 [快速]
        @code: 要反汇编的机器码所在的缓冲区
        @size: 机器码缓冲区的大小
        @address: 所给机器码缓冲区中第一个insn的地址
        @insn: 指向这个API要填充的指令的指针。
        @return:如果这个API成功反汇编了一条指令返回true，否则将返回false。

        注意1： 此API将更新code、size和address以指向输入缓冲区中的下一条指令。
        所以，虽然每次反汇编一条指令可以使用cs_disasm（count=1）来实现，但一些基准测试显示，在循环中使用cs_disasm_iter（）可以方便地快速迭代所有指令，在随机输入时可以快30%。
    */
    bool disa_cs_disasm_iter(const uint8_t **code, size_t *size, uint64_t *address, cs_insn **insn) {
        *insn = m_cs_insn;
        return cs_disasm_iter(m_cs_handle, code, size, address, m_cs_insn);
    }

    /*
        被用于在API cs_disasm_iter（）中为一条指令分配内存
    */
    cs_insn *disa_cs_malloc() {
        return cs_malloc(m_cs_handle);
    }

    /*
        @insn: 由cs_disasm()或cs_malloc()中的@insn参数返回的指针
        @count: 赋值由cs_disasm()返回的cs_insn结构的数量，或赋值为1表示由cs_malloc()分配给空闲内存的数量
    */
    void disa_cs_free(cs_insn *insn, size_t count) {
        cs_free(insn, count);
    }


    /**************************************************************************
    ***************************************************************************
                            反汇编解析函数
    ***************************************************************************
    ***************************************************************************/

    bool regs_get(REGS &regs, int regid) {
        if (regid != x86_reg::X86_REG_INVALID) {
            /*
            X86_REG_RAX,
    X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX,
    X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_SI,
    X86_REG_SIL, X86_REG_SP, X86_REG_SPL, 
            */
            /*
    X86_REG_INVALID = 0,
    X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_BH, X86_REG_BL,
    X86_REG_BP, X86_REG_BPL, X86_REG_BX, X86_REG_CH, X86_REG_CL,
    X86_REG_CS, X86_REG_CX, X86_REG_DH, X86_REG_DI, X86_REG_DIL,
    X86_REG_DL, X86_REG_DS, X86_REG_DX, X86_REG_EAX, X86_REG_EBP,
    X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX, X86_REG_EFLAGS,
    X86_REG_EIP, X86_REG_EIZ, X86_REG_ES, X86_REG_ESI, X86_REG_ESP,
    X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_IP, X86_REG_RAX,
    X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX,
    X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_SI,
    X86_REG_SIL, X86_REG_SP, X86_REG_SPL, X86_REG_SS, X86_REG_CR0,
    X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5,
    X86_REG_CR6, X86_REG_CR7, X86_REG_CR8, X86_REG_CR9, X86_REG_CR10,
    X86_REG_CR11, X86_REG_CR12, X86_REG_CR13, X86_REG_CR14, X86_REG_CR15,
    X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4,
    X86_REG_DR5, X86_REG_DR6, X86_REG_DR7, X86_REG_DR8, X86_REG_DR9,
    X86_REG_DR10, X86_REG_DR11, X86_REG_DR12, X86_REG_DR13, X86_REG_DR14,
    X86_REG_DR15, X86_REG_FP0, X86_REG_FP1, X86_REG_FP2, X86_REG_FP3,
    X86_REG_FP4, X86_REG_FP5, X86_REG_FP6, X86_REG_FP7,
    X86_REG_K0, X86_REG_K1, X86_REG_K2, X86_REG_K3, X86_REG_K4,
    X86_REG_K5, X86_REG_K6, X86_REG_K7, X86_REG_MM0, X86_REG_MM1,
    X86_REG_MM2, X86_REG_MM3, X86_REG_MM4, X86_REG_MM5, X86_REG_MM6,
    X86_REG_MM7, X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11,
    X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
    X86_REG_ST0, X86_REG_ST1, X86_REG_ST2, X86_REG_ST3,
    X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, X86_REG_ST7,
    X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3, X86_REG_XMM4,
    X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7, X86_REG_XMM8, X86_REG_XMM9,
    X86_REG_XMM10, X86_REG_XMM11, X86_REG_XMM12, X86_REG_XMM13, X86_REG_XMM14,
    X86_REG_XMM15, X86_REG_XMM16, X86_REG_XMM17, X86_REG_XMM18, X86_REG_XMM19,
    X86_REG_XMM20, X86_REG_XMM21, X86_REG_XMM22, X86_REG_XMM23, X86_REG_XMM24,
    X86_REG_XMM25, X86_REG_XMM26, X86_REG_XMM27, X86_REG_XMM28, X86_REG_XMM29,
    X86_REG_XMM30, X86_REG_XMM31, X86_REG_YMM0, X86_REG_YMM1, X86_REG_YMM2,
    X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, X86_REG_YMM7,
    X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, X86_REG_YMM12,
    X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, X86_REG_YMM16, X86_REG_YMM17,
    X86_REG_YMM18, X86_REG_YMM19, X86_REG_YMM20, X86_REG_YMM21, X86_REG_YMM22,
    X86_REG_YMM23, X86_REG_YMM24, X86_REG_YMM25, X86_REG_YMM26, X86_REG_YMM27,
    X86_REG_YMM28, X86_REG_YMM29, X86_REG_YMM30, X86_REG_YMM31, X86_REG_ZMM0,
    X86_REG_ZMM1, X86_REG_ZMM2, X86_REG_ZMM3, X86_REG_ZMM4, X86_REG_ZMM5,
    X86_REG_ZMM6, X86_REG_ZMM7, X86_REG_ZMM8, X86_REG_ZMM9, X86_REG_ZMM10,
    X86_REG_ZMM11, X86_REG_ZMM12, X86_REG_ZMM13, X86_REG_ZMM14, X86_REG_ZMM15,
    X86_REG_ZMM16, X86_REG_ZMM17, X86_REG_ZMM18, X86_REG_ZMM19, X86_REG_ZMM20,
    X86_REG_ZMM21, X86_REG_ZMM22, X86_REG_ZMM23, X86_REG_ZMM24, X86_REG_ZMM25,
    X86_REG_ZMM26, X86_REG_ZMM27, X86_REG_ZMM28, X86_REG_ZMM29, X86_REG_ZMM30,
    X86_REG_ZMM31, X86_REG_R8B, X86_REG_R9B, X86_REG_R10B, X86_REG_R11B,
    X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B, X86_REG_R8D,
    X86_REG_R9D, X86_REG_R10D, X86_REG_R11D, X86_REG_R12D, X86_REG_R13D,
    X86_REG_R14D, X86_REG_R15D, X86_REG_R8W, X86_REG_R9W, X86_REG_R10W,
    X86_REG_R11W, X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,
    X86_REG_BND0, X86_REG_BND1, X86_REG_BND2, X86_REG_BND3,

    X86_REG_ENDING		// <-- mark the end of the list of registers
            */
        }
    }

    /*
        解析操作数,获取地址
        注意 x86_reg::X86_REG_AH -> x86_reg::X86_REG_DR15
        范围会写值最大为: uint64_t  但是FPP YMM XMM 宽度很大,请自行判断使用
        
    */
    bool disa_sim_parse_operands(cs_x86_op &operands,__out void *val) {
        bool bRet = false;
        switch (operands.type) {
            case x86_op_type::X86_OP_REG: {
                if (sim_uc_reg_read(operands.reg, val) == UC_ERR_OK) {
                    bRet = true;
                }
                break;
            }
            case x86_op_type::X86_OP_IMM: {
                *(int64_t *) val = operands.imm;
                bRet             = true;
                break;
            }
            case x86_op_type::X86_OP_MEM: {
                uint64_t base         = 0;
                uint64_t index_base   = 0;
                uint64_t segment_base = 0;
                if (operands.mem.segment != x86_reg::X86_REG_INVALID) {
                    if (sim_uc_reg_read(operands.mem.segment, &segment_base) != UC_ERR_OK) {
                        __debugbreak();
                    }
                }
                if (operands.mem.base != x86_reg::X86_REG_INVALID) {
                    if (sim_uc_reg_read(operands.mem.index, &index_base) != UC_ERR_OK) {
                        __debugbreak();
                    }
                }
                *(int64_t *) val = base + index_base * (int64_t) operands.mem.scale + (int64_t) operands.mem.disp;
                bRet             = true;
                break;
            }
            default:
                break;
        }
        return bRet;
    }

    uc_engine *m_uc;        //模拟器引擎实例
    csh        m_cs_handle; //汇编解析引擎句柄
    cs_insn *  m_cs_insn;   //默认申请一条指令解析空间
private:
};
