#include "Uc.h"

#include <array>

#include "src/_plugin_entry.h"

#ifdef _WIN64
constexpr int kRegIds[] = {
    UC_X86_REG_RAX,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RBP,
    UC_X86_REG_RSP,
    UC_X86_REG_RSI,
    UC_X86_REG_RDI,

    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,

    UC_X86_REG_RIP,
    UC_X86_REG_RFLAGS,

    UC_X86_REG_DR0,
    UC_X86_REG_DR1,
    UC_X86_REG_DR2,
    UC_X86_REG_DR3,
    UC_X86_REG_DR6,
    UC_X86_REG_DR7,

    UC_X86_REG_MXCSR,
    UC_X86_REG_GS_BASE,
};

auto BuildRegPtrs(SimulateRegs &regs) {
    return std::array<void *, std::size(kRegIds)> {
        &regs.cax,
        &regs.cbx,
        &regs.ccx,
        &regs.cdx,
        &regs.cbp,
        &regs.csp,
        &regs.csi,
        &regs.cdi,

        &regs.r8,
        &regs.r9,
        &regs.r10,
        &regs.r11,
        &regs.r12,
        &regs.r13,
        &regs.r14,
        &regs.r15,

        &regs.cip,
        &regs.flags,

        &regs.dr0,
        &regs.dr1,
        &regs.dr2,
        &regs.dr3,
        &regs.dr6,
        &regs.dr7,

        &regs.MxCsr,
        &regs.gs_base,
    };
}
#else
constexpr int kRegIds[] = {
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,

    UC_X86_REG_EIP,
    UC_X86_REG_EFLAGS,

    UC_X86_REG_DR0,
    UC_X86_REG_DR1,
    UC_X86_REG_DR2,
    UC_X86_REG_DR3,
    UC_X86_REG_DR6,
    UC_X86_REG_DR7,

    UC_X86_REG_MXCSR,
    // todo, ? maybe fs
};

auto BuildRegPtrs(SimulateRegs &regs) {
    return std::array<void *, std::size(kRegIds)> {
        &regs.cax,
        &regs.cbx,
        &regs.ccx,
        &regs.cdx,
        &regs.cbp,
        &regs.csp,
        &regs.csi,
        &regs.cdi,

        &regs.cip,
        &regs.flags,

        &regs.dr0,
        &regs.dr1,
        &regs.dr2,
        &regs.dr3,
        &regs.dr6,
        &regs.dr7,

        &regs.MxCsr,
    };
}
#endif

SimulateRegs Uc::GetRegs(uc_engine *uc) {
    SimulateRegs regs {};
    auto         ptrs = BuildRegPtrs(regs);

    auto err = uc_reg_read_batch(uc, kRegIds, ptrs.data(), ptrs.size());
    if (err != UC_ERR_OK) {
        LOG("%s failed with %s", __FUNCTION__, uc_strerror(err));
    }
    return regs;
}

bool Uc::WriteReg(uc_engine *uc, SimulateRegs &regs) {
    auto ptrs = BuildRegPtrs(regs);

    auto err = uc_reg_write_batch(uc, kRegIds, ptrs.data(), ptrs.size());
    if (err != UC_ERR_OK) {
        LOG("%s failed with %s", __FUNCTION__, uc_strerror(err));
        return false;
    }
    return true;
}
