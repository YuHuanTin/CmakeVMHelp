
#include "Dbg.h"

#include <format>

#include "src/_plugin_entry.h"

SimulateRegs Dbg::GetRegs() {
    REGDUMP_AVX512 regdump_avx512 = {};
    if (!DbgGetRegDumpEx(&regdump_avx512, sizeof(regdump_avx512))) {
        throw std::runtime_error("failed to get regs");
    }

    auto &regs = regdump_avx512.regcontext;
    return SimulateRegs {
        .cax     = regs.cax,
        .cbx     = regs.cbx,
        .ccx     = regs.ccx,
        .cdx     = regs.cdx,
        .cbp     = regs.cbp,
        .csp     = regs.csp,
        .csi     = regs.csi,
        .cdi     = regs.cdi,
        .r8      = regs.r8,
        .r9      = regs.r9,
        .r10     = regs.r10,
        .r11     = regs.r11,
        .r12     = regs.r12,
        .r13     = regs.r13,
        .r14     = regs.r14,
        .r15     = regs.r15,
        .cip     = regs.cip,
        .flags   = regs.eflags,
        .dr0     = regs.dr0,
        .dr1     = regs.dr1,
        .dr2     = regs.dr2,
        .dr3     = regs.dr3,
        .dr6     = regs.dr6,
        .dr7     = regs.dr7,
        .MxCsr   = regs.MxCsr,
        .gs_base = DbgGetTebAddress(DbgGetThreadId()),
    };
}

std::string Dbg::GetAddrName(size_t addr) {
    SYMBOLINFOCPP symbol;
    if (DbgGetSymbolInfoAt(addr, &symbol) && symbol.decoratedSymbol != nullptr && symbol.decoratedSymbol[0] != '\0') {
        return symbol.undecoratedSymbol != nullptr && symbol.undecoratedSymbol[0] != '\0' ? symbol.undecoratedSymbol : symbol.decoratedSymbol;
    }

    char label[MAX_LABEL_SIZE] = {};
    if (DbgGetLabelAt(addr, SEG_DEFAULT, label) && label[0] != '\0') {
        return label;
    }

    char comment[MAX_COMMENT_SIZE] = {};
    if (DbgGetCommentAt(addr, comment) && comment[0] != '\0') {
        return comment;
    }

    char module[MAX_MODULE_SIZE] = {};
    if (DbgGetModuleAt(addr, module) && module[0] != '\0') {
        return module;
    }

    return {};
}

void Dbg::EnableBpx(size_t addr) {
    switch (DbgGetBpxTypeAt(addr)) {
        case bp_none:      break;
        case bp_normal:    DbgCmdExecDirect(std::format("be 0x{:#x}", addr).c_str()); break; // EnableBPX/bpe/be
        case bp_hardware:  DbgCmdExecDirect(std::format("bphe 0x{:#x}", addr).c_str()); break;
        case bp_memory:    DbgCmdExecDirect(std::format("bpme 0x{:#x}", addr).c_str()); break;
        case bp_dll:       DbgCmdExecDirect(std::format("bpedll 0x{:#x}", addr).c_str()); break;
        case bp_exception: DbgCmdExecDirect(std::format("EnableExceptionBPX 0x{:#x}", addr).c_str()); break;
    }
}

size_t Dbg::RunToAddr(size_t addr) {
    if (DbgGetBpxTypeAt(addr) == BPXTYPE::bp_none) {
        // const auto str = std::format("bp 0x{:016X}, \"runtotarget\", ssshort", addr);
        // DbgCmdExecDirect(str.c_str());

        // auto set bp
        DbgCmdExecDirect(std::format("go 0x{:016x}", addr).c_str());
    } else {
        if (DbgIsBpDisabled(addr)) {
            EnableBpx(addr);
        }
    }
    DbgCmdExecDirect("go");
    _plugin_waituntilpaused();
    return GetRegs().cip;
}

size_t Dbg::StepInto(int count) {
    DbgCmdExecDirect(std::format("sti {}", count).c_str());
    _plugin_waituntilpaused();
    return GetRegs().cip;
}

std::unique_ptr<uint8_t[]> Dbg::MemReadEnhanced(size_t addr, size_t size) {
    if (size == 0) {
        LOG("[%s] failed with size 0 to read", __FUNCTION__)
        return {};
    }
    auto buf = std::make_unique<uint8_t[]>(size);
    std::memset(buf.get(), 0, size);

    // read by xdbg api
    if (DbgMemRead(addr, buf.get(), size)) {
        return buf;
    }
    LOG("DbgMemRead failed, fallback to ReadProcessMemory at 0x%016llx size 0x%016llx", addr, size)

    // read by self
    HANDLE hProcess    = DbgGetProcessHandle();
    size_t currentAddr = addr;

    while (currentAddr < addr + size) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddr), &mbi, sizeof(mbi))) {
            LOG("VirtualQueryEx failed, addr = %llx, err = %lu", currentAddr, GetLastError())
            break;
        }
        const auto chunkSize = mbi.RegionSize;

        // 只有处于已提交状态（MEM_COMMIT）的页面才能进行属性修改和读取
        if (mbi.State != MEM_COMMIT) {
            // 若为 MEM_RESERVE 等未提交页面，Windows 规定无法修改保护，也没有物理内容，保持缓冲区对应位置为 0，直接跳过
            LOG("[MemRead] Address %llx is MEM_RESERVE or other (uncommitted), skipped.", currentAddr);
        } else {
            DWORD oldProtect   = mbi.Protect;
            DWORD dummyProtect = 0;

            // 优化项：为了提升性能与稳定性，如果页面本身已经可读，我们没必要频繁更改属性
            DWORD baseProtect     = mbi.Protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE);
            bool  alreadyReadable = baseProtect == PAGE_READONLY
                                   || baseProtect == PAGE_READWRITE
                                   || baseProtect == PAGE_WRITECOPY
                                   || baseProtect == PAGE_EXECUTE_READ
                                   || baseProtect == PAGE_EXECUTE_READWRITE
                                   || baseProtect == PAGE_EXECUTE_WRITECOPY;
            if (alreadyReadable) {
                SIZE_T bytesRead = 0;
                if (!ReadProcessMemory(hProcess,
                        reinterpret_cast<LPCVOID>(currentAddr),
                        buf.get() + (currentAddr - addr),
                        chunkSize,
                        &bytesRead)) {
                    LOG("ReadProcessMemory failed, addr = %llx, size = %llx, err = %lu", currentAddr, chunkSize, GetLastError());
                }
            } else {
                if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(currentAddr), chunkSize, PAGE_READONLY, &oldProtect)) {
                    LOG("[MemRead] VirtualProtectEx failed on committed page 0x%llx, size = 0x%llx, error = %lu", currentAddr, chunkSize, GetLastError());
                } else {
                    SIZE_T bytesRead = 0;
                    if (!ReadProcessMemory(hProcess,
                            reinterpret_cast<LPCVOID>(currentAddr),
                            buf.get() + (currentAddr - addr),
                            chunkSize,
                            &bytesRead)) {
                        LOG("ReadProcessMemory2 failed, addr = %llx, size = %llx, err = %lu", currentAddr, chunkSize, GetLastError());
                    }
                    VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(currentAddr), chunkSize, oldProtect, &dummyProtect);
                }
            }
        }
        currentAddr += chunkSize;
    }
    return buf;
}

std::pair<size_t, size_t> Dbg::MemFindBaseAddrEnhanced(size_t addr) {
    // size_t size = 0;
    // size_t base = DbgMemFindBaseAddr(addr, &size); // todo, has bug
    // if (base) {
    //     return { base, size };
    // }
    // LOG("DbgMemFindBaseAddr query addr 0x%016llx base = 0, using fallback VirtualQueryEx", addr);

    HANDLE hProcess = DbgGetProcessHandle();

    MEMORY_BASIC_INFORMATION mbi = {};
    if (!VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        throw std::runtime_error(std::format("bad VirtualQueryEx call with addr: 0x{:016x}, err = {}", addr, GetLastError()));
    }

    const auto regionBase = reinterpret_cast<size_t>(mbi.BaseAddress);
    const auto regionEnd  = regionBase + mbi.RegionSize;

    LOG("[%s] regionBase = %016llx, regionEnd = %016llx, size = %016llx", __FUNCTION__, regionBase, regionEnd, mbi.RegionSize);

    return { regionBase, 0x1000 };
}
