//
// Created by YuHuanTin on 2026/5/18.
//

#include "Engine.h"

#include "_plugin_entry.h"
#include "utils/Dbg.h"
#include "utils/Uc.h"

void EmuEngine::run(StopReason stopReason) {
    stopReason_ = stopReason;

    // todo verify this
    uint64_t until = 0;
    if (stopReason == REACHED_CALL_FINISH) {
        const auto regs = Dbg::GetRegs();
        if (!DbgMemRead(regs.csp, &until, sizeof(until))) {
            until = 0;
        }
    }

    for (;;) {
        const auto regs = Dbg::GetRegs();

        emuStopAddr_   = 0;
        emuExitReason_ = NORMAL;

        auto [regionBase, regionSize] = Dbg::MemFindBaseAddrEnhanced(regs.cip);
        runRegionBase_                = regionBase;
        runRegionEnd_                 = regionBase + regionSize;

        hostRegToEmu();
        hostBasicMemToEmu(regs.cip, regs.csp);

        // hook
        uc_hook hookCodeHandle       = 0;
        uc_hook hookSyscallHandle    = 0;
        uc_hook hookMemValidHandle   = 0;
        uc_hook hookMemInvalidHandle = 0;

        auto err = uc_hook_add(uc_, &hookCodeHandle, UC_HOOK_CODE, reinterpret_cast<void *>(hookCode), this, 1, 0);
        if (err != UC_ERR_OK) {
            LOG("uc_hook_add code failed with %s", uc_strerror(err))
        }

        err = uc_hook_add(uc_, &hookSyscallHandle, UC_HOOK_INSN, reinterpret_cast<void *>(hookSyscall), this, 1, 0, UC_X86_INS_SYSCALL);
        if (err != UC_ERR_OK) {
            LOG("uc_hook_add syscall failed with %s", uc_strerror(err))
        }

        err = uc_hook_add(uc_, &hookMemValidHandle, UC_HOOK_MEM_VALID, reinterpret_cast<void *>(hookMemValid), this, 1, 0);
        if (err != UC_ERR_OK) {
            LOG("uc_hook_add mem valid failed with %s", uc_strerror(err))
        }

        err = uc_hook_add(uc_, &hookMemInvalidHandle, UC_HOOK_MEM_INVALID, reinterpret_cast<void *>(hookMemInvalid), this, 1, 0);
        if (err != UC_ERR_OK) {
            LOG("uc_hook_add mem invalid failed with %s", uc_strerror(err))
        }

        // run
        LOG("[run-start] cip = 0x%016llx, csp = 0x%016llx", regs.cip, regs.csp)
        err = uc_emu_start(uc_, regs.cip, until, 0, 0);
        // refreshing last code
        traceLogger_.flush(Uc::GetRegs(uc_));
        if (err != UC_ERR_OK && emuExitReason_ == NORMAL) {
            LOG("uc_emu_start failed with %s", uc_strerror(err))
        }

        if (hookCodeHandle != 0) {
            uc_hook_del(uc_, hookCodeHandle);
        }
        if (hookSyscallHandle != 0) {
            uc_hook_del(uc_, hookSyscallHandle);
        }
        if (hookMemValidHandle != 0) {
            uc_hook_del(uc_, hookMemValidHandle);
        }
        if (hookMemInvalidHandle != 0) {
            uc_hook_del(uc_, hookMemInvalidHandle);
        }

        unmapAllRegions();

        if (emuStopAddr_ != 0) {
            LOG("switch to debugger, goto 0x%016llx", emuStopAddr_)
            uint64_t dbgStopAddr = Dbg::RunToAddr(emuStopAddr_);
            if (dbgStopAddr != emuStopAddr_) {
                LOG("failed to run to syscall address, expected 0x%016llx, got 0x%016llx", emuStopAddr_, dbgStopAddr)
                break;
            }
        }
        if (emuExitReason_ == SYSCALL) {
            traceLogger_.record(emuStopAddr_, "<before call>", "syscall", Dbg::GetRegs());
            const auto nextAddr = Dbg::StepInto();
            LOG("stepinto syscall, current cip = 0x%016llx", nextAddr)
            continue;
        }
        return;
    }
}

void EmuEngine::run(StopReason stopReason, const std::string &instTarget) {
    inst_target_ = instTarget;
    this->run(stopReason);
}

void EmuEngine::hookCode(uc_engine *uc, uint64_t address, uint32_t size, void *userData) {
    auto *engine = static_cast<EmuEngine *>(userData);
    if (engine == nullptr) {
        return;
    }
    const auto currentRegs = Uc::GetRegs(uc);
    engine->traceLogger_.flush(currentRegs);

    uint8_t code[32] = {};
    auto    readErr  = uc_mem_read(uc, address, code, size);
    if (readErr != UC_ERR_OK) {
        LOG("uc_mem_read instruction failed at %llx with %s", address, uc_strerror(readErr))
        return;
    }

    cs_insn *insn  = nullptr;
    auto     count = cs_disasm(engine->cs_, code, size, address, 1, &insn);
    if (count == 0) {
        LOG("[cs] failed to disasm code at: 0x%llx, with size: %d", address, size)
        uc_emu_stop(uc);
        return;
    }

    engine->traceLogger_.record(insn[0].address, insn[0].mnemonic, insn[0].op_str, currentRegs);

    switch (engine->stopReason_) {
        case PAGE_SWITCH:
            if (!(engine->runRegionBase_ <= address && address < engine->runRegionEnd_)) {
                engine->emuStopAddr_ = address;
                uc_emu_stop(uc);
            }
            break;
        case REACHED_BP:
            // 注意，只有断点启用时，才会有 type，否则不启用为 bp_none
            if (DbgGetBpxTypeAt(address) != bp_none) {
                engine->emuStopAddr_ = address;
                uc_emu_stop(uc);
            }
            break;
        case REACHED_INST:
            if (!engine->inst_target_.empty() && engine->inst_target_ == insn[0].mnemonic) {
                engine->emuStopAddr_ = address;
                uc_emu_stop(uc);
            }
            break;
        case REACHED_CALL_FINISH:
            break;
        default:
            break;
    }
    cs_free(insn, count);
}

void EmuEngine::hookSyscall(uc_engine *uc, void *userData) {
    auto *engine = static_cast<EmuEngine *>(userData);
    if (engine == nullptr) {
        return;
    }

    const auto regs        = Uc::GetRegs(uc);
    engine->emuStopAddr_   = regs.cip;
    engine->emuExitReason_ = SYSCALL;
    uc_emu_stop(uc);
}

void EmuEngine::hookMemValid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *userData) {
    (void)uc;
    (void)type;
    (void)address;
    (void)size;
    (void)value;
    (void)userData;
}

bool EmuEngine::hookMemInvalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *userData) {
    (void)uc;
    (void)type;
    (void)size;
    (void)value;

    auto *engine = static_cast<EmuEngine *>(userData);
    if (engine == nullptr) {
        return false;
    }

    try {
        auto [pageBase, pageSize] = Dbg::MemFindBaseAddrEnhanced(address);
        engine->hostPageToEmu(pageBase, pageSize);
        return true;
    } catch (const std::exception &e) {
        LOG("hookMemInvalid failed at %llx with err '%s'", address, e.what())
        return false;
    }
}

void EmuEngine::hostBasicMemToEmu(size_t cip, size_t sp) {
    size_t teb                = DbgGetTebAddress(DbgGetThreadId());
    auto [teb_base, teb_size] = Dbg::MemFindBaseAddrEnhanced(teb);

    LOG("teb = %llx", teb)
    LOG("teb_base = %llx", teb_base)
    LOG("teb_size = %llx", teb_size)

    auto [cip_base, cip_size] = Dbg::MemFindBaseAddrEnhanced(cip);
    auto [sp_base, sp_size]   = Dbg::MemFindBaseAddrEnhanced(sp);
    hostPageToEmu(cip_base, cip_size);
    hostPageToEmu(sp_base, sp_size);
    hostPageToEmu(teb_base, teb_size);
}

void EmuEngine::hostPageToEmu(std::size_t pageBase, std::size_t pageSize) {
    LOG("[page-map] 0x%llx with size 0x%llx", pageBase, pageSize)
    const auto buf = Dbg::MemReadEnhanced(pageBase, pageSize);

    auto uc_err = uc_mem_map(uc_, pageBase, pageSize, UC_PROT_ALL);
    if (uc_err != UC_ERR_OK) {
        LOG("uc_mem_map failed with %s", uc_strerror(uc_err))
    }

    uc_err = uc_mem_write(uc_, pageBase, buf.get(), pageSize);
    if (uc_err != UC_ERR_OK) {
        LOG("uc_mem_write failed with %s", uc_strerror(uc_err))
    }
}

void EmuEngine::unmapAllRegions() {
    uc_mem_region *regions = nullptr;
    uint32_t       count   = 0;

    const auto err = uc_mem_regions(uc_, &regions, &count);
    if (err != UC_ERR_OK) {
        LOG("uc_mem_regions failed with %s", uc_strerror(err))
        return;
    }

    for (uint32_t i = 0; i < count; ++i) {
        const auto begin = regions[i].begin;
        const auto size  = regions[i].end - regions[i].begin + 1;
        const auto ret   = uc_mem_unmap(uc_, begin, size);
        if (ret != UC_ERR_OK) {
            LOG("uc_mem_unmap failed at %llx with %s", begin, uc_strerror(ret))
        }
    }
    uc_free(regions);
}

void EmuEngine::hostRegToEmu() {
    auto reg = Dbg::GetRegs();
    reg.flags &= ~0x100ull; // disable TF flag

    Uc::WriteReg(uc_, reg);
}

bool init_engine() {
    auto uc_err = uc_open(UC_ARCH_X86, UC_MODE_64, &gEngine.uc_);
    if (uc_err != UC_ERR_OK) {
        LOG("init uc failed with %s", uc_strerror(uc_err))
        return false;
    }

    auto cs_err = cs_open(CS_ARCH_X86, CS_MODE_64, &gEngine.cs_);
    if (cs_err != CS_ERR_OK) {
        LOG("init cs failed with %s", cs_strerror(cs_err))
        return false;
    }
    return true;
}
