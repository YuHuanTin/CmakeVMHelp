//
// Created by YuHuanTin on 2026/5/18.
//

#include "CommandHandlers.h"

#include <format>

#include "Engine.h"
#include "_plugin_entry.h"
#include "utils/Dbg.h"


bool cb_run_until_page_switch(int argc, char *argv[]) {
    LOG("command: [%s]", __FUNCTION__)
    gEngine.run(PAGE_SWITCH);
    return true;
}
bool cb_run_until_breakpoint(int argc, char *argv[]) {
    LOG("command: [%s]", __FUNCTION__)
    gEngine.run(REACHED_BP);
    return true;
}
bool cb_run_until_instruction(int argc, char *argv[]) {
    LOG("command: [%s]", __FUNCTION__)
    if (argc < 2) {
        LOG("usage: vm_run_until_instruction <mnemonic>")
        return false;
    }

    gEngine.run(REACHED_INST, argv[1]);
    return true;
}
bool cb_run_until_call_return(int argc, char *argv[]) {
    LOG("command: [%s]", __FUNCTION__)
    gEngine.run(REACHED_CALL_FINISH);
    return true;
}

bool cb_test_DbgGetBpxTypeAt(int argc, char *argv[]) {
    if (argc < 2) {
        LOG("usage: _test_DbgGetBpxTypeA 0x00000000")
        return false;
    }

    const auto addr = std::stoll(argv[1], nullptr, 16);
    switch (DbgGetBpxTypeAt(addr)) {
        case bp_none:
            LOG("bp_none at %s", argv[1])
            break;
        case bp_normal:
            LOG("bp_normal at %s", argv[1])
            break;
        case bp_hardware:
            LOG("bp_hardware at %s", argv[1])
            break;
        case bp_memory:
            LOG("bp_memory at %s", argv[1])
            break;
        case bp_dll:
            LOG("bp_dll at %s", argv[1])
            break;
        case bp_exception:
            LOG("bp_exception at %s", argv[1])
            break;
    }
    return true;
}
bool cb_test_PageQuery(int argc, char *argv[]) {
    if (argc < 2) {
        LOG("usage: _test_PageQuery 0x00000000")
        return false;
    }
    const auto addr = std::stoll(argv[1], nullptr, 16);

    MEMORY_BASIC_INFORMATION mbi;

    if (!VirtualQueryEx(DbgGetProcessHandle(), reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi))) {
        LOG("VirtualQueryEx at %s failed with err %lu", argv[1], GetLastError());
        return false;
    }

    LOG("%s", std::format("VirtualQueryEx addr: 0x{:016x}"
                          " AllocationBase: 0x{:016x}"
                          " BaseAddress: 0x{:016x}"
                          " RegionSize: 0x{:016x}"
                          " Protect: 0x{:08x}"
                          " State: 0x{:08x}",
                  (size_t)addr,
                  (size_t)mbi.AllocationBase,
                  (size_t)mbi.BaseAddress,
                  (size_t)mbi.RegionSize,
                  mbi.Protect,
                  mbi.State)
                  .c_str())

    size_t size = 0;
    auto   base = DbgMemFindBaseAddr(addr, &size);
    if (base == 0) {
        LOG("DbgMemFindBaseAddr failed");
        return false;
    }
    LOG("DbgMemFindBaseAddr addr: 0x%016llx, base = 0x%016llx, size = 0x%016llx", addr, base, size);
    return true;
}

bool cb_test_StepInAndQueryPage(int argc, char *argv[]) {
    if (argc < 2) {
        LOG("usage: _test_StepInAndQueryPage 0x00000000(spy addr)")
        return false;
    }
    Dbg::StepInto(1);

    for (int i = 0; i < 5; ++i) {
        cb_test_PageQuery(argc, argv);
        sleep(1);
    }
    return true;
}
