//
// Created by YuHuanTin on 2026/5/18.
//

#include "CommandHandlers.h"

#include "Engine.h"
#include "_plugin_entry.h"


bool cb_run_until_page_switch(int argc, char *argv[]) {
    gEngine.run(PAGE_SWITCH);
    return true;
}
bool cb_run_until_breakpoint(int argc, char *argv[]) {
    gEngine.run(REACHED_BP);
    return true;
}
bool cb_run_until_instruction(int argc, char *argv[]) {
    if (argc < 2) {
        LOG("usage: vm_run_until_instruction <mnemonic>")
        return false;
    }

    gEngine.run(REACHED_INST, argv[1]);
    return true;
}
bool cb_run_until_call_return(int argc, char *argv[]) {
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
