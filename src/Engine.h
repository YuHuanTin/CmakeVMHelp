#pragma once

#include <string>

#include "utils/CodeTraceLogger.h"

enum StopReason {
    PAGE_SWITCH,
    REACHED_BP,
    REACHED_INST,
    REACHED_CALL_FINISH
};

class EmuEngine {
public:
    uc_engine *uc_;
    csh        cs_;

    void run(StopReason stopReason);

    void run(StopReason stopReason, const std::string &instTarget);

private:
    StopReason  stopReason_    = PAGE_SWITCH;
    std::size_t runRegionBase_ = 0;
    std::size_t runRegionEnd_  = 0;
    std::size_t stopAddr_      = 0;
    std::string inst_target_;

    CodeTraceLogger traceLogger_;

    void hostBasicMemToEmu(std::size_t cip, std::size_t sp);

    void hostPageToEmu(std::size_t pageBase, std::size_t pageSize);

    void hostRegToEmu();

    void unmapAllRegions();

    static void hookCode(uc_engine *uc, uint64_t address, uint32_t size, void *userData);

    static void hookMemValid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *userData);

    static bool hookMemInvalid(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *userData);
};

inline EmuEngine gEngine;

bool init_engine();
