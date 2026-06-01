#pragma once

#include <string>

#include "StructDef.h"

class CodeTraceLogger {
public:
    void reset();

    void flush(const SimulateRegs &currentRegs);

    void record(std::uint64_t addr, const char *mnemonic, const char *opStr, const SimulateRegs &currentRegs);

private:
    static std::string calcRegsDiff(const SimulateRegs &regsBefore, const SimulateRegs &regsAfter);

    SimulateRegs pendingRegs_ {};
    std::string  pendingLine_;
    bool         hasPending_ = false;
};
