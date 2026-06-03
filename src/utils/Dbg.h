#pragma once

#include <memory>
#include <string>

#include "StructDef.h"

namespace Dbg
{
    SimulateRegs GetRegs();

    std::string GetAddrName(size_t addr);

    void EnableBpx(size_t addr);

    size_t RunToAddr(size_t addr);

    size_t StepInto(int count = 1);

    std::unique_ptr<uint8_t[]> MemReadEnhanced(size_t addr, size_t size);

    std::pair<size_t, size_t> MemFindBaseAddrEnhanced(size_t addr);
}
