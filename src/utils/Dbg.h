#pragma once

#include <string>
#include <tuple>

#include "StructDef.h"

namespace Dbg
{
    std::tuple<size_t, size_t> GetMemBaseWithSize(size_t addr);

    SimulateRegs GetRegs();

    std::string GetAddrName(size_t addr);

    void EnableBpx(size_t addr);

    size_t RunToAddr(size_t addr);

    bool MemRead(size_t addr, uint8_t *buf_output, size_t size);
}
