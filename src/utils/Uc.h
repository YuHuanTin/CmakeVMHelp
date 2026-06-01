#pragma once

#include "StructDef.h"

namespace Uc
{
    SimulateRegs GetRegs(uc_engine *uc);

    bool WriteReg(uc_engine *uc, SimulateRegs &regs);
}
