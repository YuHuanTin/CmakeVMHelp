#pragma once

#include <cstdint>

struct SimulateRegs {
    size_t cax;
    size_t cbx;
    size_t ccx;
    size_t cdx;

    size_t cbp;
    size_t csp;
    size_t csi;
    size_t cdi;
#ifdef _WIN64
    size_t r8;
    size_t r9;
    size_t r10;
    size_t r11;
    size_t r12;
    size_t r13;
    size_t r14;
    size_t r15;
#endif //_WIN64
    size_t cip;
    size_t flags;

    size_t dr0;
    size_t dr1;
    size_t dr2;
    size_t dr3;
    size_t dr6;
    size_t dr7;

    uint32_t MxCsr; // SIMD 相关

    // Segment selector
    // GDT, LDT simulate required
    // may cause `Unhandled CPU exception (UC_ERR_EXCEPTION)`
    // gs,fs,es,cs,ds,ss

    // Segment Base Address
    size_t gs_base;
    // size_t fs_base;
};
