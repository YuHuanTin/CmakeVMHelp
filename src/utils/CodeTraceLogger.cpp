#include "CodeTraceLogger.h"

#include <format>

#include "src/_plugin_entry.h"

void CodeTraceLogger::reset() {
    pendingRegs_ = {};
    pendingLine_.clear();
    hasPending_ = false;
}

void CodeTraceLogger::flush(const SimulateRegs &currentRegs) {
    if (!hasPending_) {
        return;
    }

    const auto regDiff = calcRegsDiff(pendingRegs_, currentRegs);
    if (regDiff.empty()) {
        LOG("%s", pendingLine_.c_str());
    } else {
        LOG("%s \t=> [%s]", pendingLine_.c_str(), regDiff.c_str());
    }

    pendingLine_.clear();
    hasPending_ = false;
}

void CodeTraceLogger::record(const std::uint64_t addr, const char *mnemonic, const char *opStr, const SimulateRegs &currentRegs) {
    pendingLine_ = std::format("[uc-code] 0x{:016x} {} {}", addr, mnemonic, opStr);
    pendingRegs_ = currentRegs;
    hasPending_  = true;
}

std::string CodeTraceLogger::calcRegsDiff(const SimulateRegs &regsBefore, const SimulateRegs &regsAfter) {
    std::string buf;
    if (regsBefore.cax != regsAfter.cax) {
        buf += std::format("cax: {:#x} -> {:#x}, ", regsBefore.cax, regsAfter.cax);
    }
    if (regsBefore.cbx != regsAfter.cbx) {
        buf += std::format("cbx: {:#x} -> {:#x}, ", regsBefore.cbx, regsAfter.cbx);
    }
    if (regsBefore.ccx != regsAfter.ccx) {
        buf += std::format("ccx: {:#x} -> {:#x}, ", regsBefore.ccx, regsAfter.ccx);
    }
    if (regsBefore.cdx != regsAfter.cdx) {
        buf += std::format("cdx: {:#x} -> {:#x}, ", regsBefore.cdx, regsAfter.cdx);
    }
    if (regsBefore.cbp != regsAfter.cbp) {
        buf += std::format("cbp: {:#x} -> {:#x}, ", regsBefore.cbp, regsAfter.cbp);
    }
    if (regsBefore.csp != regsAfter.csp) {
        buf += std::format("csp: {:#x} -> {:#x}, ", regsBefore.csp, regsAfter.csp);
    }
    if (regsBefore.csi != regsAfter.csi) {
        buf += std::format("csi: {:#x} -> {:#x}, ", regsBefore.csi, regsAfter.csi);
    }
    if (regsBefore.cdi != regsAfter.cdi) {
        buf += std::format("cdi: {:#x} -> {:#x}, ", regsBefore.cdi, regsAfter.cdi);
    }
    if (regsBefore.r8 != regsAfter.r8) {
        buf += std::format("r8: {:#x} -> {:#x}, ", regsBefore.r8, regsAfter.r8);
    }
    if (regsBefore.r9 != regsAfter.r9) {
        buf += std::format("r9: {:#x} -> {:#x}, ", regsBefore.r9, regsAfter.r9);
    }
    if (regsBefore.r10 != regsAfter.r10) {
        buf += std::format("r10: {:#x} -> {:#x}, ", regsBefore.r10, regsAfter.r10);
    }
    if (regsBefore.r11 != regsAfter.r11) {
        buf += std::format("r11: {:#x} -> {:#x}, ", regsBefore.r11, regsAfter.r11);
    }
    if (regsBefore.r12 != regsAfter.r12) {
        buf += std::format("r12: {:#x} -> {:#x}, ", regsBefore.r12, regsAfter.r12);
    }
    if (regsBefore.r13 != regsAfter.r13) {
        buf += std::format("r13: {:#x} -> {:#x}, ", regsBefore.r13, regsAfter.r13);
    }
    if (regsBefore.r14 != regsAfter.r14) {
        buf += std::format("r14: {:#x} -> {:#x}, ", regsBefore.r14, regsAfter.r14);
    }
    if (regsBefore.r15 != regsAfter.r15) {
        buf += std::format("r15: {:#x} -> {:#x}, ", regsBefore.r15, regsAfter.r15);
    }
    // if (regsBefore.cip != regsAfter.cip) {
    //     buf += std::format("cip: {:#x} -> {:#x}, ", regsBefore.cip, regsAfter.cip);
    // }
    if (regsBefore.flags != regsAfter.flags) {
        buf += std::format("flags: {:#x} -> {:#x}, ", regsBefore.flags, regsAfter.flags);
    }
    if (regsBefore.dr0 != regsAfter.dr0) {
        buf += std::format("dr0: {:#x} -> {:#x}, ", regsBefore.dr0, regsAfter.dr0);
    }
    if (regsBefore.dr1 != regsAfter.dr1) {
        buf += std::format("dr1: {:#x} -> {:#x}, ", regsBefore.dr1, regsAfter.dr1);
    }
    if (regsBefore.dr2 != regsAfter.dr2) {
        buf += std::format("dr2: {:#x} -> {:#x}, ", regsBefore.dr2, regsAfter.dr2);
    }
    if (regsBefore.dr3 != regsAfter.dr3) {
        buf += std::format("dr3: {:#x} -> {:#x}, ", regsBefore.dr3, regsAfter.dr3);
    }
    if (regsBefore.dr6 != regsAfter.dr6) {
        buf += std::format("dr6: {:#x} -> {:#x}, ", regsBefore.dr6, regsAfter.dr6);
    }
    if (regsBefore.dr7 != regsAfter.dr7) {
        buf += std::format("dr7: {:#x} -> {:#x}, ", regsBefore.dr7, regsAfter.dr7);
    }
    if (regsBefore.MxCsr != regsAfter.MxCsr) {
        buf += std::format("MxCsr: {:#x} -> {:#x}, ", regsBefore.MxCsr, regsAfter.MxCsr);
    }
    if (regsBefore.gs_base != regsAfter.gs_base) {
        buf += std::format("gs_base: {:#x} -> {:#x}, ", regsBefore.gs_base, regsAfter.gs_base);
    }

    return buf.size() > 2 ? buf.erase(buf.size() - 2) : buf;
}
