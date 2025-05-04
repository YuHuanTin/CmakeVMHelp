#include "pch.h"
#include "gdt.h"


//初始化段描述符			is_code:是否代码段		dpl:特权级别 == 3 应用级  is_64_code:0则为32位汇编执行模式 1则为64位汇编执行模式
void init_descriptor(SegmentDescriptor *desc, uint64_t base, uint32_t limit, uint8_t is_code, uint8_t dpl, uint8_t is_64_code) {
    desc->desc  = 0; // 清除描述符
    desc->base0 = base & 0xffff;
    desc->base1 = (base >> 16) & 0xff;
    desc->base2 = (base >> 24) & 0xff;

    if (limit > 0xfffff) {
        // 需要 Giant 粒度
        limit >>= 12;
        desc->granularity = 1;
    }

    desc->limit0 = limit & 0xffff;
    desc->limit1 = (limit >> 16) & 0xf;

    // 设置一些合理的默认值
    desc->dpl        = dpl; //三环
    desc->present    = 1;
    desc->db         = 1; // 32 位
    desc->type       = is_code ? 0xb : 3;
    desc->system     = 1; // code or data
    desc->is_64_code = is_64_code;
}
