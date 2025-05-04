#pragma once
#pragma pack(push, 1)
struct SegmentDescriptor {
    union {
        struct {
            uint16_t limit0;         // 段限制低 16 位
            uint16_t base0;          // 段基址低 16 位
            uint8_t  base1;          // 段基址中间 8 位
            uint8_t  type       : 4; // 段类型			用于表示内存段的具体类型和访问权限。例如，数据段、代码段等
            uint8_t  system     : 1; // 系统标志			表示段描述符是系统段TSS（0）还是代码或数据段（1）  
            uint8_t  dpl        : 2; // 特权级别			表示内存段的特权级别，范围从0（最高特权）到3（最低特权）
            uint8_t  present    : 1; // 存在标志			表示段描述符是否有效。有效时置1，无效时置0
            uint8_t  limit1     : 4; // 段限制高 4 位		
            uint8_t  avail      : 1; // 可用位			系统软件可以自由使用这个位
            uint8_t  is_64_code : 1; // 64 位代码标志		0则为32位汇编  1则是64位汇编
            uint8_t  db         : 1; // 默认操作数大小标志
            uint8_t  granularity: 1; // 段粒度			用于控制限制字段的单位。当G为0时，单位是字节；当G为1时，单位是4KB
            uint8_t  base2;          // 段基址高 8 位
        };

        uint64_t desc; // 整个段描述符
    };
};

//选择子
struct SegmentSelector {
    union {
        struct {
            uint16_t rpl  : 2;  // 请求特权级别（2位）
            uint16_t table: 1;  // 表示选择子对应的描述符表是 GDT（0）还是 LDT（1）
            uint16_t index: 13; // 索引值（13位）
        };

        uint64_t desc; // 整个段描述符
    };
};
#pragma pack(pop)
//初始化段描述符			is_code:是否代码段		dpl:特权级别 == 3 应用级  is_64_code:0则为32位汇编执行模式 1则为64位汇编执行模式
void init_descriptor(SegmentDescriptor *desc, uint64_t base, uint32_t limit, uint8_t is_code, uint8_t dpl, uint8_t is_64_code = 0);
