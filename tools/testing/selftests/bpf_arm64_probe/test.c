// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
_Static_assert(sizeof(void *)==8,"ARM64 logic fixture requires a 64-bit host");
typedef uint32_t __le32;typedef uint32_t u32;
struct exception_table_entry {int insn,fixup;};
struct pt_regs {uint64_t regs[31],sp,pc,pstate;};
struct bpf_insn {uint8_t code;uint8_t dst_reg:4,src_reg:4;int16_t off;int32_t imm;};
struct bpf_prog_aux {struct exception_table_entry *extable;unsigned num_exentries;};
struct bpf_prog {struct bpf_prog_aux *aux;};
#define GENMASK(h,l) (((~0ULL)<<(l))&((~0ULL)>>(63-(h))))
#define FIELD_GET(mask,val) (((uint64_t)(val)&(mask))>>__builtin_ctzll(mask))
#define FIELD_PREP(mask,val) (((uint64_t)(val)<<__builtin_ctzll(mask))&(mask))
#define FIELD_FIT(mask,val) ((((uint64_t)(val)<<__builtin_ctzll(mask))&~(mask))==0)
#define WARN_ON_ONCE(v) (v)
#define BPF_MODE(c) ((c)&0xe0)
#define BPF_PROBE_MEM 0x20
#define AARCH64_INSN_SIZE 4
#define AARCH64_BREAK_FAULT 0xd4202000U
#define le32_to_cpu(v) (v)
#define CONFIG_BPF_JIT 1
#define IS_ENABLED(v) (v)
static uintptr_t region_start,region_end;
#define BPF_JIT_REGION_START region_start
#define BPF_JIT_REGION_END region_end
#define instruction_pointer(r) ((r)->pc)
static const struct exception_table_entry *active;
static const struct exception_table_entry *search_exception_tables(unsigned long pc){(void)pc;return active;}
#define BPF_REG_AX 11
#define BPF_ADD 0x00
#define BPF_RSH 0x70
#define BPF_JLE 0xb0
#define BPF_JA 0x00
#define BPF_MOV64_REG(d,s) ((struct bpf_insn){.code=0xbf,.dst_reg=(d),.src_reg=(s)})
#define BPF_MOV64_IMM(d,v) ((struct bpf_insn){.code=0xb7,.dst_reg=(d),.imm=(v)})
#define BPF_ALU64_IMM(op,d,v) ((struct bpf_insn){.code=0x07|(op),.dst_reg=(d),.imm=(v)})
#define BPF_JMP_IMM(op,d,v,o) ((struct bpf_insn){.code=0x05|(op),.dst_reg=(d),.imm=(v),.off=(o)})
#include "actual-functions.inc"
struct block {u32 image[8];struct exception_table_entry table[4];};
static void check_user_guard(uint64_t base,int16_t offset,bool allow,bool alias){
 struct bpf_insn insn={.code=0x39,.src_reg=1,.dst_reg=alias?1:0,.off=offset},code[16];
 unsigned n=generate_guard(&insn,code,1ULL<<39);uint64_t regs[12]={0};regs[1]=base;
 unsigned reads=0,steps=0;uint64_t address=0;
 for(unsigned pc=0;pc<n;pc++){
  assert(++steps<20);struct bpf_insn i=code[pc];
  switch(i.code){
  case 0xbf:regs[i.dst_reg]=regs[i.src_reg];break;
  case 0xb7:regs[i.dst_reg]=(int64_t)i.imm;break;
  case 0x07:regs[i.dst_reg]+=(int64_t)i.imm;break;
  case 0x77:regs[i.dst_reg]>>=i.imm;break;
  case 0xb5:if(regs[i.dst_reg]<=(uint64_t)(int64_t)i.imm)pc+=i.off;break;
  case 0x05:pc+=i.off;break;
  case 0x39:reads++;address=regs[i.src_reg]+i.off;regs[i.dst_reg]=0xf00dbabe;break;
  default:assert(0);
  }
 }
 assert(reads==(allow?1u:0u));assert(regs[insn.dst_reg]==(allow?0xf00dbabe:0));
 if(allow)assert(address==base+offset);
}
int main(void){
 struct block data={0};for(unsigned i=0;i<8;i++)data.image[i]=0xd503201f;
 struct bpf_prog_aux aux={.extable=data.table,.num_exentries=1};struct bpf_prog prog={.aux=&aux};
 struct jit_ctx ctx={.prog=&prog,.image=data.image,.idx=2};
 region_start=(uintptr_t)data.image;region_end=(uintptr_t)(data.image+8);
 unsigned widths[]={0x21,0x29,0x31,0x39};unsigned cases=0;
 for(unsigned w=0;w<4;w++)for(int reg=0;reg<31;reg++){
  struct bpf_insn insn={.code=widths[w]};ctx.exentry_idx=0;
  assert(add_exception_handler(&insn,&ctx,reg)==0);assert(ctx.exentry_idx==1);
  assert((intptr_t)&data.table[0].insn+data.table[0].insn==(intptr_t)&data.image[1]);
  struct pt_regs regs={.pc=(uintptr_t)&data.image[1],.sp=0x123400,.pstate=0xf0000000};
  for(int j=0;j<31;j++)regs.regs[j]=0x100+j;
  active=&data.table[0];assert(fixup_exception(&regs)==1);
  assert(regs.pc==(uintptr_t)&data.image[2]);assert(regs.sp==0x123400&&regs.pstate==0xf0000000);
  for(int j=0;j<31;j++)assert(regs.regs[j]==(j==reg?0:0x100u+j));
  assert(validate_code(&ctx)==0);cases++;
 }
 struct bpf_insn probe={.code=0x39},normal={.code=0x79};
 ctx.exentry_idx=0;ctx.image=NULL;assert(add_exception_handler(&probe,&ctx,0)==0&&ctx.exentry_idx==0);
 ctx.image=data.image;assert(add_exception_handler(&normal,&ctx,0)==0&&ctx.exentry_idx==0);
 aux.extable=NULL;assert(add_exception_handler(&probe,&ctx,0)==-EINVAL);aux.extable=data.table;
 aux.num_exentries=0;assert(add_exception_handler(&probe,&ctx,0)==-EINVAL);aux.num_exentries=1;
 ctx.image=(u32*)&data.table[3];ctx.idx=1;assert(add_exception_handler(&probe,&ctx,0)==-ERANGE);
 ctx.image=(u32*)((uintptr_t)&data.table[0]-(1UL<<27)-4096);assert(add_exception_handler(&probe,&ctx,0)==-ERANGE);
 ctx.image=data.image;ctx.idx=2;ctx.exentry_idx=0;assert(validate_code(&ctx)==-1);
 ctx.exentry_idx=1;data.image[0]=AARCH64_BREAK_FAULT;assert(validate_code(&ctx)==-1);data.image[0]=0xd503201f;
 /* Ordinary exception entries must retain the original PC-only fixup. */
 data.table[0].fixup=(intptr_t)&data.image[5]-(intptr_t)&data.table[0].fixup;
 struct pt_regs ordinary={.pc=1,.sp=7,.pstate=0xa0000000};for(int j=0;j<31;j++)ordinary.regs[j]=j+1;
 active=&data.table[0];assert(fixup_exception(&ordinary)==1&&ordinary.pc==(uintptr_t)&data.image[5]);
 for(int j=0;j<31;j++)assert(ordinary.regs[j]==j+1u);assert(ordinary.sp==7&&ordinary.pstate==0xa0000000);
 active=NULL;ordinary.pc=0x1234;assert(fixup_exception(&ordinary)==0&&ordinary.pc==0x1234);
 for(unsigned i=0;i<1024;i++)for(int off=-16;off<=16;off+=16){
  check_user_guard((uint64_t)i*1048576+65536,off,false,false);
  check_user_guard(0xffffff8000100000ULL+(uint64_t)i*65536,off,true,true);
 }
 check_user_guard(0,0,false,false);check_user_guard((1ULL<<39)-1,16,false,true);
 check_user_guard(0xfffffffffffffff0ULL,32,false,false);
 puts("PASS: actual verifier-generated guard blocks user ranges/effective-address wrap, allows kernel reads and preserves alias behavior");
 printf("PASS: %u register/width fixups preserve flags/SP; table bounds/count/hole checks and ordinary exception behavior pass\n",cases);
}
