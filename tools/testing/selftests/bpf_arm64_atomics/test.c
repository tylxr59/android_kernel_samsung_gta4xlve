// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <linux/bpf.h>
typedef uint8_t u8; typedef int16_t s16; typedef int32_t s32;
#define BPF_REG_FP BPF_REG_10
#define BPF_REG_AX 11
#define MAX_BPF_JIT_REG 12
#define A64_R(n) (n)
#define pr_info(...) ((void)0)
#define pr_err_once(...) ((void)0)
enum { MOV, IMM, LOAD, ADD, AND, OR, XOR, STORE, BRANCH, BARRIER };
struct step { int op, wide, dst, left, right, offset; };
struct jit_ctx { struct bpf_prog { const struct bpf_insn *insnsi; } *prog; struct step code[32]; int idx; };
#define I(op,w,d,a,b,o) ((struct step){op,w,d,a,b,o})
#define A64_MOV(w,d,a) I(MOV,w,d,a,0,0)
#define A64_LDXR(w,d,a) I(LOAD,w,d,a,0,0)
#define A64_ADD(w,d,a,b) I(ADD,w,d,a,b,0)
#define A64_AND(w,d,a,b) I(AND,w,d,a,b,0)
#define A64_ORR(w,d,a,b) I(OR,w,d,a,b,0)
#define A64_EOR(w,d,a,b) I(XOR,w,d,a,b,0)
#define A64_STXR(w,v,a,status) I(STORE,w,status,a,v,0)
#define A64_STLXR A64_STXR
#define A64_CBNZ(w,r,o) I(BRANCH,w,0,r,0,o)
#define A64_DMB_ISH I(BARRIER,0,0,0,0,0)
static void emit(struct step s,struct jit_ctx *c) { assert(c->idx<32);c->code[c->idx++]=s; }
static void emit_a64_mov_i(int wide,int d,int imm,struct jit_ctx *c) { emit(I(IMM,wide,d,0,0,imm),c); }
#include "actual-functions.inc"
static uint64_t narrow(uint64_t x,int wide) {return wide?x:(uint32_t)x;}
static void execute(struct jit_ctx *c,uint64_t *r,uint64_t *mem,uint64_t addr,int failures) {
 int pc=0,bound=200;
 while(pc<c->idx) { assert(--bound>0);struct step s=c->code[pc];uint64_t x=0;int write=1;
  switch(s.op) {
   case MOV:x=r[s.left];break;case IMM:x=(int64_t)s.offset;break;
   case LOAD:assert(r[s.left]==addr);x=*mem;break;
   case ADD:x=r[s.left]+r[s.right];break;case AND:x=r[s.left]&r[s.right];break;
   case OR:x=r[s.left]|r[s.right];break;case XOR:x=r[s.left]^r[s.right];break;
   case STORE:assert(r[s.left]==addr);x=failures>0;if(failures)failures--;else *mem=narrow(r[s.right],s.wide);break;
   case BRANCH:write=0;if(narrow(r[s.left],s.wide)){pc+=s.offset;continue;}break;
   case BARRIER:write=0;break;default:assert(0);
  }
  if(write)r[s.dst]=narrow(x,s.wide);pc++;
 }
}
int main(void) {
 const int ops[]={BPF_ADD,BPF_AND,BPF_OR,BPF_XOR,BPF_ADD|BPF_FETCH,BPF_AND|BPF_FETCH,BPF_OR|BPF_FETCH,BPF_XOR|BPF_FETCH,BPF_XCHG,BPF_CMPXCHG};
 int cases=0;
 for(int wide=0;wide<2;wide++)for(int opi=0;opi<10;opi++)for(int src=0;src<10;src++)for(int dst=1;dst<11;dst++) {
  if(src==dst)continue;
  for(int offset=-16;offset<=16;offset+=16)for(int failed=0;failed<2;failed++)for(int match=0;match<2;match++) {
   uint64_t r[32],before[32];for(int i=0;i<32;i++)r[i]=0xaaaa000000000000ULL+i;
   uint64_t initial=narrow(0x87654321abcdf123ULL,wide),mem=initial,value=narrow(0x12345678f0e1d2c3ULL,wide),expected;
   r[bpf2a64[src]]=value;r[bpf2a64[dst]]=0x10000-offset;
   if(ops[opi]==BPF_CMPXCHG){r[bpf2a64[0]]=initial+(match?0:1);if(src==0)value=r[bpf2a64[0]];}
   for(int i=0;i<32;i++)before[i]=r[i];
   struct bpf_insn insn={.code=BPF_STX|BPF_ATOMIC|(wide?BPF_DW:BPF_W),.dst_reg=dst,.src_reg=src,.off=offset,.imm=ops[opi]};
   struct bpf_prog prog={&insn};struct jit_ctx c={.prog=&prog};assert(emit_ll_sc_atomic(&insn,&c)==0);
   switch(ops[opi]&~BPF_FETCH){case BPF_ADD:expected=initial+value;break;case BPF_AND:expected=initial&value;break;case BPF_OR:expected=initial|value;break;case BPF_XOR:expected=initial^value;break;default:expected=ops[opi]==BPF_XCHG?value:(match?value:initial);}
   execute(&c,r,&mem,0x10000,failed);assert(mem==narrow(expected,wide));
   int result=ops[opi]==BPF_CMPXCHG?0:((ops[opi]&BPF_FETCH)?src:-1);
   if(result>=0)assert(r[bpf2a64[result]]==initial);
   for(int i=0;i<11;i++)if(i!=result)assert(r[bpf2a64[i]]==before[bpf2a64[i]]);
   cases++;
  }
 }
 printf("PASS: %d actual LL/SC emitter cases (32/64-bit, offsets, registers, cmpxchg match/miss, store retries)\n",cases);
}
