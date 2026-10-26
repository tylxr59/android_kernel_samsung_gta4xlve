// SPDX-License-Identifier: GPL-2.0-only
/* Bounded, unattached socket-filter tests. No maps, pins or persistent hooks. */
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#define RAW(c,d,s,o,i) ((struct bpf_insn){.code=c,.dst_reg=d,.src_reg=s,.off=o,.imm=i})
#define MOV(d,i) RAW(BPF_ALU64|BPF_MOV|BPF_K,d,0,0,i)
#define LOAD(sz,d,s,o) RAW(BPF_LDX|BPF_MEM|sz,d,s,o,0)
#define STORE(sz,d,o,i) RAW(BPF_ST|BPF_MEM|sz,d,0,o,i)
#define EXIT() RAW(BPF_JMP|BPF_EXIT,0,0,0,0)
static int bpfcall(int command,union bpf_attr *a) { return syscall(__NR_bpf,command,a,sizeof(*a)); }
static int load(struct bpf_insn *insns,int count,char *log) {
 union bpf_attr a={0};a.prog_type=BPF_PROG_TYPE_SOCKET_FILTER;a.insn_cnt=count;
 a.insns=(uintptr_t)insns;a.license=(uintptr_t)"GPL";a.log_buf=(uintptr_t)log;a.log_size=32768;a.log_level=1;
 return bpfcall(BPF_PROG_LOAD,&a);
}
static int run(int fd) {
 unsigned char in[64]={0},out[128]={0};union bpf_attr a={0};a.test.prog_fd=fd;
 a.test.data_in=(uintptr_t)in;a.test.data_size_in=sizeof(in);a.test.data_out=(uintptr_t)out;a.test.data_size_out=sizeof(out);a.test.repeat=1;
 if(bpfcall(BPF_PROG_TEST_RUN,&a))return -1;return a.test.retval;
}
int main(void) {
 if(getuid()!=0){fputs("Run only during authorized rooted diagnostics\n",stderr);return 2;}
 const int ops[]={BPF_ADD,BPF_AND,BPF_OR,BPF_XOR,BPF_ADD|BPF_FETCH,BPF_AND|BPF_FETCH,BPF_OR|BPF_FETCH,BPF_XOR|BPF_FETCH,BPF_XCHG,BPF_CMPXCHG};
 int passed=0;char log[32768];
 for(int wide=0;wide<2;wide++)for(int oi=0;oi<10;oi++)for(int match=0;match<2;match++) {
  int initial=42,value=7,op=ops[oi],expect;
  switch(op&~BPF_FETCH){case BPF_ADD:expect=initial+value;break;case BPF_AND:expect=initial&value;break;case BPF_OR:expect=initial|value;break;case BPF_XOR:expect=initial^value;break;default:expect=op==BPF_XCHG?value:(match?value:initial);}
  /* r6 retains the memory base; r1 supplies/receives the atomic operand. */
  struct bpf_insn p[]={STORE(BPF_DW,10,-8,initial),RAW(BPF_ALU64|BPF_MOV|BPF_X,6,10,0,0),RAW(BPF_ALU64|BPF_ADD|BPF_K,6,0,0,-8),MOV(1,value),MOV(0,initial+(match?0:1)),RAW(BPF_STX|BPF_ATOMIC|(wide?BPF_DW:BPF_W),6,1,0,op),LOAD(wide?BPF_DW:BPF_W,2,6,0),RAW(BPF_JMP|BPF_JNE|BPF_K,2,0,3,expect),RAW(BPF_JMP|BPF_JNE|BPF_K,op==BPF_CMPXCHG?0:1,0,2,(op&BPF_FETCH)?initial:value),MOV(0,1),EXIT(),MOV(0,0),EXIT()};
  memset(log,0,sizeof(log));int fd=load(p,sizeof(p)/sizeof(p[0]),log);
  if(fd<0){fprintf(stderr,"load failed wide=%d op=%x: %s\n%s\n",wide,op,strerror(errno),log);return 1;}
  int result=run(fd);int saved=errno;close(fd);
  if(result!=1){fprintf(stderr,"execution failed wide=%d op=%x result=%d errno=%d\n",wide,op,result,saved);return 1;}passed++;
 }
 for(int bad=0;bad<3;bad++){
  struct bpf_insn p[]={STORE(BPF_DW,10,-8,42),MOV(1,1),RAW(BPF_STX|BPF_ATOMIC|(bad==2?BPF_H:BPF_W),10,1,bad==1?-7:-8,bad==0?0xff:BPF_ADD|BPF_FETCH),MOV(0,1),EXIT()};
  memset(log,0,sizeof(log));int fd=load(p,sizeof(p)/sizeof(p[0]),log);
  if(fd>=0){close(fd);fprintf(stderr,"invalid atomic accepted: %d\n",bad);return 1;}passed++;
 }
 printf("PASS: %d bounded live atomic execution/rejection cases\n",passed);return 0;
}
