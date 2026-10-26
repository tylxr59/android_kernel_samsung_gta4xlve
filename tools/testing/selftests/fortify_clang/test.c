#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <assert.h>
#define __kernel_size_t size_t
#define __noreturn __attribute__((noreturn))
#define __cold __attribute__((cold))
#define __compiletime_error(s) __attribute__((error(s)))
#define CONFIG_FORTIFY_SOURCE 1
typedef unsigned gfp_t;
extern char *strncpy(char *,const char *,size_t);
extern char *strcat(char *,const char *);
extern size_t strlen(const char *);
extern size_t strnlen(const char *,size_t);
extern size_t strlcpy(char *,const char *,size_t);
extern size_t strlcat(char *,const char *,size_t);
extern char *strncat(char *,const char *,size_t);
extern void *memset(void *,int,size_t);
extern void *memcpy(void *,const void *,size_t);
extern void *memmove(void *,const void *,size_t);
extern void *memscan(void *,int,size_t);
extern int memcmp(const void *,const void *,size_t);
extern void *memchr(const void *,int,size_t);
extern void *memchr_inv(const void *,int,size_t);
extern void *kmemdup(const void *,size_t,gfp_t);
extern char *strcpy(char *,const char *);
#include "actual-fortify.inc"
void fortify_panic(const char *name) { (void)name;_Exit(86); }
__attribute__((noinline)) static size_t dynamic_size(size_t n) { asm volatile("" : "+r"(n));return n; }
int main(void) {
 char a[16],b[16]="hello";memset(a,0,sizeof(a));memcpy(a,b,6);assert(strlen(a)==5);assert(memcmp(a,b,6)==0);memmove(a+1,a,6);assert(a[1]=='h');
 pid_t p=fork();assert(p>=0);
 if(!p) {
  volatile size_t n=dynamic_size(17);
#if defined(NEGATIVE_WRITE)
  memcpy(a,b,17);
#elif defined(NEGATIVE_READ)
  char big[32];memcpy(big,b,17);
#else
  memset(a,0,n);
#endif
  _Exit(0);
 }
 int status;assert(waitpid(p,&status,0)==p);assert(WIFEXITED(status)&&WEXITSTATUS(status)==86);
 puts("PASS: valid operations and dynamic overflow trap");
}
