// SPDX-License-Identifier: GPL-2.0-only
#include <assert.h>
#include <stdio.h>
#include "linux/test_stubs.h"
#ifndef ITER_SOURCE
#error ITER_SOURCE must name the actual kernel iterator source
#endif
#include ITER_SOURCE
static struct dma_buf buffers[1000];
static unsigned count;
struct dma_buf *dma_buf_iter_begin(void) {
 if (!count) return NULL;
 buffers[0].refs++;
 return &buffers[0];
}
void dma_buf_put(struct dma_buf *b) { assert(b && b->refs); --b->refs; }
struct dma_buf *dma_buf_iter_next(struct dma_buf *b) {
 struct dma_buf *next=b->next;
 if (next) ++next->refs;
 dma_buf_put(b);
 return next;
}
static void init(unsigned n) {
 count=n;
 for (unsigned i=0;i<n;i++) buffers[i]=(struct dma_buf){.id=i,.next=i+1<n?&buffers[i+1]:NULL};
}
static void no_refs(void) { for(unsigned i=0;i<count;i++) assert(buffers[i].refs==0); }
static void short_reads(unsigned chunk) {
 struct dmabuf_iter_seq_info info={0}; struct seq_file seq={.private=&info}; loff_t pos=0;
 unsigned seen=0;
 for (;;) {
  struct dma_buf *p=dmabuf_iter_seq_start(&seq,&pos);
  if (!p) {dmabuf_iter_seq_stop(&seq,NULL);break;}
  for(unsigned i=0;p && i<chunk;i++) {
   assert(p->id==seen++); assert(p->refs==1);
   p=dmabuf_iter_seq_next(&seq,p,&pos);
  }
  dmabuf_iter_seq_stop(&seq,p);
 }
 assert(seen==count);dmabuf_iter_seq_fini(&info);no_refs();
}
int main(void) {
 init(0);short_reads(1);
 init(1);short_reads(1);
 init(1000);short_reads(1);short_reads(17);short_reads(1000);
 /* Close with an unconsumed next object retained between reads. */
 struct dmabuf_iter_seq_info info={0};struct seq_file seq={.private=&info};loff_t pos=0;
 struct dma_buf *p=dmabuf_iter_seq_start(&seq,&pos);
 p=dmabuf_iter_seq_next(&seq,p,&pos);
 dmabuf_iter_seq_stop(&seq,p);assert(buffers[1].refs==1);
 dmabuf_iter_seq_fini(&info);no_refs();
 puts("PASS: actual iterator source handles empty/single/1000 buffers, short reads, EOF and early-close references");
}
