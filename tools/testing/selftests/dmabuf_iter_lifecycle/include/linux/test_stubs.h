// SPDX-License-Identifier: GPL-2.0-only
#ifndef ITER_TEST_STUBS
#define ITER_TEST_STUBS
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#define __init
#define __bpf_md_ptr(type, name) type name
#define PTR_TO_BTF_ID_OR_NULL 1
#define DEFINE_BPF_ITER_FUNC(...)
#define BTF_ID_LIST_SINGLE(name, ...) static unsigned name[1];
#define late_initcall(fn)
struct dma_buf { unsigned id, refs; struct dma_buf *next; };
struct seq_file { void *private; };
struct bpf_iter_meta { struct seq_file *seq; };
struct bpf_prog {};
struct bpf_iter_aux_info {};
struct seq_operations { void *(*start)(struct seq_file *, loff_t *); void *(*next)(struct seq_file *, void *, loff_t *); void (*stop)(struct seq_file *, void *); int (*show)(struct seq_file *, void *); };
struct bpf_iter_seq_info { const struct seq_operations *seq_ops; void *init_seq_private; void (*fini_seq_private)(void *); size_t seq_priv_size; };
struct bpf_iter_reg { const char *target; void (*show_fdinfo)(const struct bpf_iter_aux_info *, struct seq_file *); unsigned ctx_arg_info_size; struct { size_t offset; unsigned type, btf_id; } ctx_arg_info[1]; const struct bpf_iter_seq_info *seq_info; };
struct dma_buf *dma_buf_iter_begin(void);
struct dma_buf *dma_buf_iter_next(struct dma_buf *);
void dma_buf_put(struct dma_buf *);
static inline struct bpf_prog *bpf_iter_get_info(struct bpf_iter_meta *m, bool s) { return NULL; }
static inline int bpf_iter_run_prog(struct bpf_prog *p, void *ctx) { return 0; }
static inline int bpf_iter_reg_target(struct bpf_iter_reg *r) { return 0; }
static inline void seq_puts(struct seq_file *s, const char *t) {}
#endif
