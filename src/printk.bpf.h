#include <bpf/bpf_core_read.h>

// Define our own struct definition if our vmlinux.h is outdated
struct trace_event_raw_bpf_trace_printk___x
{
};

// Redefine bpf_prink to support:
// - automatic new lines
#undef bpf_printk
#define bpf_printk(fmt, ...)                                                       \
    (                                                                              \
        {                                                                          \
            static char ____fmt[] = fmt "\0";                                      \
            if (bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk___x)) \
            {                                                                      \
                bpf_trace_printk(____fmt, sizeof(____fmt) - 1, ##__VA_ARGS__);     \
            }                                                                      \
            else                                                                   \
            {                                                                      \
                ____fmt[sizeof(____fmt) - 2] = '\n';                               \
                bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);         \
            }                                                                      \
        })

// Don't rely on up-to-date vmlinux.h
enum bpf_func_id___x
{
    BPF_FUNC_snprintf___x = 42
};

// Detect whether the current kernel (>= 5.13?) supports the full powers bpf_trace_printk()
// Supports:
// - more than one %s arguments
// - witdh specifiers (eg., %10d)
// - %%
// - X modifier
// - %pK, %px, %pB, %pi4, %pI4, %pi6, %pI6
// - %ps, %pS
#define full_printk \
    (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x))