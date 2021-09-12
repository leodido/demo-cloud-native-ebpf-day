#include <bpf/bpf_core_read.h>

// Don't rely on up-to-date vmlinux.h
enum bpf_func_id___x
{
    BPF_FUNC_snprintf___x = 42
};

// Detect whether the current kernel supports the full powers bpf_trace_printk()
// Supports:
// - automatic new line
// - %%
// - X modifier
// - %pK, %px, %pB, %pi4, %pI4, %pi6, %pI6
// - %ps, %pS
#define full_printk \
    (bpf_core_enum_value_exists(enum bpf_func_id___x, BPF_FUNC_snprintf___x))