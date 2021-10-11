#include "vmlinux.h"
#include <asm/unistd.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "printk.bpf.h"

char LICENSE[] SEC("license") = "GPL";

const char program[16] = "attack_connect";

static inline bool is_program(char a[])
{
    int flag = 1, i = 0;
    while (a[i] != '\0' && program[i] != '\0')
    {
        if (a[i] != program[i])
        {
            flag = 0;
            break;
        }
        i++;
    }
    return flag;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_sys_connect(struct trace_event_raw_sys_enter *ctx)
{
    if (ctx->id != __NR_connect)
    {
        return 0;
    }

    char comm[16];
    bpf_get_current_comm(comm, 16);

    if (is_program(comm))
    {
        struct sockaddr *address;
        address = (struct sockaddr *)ctx->args[1];

        sa_family_t fam;
        bpf_core_read_user(&fam, sizeof(fam), &address->sa_family);
        if (fam != 2 /* AF_INET */)
        {
            // Only IPv4 in this example
            return 0;
        }

        struct sockaddr_in *addr = (struct sockaddr_in *)address;
        __u32 dest;
        bpf_core_read_user(&dest, sizeof(dest), &addr->sin_addr.s_addr);

        if (full_printk)
        {
            bpf_printk("tp/syscall/connect: %pI4", &dest);
        }
        else
        {
            bpf_printk("tp/syscall/connect: %d", dest);
        }
    }

    return 0;
}