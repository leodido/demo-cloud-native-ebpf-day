#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "printk.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2

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

SEC("lsm/socket_connect")
int BPF_PROG(audit_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Satisfying "cannot override a denial" rule
    if (ret != 0)
    {
        return ret;
    }

    char comm[16];
    bpf_get_current_comm(comm, 16);

    if (is_program(comm))
    {
        // Only IPv4 in this example
        if (address->sa_family != AF_INET)
        {
            return 0;
        }

        // Cast the address to an IPv4 socket address
        struct sockaddr_in *addr = (struct sockaddr_in *)address;

        // Where do you want to go?
        __u32 dest = addr->sin_addr.s_addr;

        if (full_printk)
        {
            bpf_printk("lsm: auditing %pI4", &dest);
        }
        else
        {
            bpf_printk("lsm: auditing %d", dest);
        }
    }

    return 0;
}
