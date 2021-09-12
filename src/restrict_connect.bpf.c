#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "full_printk.bpf.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1
#define AF_INET 2

const __u32 blockme = 16843009; // 1.1.1.1 -> int

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    // Exit if this is not the first LSM hook and the previous BPF program requires us to exit
    if (ret != 0)
    {
        return ret;
    }

    // Only IPv4 in this example
    if (address->sa_family != AF_INET)
    {
        return 0;
    }

    // Cast the address to an IPv4 socket address
    struct sockaddr_in *addr = (struct sockaddr_in *)address;

    // Where do you want to go?
    __u32 dest = addr->sin_addr.s_addr;

    if (dest == blockme)
    {
        if (full_printk)
        {
            bpf_printk("lsm: blocking %pI4h", &dest);
        }
        else
        {
            bpf_printk("lsm: blocking %d\n", dest);
        }
        return -EPERM;
    }
    return 0;
}
