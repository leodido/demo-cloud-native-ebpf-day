#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const __u32 blockme = 1136196238; //16843009;

SEC("lsm/socket_connect")
int BPF_PROG(restrict_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    // Only IPv4 in this example
    if (address->sa_family != 2 /* AF_INET */)
    {
        return 0;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)address;
    __u32 dest = addr->sin_addr.s_addr;

    bpf_printk("lsm: %d\n", dest);
    if (dest == blockme)
    {
        bpf_printk("lsm: block\n");
        return -1 /* -EPERM */;
    }
    return 0;
}
