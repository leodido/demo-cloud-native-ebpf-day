#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const char program[16] = "curl";

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

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(handle_security_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    sa_family_t fam;
    bpf_core_read(&fam, sizeof(fam), &address->sa_family);

    if (fam == 2 /* AF_INET */)
    {
        char comm[16];
        bpf_get_current_comm(comm, 16);

        if (is_program(comm))
        {
            struct sockaddr_in *saddr = (struct sockaddr_in *)address;

            __u32 addr;
            bpf_core_read(&addr, sizeof(addr), &saddr->sin_addr.s_addr);

            union
            {
                unsigned int integer;
                unsigned char byte[4];
            } ipv4tochar;
            ipv4tochar.integer = addr;

            bpf_printk("kprobe: %d\n", addr);
            bpf_printk("kprobe: %u.%u\n", ipv4tochar.byte[0], ipv4tochar.byte[1]);
            bpf_printk("kprobe: %u.%u\n", ipv4tochar.byte[2], ipv4tochar.byte[3]);
        }
    }

    return 0;
}