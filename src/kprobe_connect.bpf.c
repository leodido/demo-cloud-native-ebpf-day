#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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

            if (full_printk)
            {
                bpf_printk("kprobe: %pI4", &addr);
            }
            else
            {
                bpf_printk("kprobe: %d\n", addr);
            }
        }
    }

    return 0;
}