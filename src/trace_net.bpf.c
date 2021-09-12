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

typedef union
{
    unsigned int integer;
    unsigned char byte[4];
} ipv4tochar;

static inline ipv4tochar
get_ip(struct sk_buff *skb)
{
    char *hdr_hdr;
    __u16 mac_hdr;
    __u16 net_hdr;

    bpf_core_read(&hdr_hdr, sizeof(hdr_hdr), &skb->head);
    bpf_core_read(&mac_hdr, sizeof(mac_hdr), &skb->mac_header);
    bpf_core_read(&net_hdr, sizeof(net_hdr), &skb->network_header);

    if (net_hdr == 0)
    {
        net_hdr = mac_hdr + 14 /* MAC header size */;
    }

    char *ipaddr = hdr_hdr + net_hdr;

    __u8 ip_vers;
    bpf_core_read(&ip_vers, sizeof(ip_vers), ipaddr);
    ip_vers = ip_vers >> 4 & 0xf;

    ipv4tochar ret;
    if (ip_vers == 4)
    {
        struct iphdr iph_hdr;
        bpf_core_read(&iph_hdr, sizeof(iph_hdr), ipaddr);

        ret.integer = iph_hdr.daddr;

        return ret;
    }

    return ret;
}

SEC("tp/net/net_dev_queue")
int handle_net_dev_queue(struct trace_event_raw_net_dev_template *ctx)
{
    char comm[16];
    bpf_get_current_comm(comm, 16);

    if (is_program(comm))
    {
        ipv4tochar res = get_ip((struct sk_buff *)ctx->skbaddr);
        if (res.integer > 0)
        {
            bpf_printk("tp/sched/net_dev_queue: %d\n", res.integer);
            bpf_printk("tp/sched/net_dev_queue: %u.%u\n", res.byte[0], res.byte[1]);
            bpf_printk("tp/sched/net_dev_queue: %u.%u\n", res.byte[2], res.byte[3]);
        }
    }
    return 0;
}
