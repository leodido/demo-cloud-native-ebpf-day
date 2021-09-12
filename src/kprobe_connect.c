#include "utils.c"
#include <unistd.h>
#include "kprobe_connect.skel.h"

int main(int argc, char **argv)
{
    struct kprobe_connect_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    if (signal(SIGINT, sig_int) == SIG_ERR || signal(SIGTERM, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Can't handle Ctrl-C: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Open load and verify BPF application */
    skel = kprobe_connect_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    fprintf(stdout, "BPF skeleton ok\n");

    /* Attach tracepoint handler */
    err = kprobe_connect_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs. ✌️\n");

    while (!stop)
    {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    kprobe_connect_bpf__destroy(skel);
    return -err;
}
