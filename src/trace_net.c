#include "utils.c"
#include "trace_net.skel.h"

int main(int argc, char **argv)
{
    struct trace_net_bpf *skel;
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
    skel = trace_net_bpf__open_and_load();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    fprintf(stdout, "BPF skeleton ok\n");

    /* Attach tracepoint handler */
    err = trace_net_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    err = bpf_trace_pipe(STDERR_FILENO);

cleanup:
    trace_net_bpf__destroy(skel);
    return -err;
}
