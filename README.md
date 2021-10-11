# LSM BPF Changes Everything

This repository contains the code I used for the demo during my [talk](https://sched.co/mFTQ) @ [Cloud Native eBPF Day NA 2021](https://events.linuxfoundation.org/cloud-native-ebpf-day-north-america/).

Here you'll find the following eBPF programs:

<dl>
  <dt><a href="./src/restrict_connect.bpf.c">restrict_connect</a></dt>
  <dd>BPF LSM program (on <code>socket_connect</code> hook) that prevents any connection towards 1.1.1.1 to happen</dd>
  <dt><a href="./src/audit_connect.bpf.c">audit_connect</a></dt>
  <dd>program that shows BPF LSM for auditing (on <code>socket_connect</code> hook)</dd>
  <dt><a href="./src/kprobe_connect.bpf.c">kprobe_connect</a></dt>
  <dd>program that instruments a kprobe on the Kernel function (<code>security_socket_connect</code>) installing the <code>socket_connect</code> hook</dd>
  <dt><a href="./src/trace_net.bpf.c">trace_net</a></dt>
  <dd>eBPF program for the <code>net/net_dev_queue</code> tracepoint</dd>
  <dt><a href="./src/trace_connect.bpf.c">trace_connect</a></dt>
  <dd>eBPF program tracing the entering of the <code>connect</code> syscall</dd>
</dl>

## Usage

First thing you'd need to clone this repository, isn't it?

```console
git clone --recurse-submodules -j8 https://github.com/leodido/demo-cloud-native-ebpf-day.git
```

I guess you wanna now build this machinery. Cool!

### Prerequisites

Wait a sec, here are some preconditions to get all of this demo working...

<details>
<summary>You need a <a href="https://www.kernel.org/doc/html/latest/bpf/btf.html">BTF</a> capable Kernel (Linux Kernel 4.18+).</summary>
<p>

To check whether you have a BTF enabled kernel run:

```console
$ zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF=
```

Otherwise, you need to recompile you kernel with `CONFIG_DEBUG_INFO_BTF=y`: it's size will increase of ~1.5MB, not a big deal.
</p>
</details>

<details>
<summary>You need to install <code>bpftool</code> and <code>clang</code>.</summary>
<p>

On ArchLinux this is as easy as running:

```console
$ sudo pacman -S bpf clang
```
</p>
</details>

<details>
<summary>If you also wanna try the BPF LSM programs, you need a Linux Kernel 5.7+ with BPF LSM on.</summary>
<p>

To check whether you have it enabled or not:

```console
$ zcat /proc/config.gz | grep CONFIG_LSM=
```

Check if BPF hooks are enabled for LSM by looking at the output to contain them:

```console
CONFIG_LSM="...,bpf"
```

Remember that BPF hooks for LSM can also be enabled via the `lsm` Kernel boot parameters, so take a look there too.

Also check your Kernel supports [BPF LSM instrumentation](https://github.com/torvalds/linux/blob/5d6ab0bb408ffdaac585982faa9ec8c7d5cc349f/kernel/bpf/Kconfig#L77) with:

```console
$ zcat /proc/config.gz | grep CONFIG_BPF_LSM=
```
</p>
</details>

### Building

Ok, now you can move to the `src` directory. Here you'll find a nice [Makefile](./src/Makefile) to build all the things at once:

```console
$ make
```

Or, one by one. For example:

```console
$ make trace_net
$ make V=1 restrict_connect # in case you like to be verbose
```

### Running

Now it's time to run 🏃

Wanna try to restrict connections towards 1.1.1.1? Try this:

```console
$ sudo ./restrict_connect
```

Then, in another terminal:

```console
$ curl https://1.1.1.1
$ ping 1.1.1.1
```

And observe the output!

Notice that all the other eBPF programs in this repo (so, except `restrict_connect` at the moment)
work only against connections coming from executables which name is `attack_connect`.

This means they'll ignore connections generating from `curl`, etc.

## Evaluation

One of the reasons because this repository (and its talk) exist was because I wanted to test an attack ([CVE-2021-33505](https://nvd.nist.gov/vuln/detail/CVE-2021-33505))
that in some circumstances (ie., `userfaultfd` syscall enabled) is able to bypass security auditing tools
based on tracepoints (that were not exactly made to accomplish this goal, but still...).

So, I wanted to verify which tracing implementations for the security context
are vulnerable to this attack... And here we are. 🙃

Wanna know more about this attack? Watch this [DEFCON talk](https://youtu.be/yaAdM8pWKG8) by my friend Xiaofei Rex Guo.

Now, let's say that you wanna try the attack yourself targeting one of the eBPF programs here.

<details>
<summary>First, you'll need to verify whether you have the `userfaultfd` syscall...</summary>
<p>

```console
$ zcat /proc/config.gz | grep CONFIG_USERFAULTFD
```

You'll also need to verify if it is enabled for unprivileged users
(surprisingly, it is enabled for unprivileged users in many distro kernels).

```console
$ cat /proc/sys/vm/unprivileged_userfaultfd
```

If `/proc/sys/vm/unprivileged_userfaultfd` is set to `0`, for the sake of this experimentation set it to `1`, like so:

```console
$ sudo sysctl -w vm.unprivileged_userfaultfd=1
```
</p>
</details>

Now you should be able to doo you experimentations!

First, start an eBPF program of your choice...

Then, it's attack time:

```console
$ pushd phantom-attack/phantom_v1/
$ make
$ popd
$ ./phantom-attack/phantom_v1/attack_connect
```

I also wrote a bash script to make these experimentations more straightforward.

Maybe, one day, I'll publish the results of such experimentations among different kernel releases, eBPF programs, etc.

Anyways, you can find it at [experiment.sh](./experiment.sh) in this repo and you can execute it by providing the number of times you want the attack to run (let's say 10?) and the eBPF program to target (let's say `trace_connect`?).

```console
$ ./experiment.sh -i 100 -p trace_connect
```

Have fun!

~
Leo

---

[![Analytics](https://ga-beacon.appspot.com/UA-49657176-1/demo-cloud-native-ebpf-day?flat)](https://github.com/igrigorik/ga-beacon)
