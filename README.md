# LSM BPF Changes Everything

This repository contains the code I used for the demo during my [talk](https://sched.co/mFTQ) @ Cloud Native eBPF Day NA 2021.

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
make
```

Or, one by one. For example:

```console
make trace_net
make V=1 restrict_connect # in case you like to be verbose
```




---

[![Analytics](https://ga-beacon.appspot.com/UA-49657176-1/demo-cloud-native-ebpf-day?flat)](https://github.com/igrigorik/ga-beacon)
