> This project is published strictly for educational and defensive research purposes. It demonstrates how kernel execution flow can be redirected using ftrace to intercept system calls. Do not deploy this on systems you do not own or have explicit permission to test.

## Modern Linux Syscall Hooking via Ftrace + Kprobes (PoC)

This project implements a **kernel-space function hooking mechanism** for modern Linux systems using a combination of Ftrace and Kprobes. The primary goal is to demonstrate how traditional syscall table hooking is no longer viable on hardened kernels, and how **ftrace has become the default primitive for runtime kernel instrumentation**.

Before, kernel rootkits and monitoring tools relied on `sys_call_table` scanning and direct symbol resolution using `kallsyms_lookup_name`. On modern kernels (>= 5.7) `sys_call_table` is no longer exported, `kallsyms_lookup_name` is restricted, KASLR makes static scanning unreliable.

### Core Technique

This poc replaces legacy syscall hooking with Kprobe Symbol Resolution. Since `kallsyms_lookup_name` is no longer exported, a **kprobe** is temporarily registered on it to retrieve its runtime address. This provides a legitimate way to resolve any kernel symbols without memory scanning.

Instead of modifying pointers or tables, this approach uses **Ftrace's internal trampoline mechanism**. When a target function is executed, the kernel jumps into Ftrace, it calls our registered callback, the callback modifies `regs->ip`, and execution resumes at our function instead of the original one.

This is stable on modern kernels (6.x) and is used internally by kernel debuggers, tracing frameworks. This technique is used by legitimate tooling as well.

### Known Limitations

This PoC does **not** implement:
- Module hiding
- Symbol hiding
- Stealth persistence
- EDR evasion

There is **no novel exploitation primitive** in this project.
This implementation is a (hopefully) clean integration of Kprobes symbol resolution, Ftrace trampoline hooking, and standard kernel control flow redirection.

### Usage

In one terminal open `dmesg -W` to monitor KERN_INFO messages from this module.

In the second, make and load the module.
```bash
make
sudo insmod kmodule.ko # load module

sudo rmmod kmodule     # unload module
```

### Links

https://docs.kernel.org/trace/ftrace.html

https://lwn.net/Articles/365835/

https://docs.kernel.org/trace/kprobes.html#register-kprobe

https://github.com/xcellerator/linux_kernel_hacking/issues/3

https://medium.com/dvt-engineering/how-to-write-your-first-linux-kernel-module-cf284408beeb

https://planeta.github.io/programming/kernel-development-setup-with-vagrant/
