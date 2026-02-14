/* ==========================================================
 * A Proof of Concept demonstrating kernel-level function
 * interception using the Linux ftrace framework.
 *
 * The technique operates by rewriting the instruction
 * pointer inside ftrace callbacks, effectively enabling
 * transparent syscall hooking without modifying kernel
 * memory or syscall tables.
 * ==========================================================
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("RLCTHD");
MODULE_DESCRIPTION("(function) Hooker :)");
MODULE_VERSION("0.01");

/* ======================================= *
 *              KPROBE LOOKUP              *
 kallsyms_lookup_name tells what mem addr
 holds other kernel functions.

 After 5.7 it is an "unkown symbol", thus 
 the need for a lookup function
 * ======================================= */
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
// null pointer, which will hold kallsyms_lookup_name address
static kallsyms_lookup_name_t kallsyms_lookup_name_func;

// Before `symbol_name` was included in the struct, the probe was described by an address.
// This is not recommended since KASLR was added
// A symbol name is enough to "describe the Kprobe"
static struct kprobe kp = {
    // https://docs.kernel.org/trace/kprobes.html#register-kprobe
    // https://lwn.net/Articles/132196/
    .symbol_name = "kallsyms_lookup_name"
};


/* ======================================= *
 *            FTRACE STRUCTURE             *
 *           And Hook Operations           *
 * ======================================= */
struct ftrace_hook {
    const char *name;       // symbol_name ex: __x64_sys_execve
    void *function;         // hooked func addr
    void *original;         // storage for original func
    unsigned long address;  // resolved func addr via kallsyms
    struct ftrace_ops ops;  // ftrace metadata
};

// notrace avoids kernel panic due to recursion
// ftrace calls this helper every time the hooked function is entered
static void notrace fh_trace_helper(
    unsigned long ip,           // instruction ptr of the original function being hooked.  
    unsigned long parent_ip,    // used for recursion detection
    struct ftrace_ops *ops,
    struct ftrace_regs *fregs   // on old kernels you got struct pt_regs * directly
) {
    struct pt_regs *regs;

    // container_of(ptr, type, member)
    // given a pointer to member, compute the pointer to the struct that contains it:
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    // this extracts a usable struct pt_regs
    regs = ftrace_get_regs(fregs);
    if (!regs) return;
    
    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long)hook->function;
    }
}

static int fh_resolve_hook_address(struct ftrace_hook *hook) {
    hook->address = kallsyms_lookup_name_func(hook->name);

    if (!hook->address) {
        printk(KERN_INFO "[i] Unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long*) hook->original) = hook->address;
    return 0;
}

static int fh_install_hook(struct ftrace_hook *hook) {
    int err;
    err = fh_resolve_hook_address(hook);
    if (err) return err;

    hook->ops.func = fh_trace_helper;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        // printk(KERN_DEBUG "[-] ftrace_set_filter_ip failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        // printk(KERN_DEBUG "[-] register_ftrace_function failed: %d\n", err);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook) {
    unregister_ftrace_function(&hook->ops);
    ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
}

/* ======================================= *
 *                  HOOKS                  *
 * ======================================= */

// On x86_64, the kernel syscall ABI passes all arguments via struct pt_regs* 
static asmlinkage long (*orig_mkdir)(const struct pt_regs *);

asmlinkage int fh_sys_mkdir(const struct pt_regs *regs) {
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO "[i] LKM: Trying to create dir: %s\n", dir_name);

    orig_mkdir(regs);
    return 0;
}

static struct ftrace_hook hooks[] = {
    { "__x64_sys_mkdir", fh_sys_mkdir, &orig_mkdir },
    //{ "__x64_sys_unlinkat", fh_sys_unlinkat, &orig_unlinkat },

};


/* ======================================= *
 *               INIT/EXIT                 *
 * ======================================= */
static int __init km_init(void) {
    int ret;
    size_t i;

    // the registration function takes a reference to the KProbe structure describing the probe.
    ret = register_kprobe(&kp);
    if (ret < 0) return ret;
    kallsyms_lookup_name_func = (kallsyms_lookup_name_t) kp.addr;
    // once we get the address, discard the kprobe
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_func) return -EFAULT;

    printk(KERN_INFO "[+] LKM: Loaded.\n");

    // loop through hooks array and install each hook
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        ret = fh_install_hook(&hooks[i]);
        if (ret) {
            printk(KERN_INFO "[-] Failed to hook: %s\n", hooks[i].name);
            while (i > 0) {
                fh_remove_hook(&hooks[--i]);
            }
            return ret;
        }
    }
    return 0;
}

static void __exit km_exit(void) {
    size_t i;
    for (i = 0; i < ARRAY_SIZE(hooks); i++) {
        fh_remove_hook(&hooks[i]);
    }
    printk(KERN_INFO "[-] LKM: Unloaded.\n");

}

module_init(km_init);
module_exit(km_exit);
