# Rootkit

## 应该使用bash而不是zsh

## hide module

内核中的模块信息定义在linux/module.h中，

```C
struct module {
    enum module_state state;
    
    /* Member of list of modules */
    struct list_head list;
    
}
```

通过THIS_MODULE宏获得当前的module信息

一种隐藏module的方式：将当前module从链表中删除，需要恢复时再重新插入链表。

## hide directories

```C
struct linux_dirent64 {
    u64         d_ino;
    s64         d_off;
    unsigned short      d_reclen;
    unsigned char       d_type;
    char        d_name[];
};
```

d_reclen record length，struct的长度，单位为字节，可以用于跳过某一条struct来查找想要的struct记录。

d_name：文件名



